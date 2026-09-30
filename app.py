from flask import Flask, redirect, url_for
from flask_login import current_user
from flask_session import Session
from flask_wtf import CSRFProtect

from config import Config
from database import init_db, get_client, get_users_collection, get_db

# ── APScheduler (Phase E) ──────────────────────────────────────────────
# Inisialisasi DI SINI (sebelum create_app) supaya @scheduler.task bisa
# dipakai di mana pun dalam modul ini jika perlu. Scheduler dimulai di
# dalam create_app dengan guard reloader (lihat komentar di bawah).
from flask_apscheduler import APScheduler
from apscheduler.triggers.cron import CronTrigger

from services.backup_utils import create_backup
from services.notification import notify

scheduler = APScheduler()


def _run_scheduled_backup() -> None:
    """Job terjadwal: backup semua koleksi ke S3 + notifikasi."""
    db = get_db()
    if db is None:
        notify('Backup otomatis', 'MongoDB tidak tersedia.', level='error')
        return

    result = create_backup(db, triggered_by='scheduler')
    if result.get('success'):
        summary = (
            f'{result.get("total_documents", 0)} dokumen ter-backup '
            f'dari {len(result.get("collections", {}))} koleksi '
            f'({result.get("size_bytes", 0) // 1024} KB)'
        )
        notify('Backup otomatis selesai', summary, level='success')
    else:
        notify('Backup otomatis GAGAL', result.get('error', ''), level='error')


def _run_kev_sync() -> None:
    """
    Job terjadwal: sinkronkan katalog vendor/product dari feed KEV ke
    `kev_catalog` (sumber dropdown Tech Stack). Hanya menyisipkan pasangan
    yang belum ada -- tidak pernah menghapus entri lama.
    """
    from database import get_kev_catalog_collection, get_tech_stack_collection
    from services.kev_utils import sync_vendor_catalog

    db = get_db()
    if db is None:
        notify('Sync katalog KEV', 'MongoDB tidak tersedia.', level='error')
        return

    result = sync_vendor_catalog(get_kev_catalog_collection(), get_tech_stack_collection())
    if result.get('success'):
        notify(
            'Sync katalog KEV selesai',
            f'{result.get("inserted", 0)} pasangan vendor/product baru '
            f'dari total {result.get("total_pairs", 0)} '
            f'({result.get("vendors", 0)} vendor).',
            level='success',
        )
    else:
        notify('Sync katalog KEV GAGAL', result.get('error', ''), level='error')


def _run_ai_proposals() -> None:
    """
    Job terjadwal: buat usulan draft rule dari advisory KEV yang relevan
    dengan tech_stack (Phase F, Opsi C). Usulan TIDAK pernah otomatis
    menjadi rule -- tersimpan sebagai pending review di `ai_proposals`.
    """
    from services.ai_utils import run_proposal_job

    db = get_db()
    if db is None:
        notify('Usulan rule AI', 'MongoDB tidak tersedia.', level='error')
        return

    result = run_proposal_job(db, max_items=Config.AI_PROPOSAL_MAX_PER_RUN)
    if not result.get('success'):
        notify('Usulan rule AI GAGAL', result.get('error', ''), level='error')
        return

    generated = result.get('generated', 0)
    if generated:
        notify(
            'Usulan rule AI selesai',
            f'{generated} draft usulan baru '
            f'({result.get("relevant", 0)} CVE relevan, '
            f'{result.get("skipped_existing", 0)} sudah pernah diusulkan).',
            level='success',
        )


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialise MongoDB connection (non-fatal if unavailable)
    init_db()

    # -- Session (server-side, MongoDB-backed) --------------------------
    # Flask-Session's MongoDB backend needs a live pymongo.MongoClient
    # instance in SESSION_MONGODB (not a URI string) -- reuse the exact
    # client database.py already opened rather than creating a second
    # connection to the same server.
    #
    # IMPORTANT: only wire up Session(app) when we actually have a
    # connected client. Flask-Session's MongoDBSessionInterface, if given
    # client=None, silently creates its OWN new MongoClient() pointed at
    # localhost and immediately calls create_index() on it -- which
    # raises ServerSelectionTimeoutError and CRASHES app startup entirely
    # when Mongo is unreachable. That would undermine the non-fatal
    # degradation database.init_db() already guarantees ("the app starts
    # without MongoDB support"). So: Mongo down -> skip Flask-Session,
    # fall back to Flask's default signed-cookie session so the app still
    # boots. Login won't work either way in that state (get_users_collection()
    # is also None), consistent with every other feature already
    # returning 503 when Mongo is unavailable.
    mongo_client = get_client()
    if mongo_client is not None:
        app.config['SESSION_MONGODB'] = mongo_client
        app.config['SESSION_MONGODB_DB'] = Config.SESSION_MONGODB_DB or Config.MONGO_DB_NAME
        Session(app)
    else:
        app.logger.warning(
            '[Session] MongoDB unavailable -- falling back to default '
            'signed-cookie session. Login will not work until MongoDB is '
            'reachable (restart the app once it is).'
        )

    # CSRF protection -- relevant now that there's a login form (and any
    # other server-rendered form) submitting session-authenticated
    # requests.
    CSRFProtect(app)

    # -- Auth -------------------------------------------------------------
    from blueprints.auth import auth_bp, login_manager
    login_manager.init_app(app)
    app.register_blueprint(auth_bp, url_prefix='/auth')

    # Register blueprints
    from blueprints.builder import builder_bp
    from blueprints.api import api_bp
    from blueprints.tester import tester_bp
    from blueprints.importer import importer_bp
    from blueprints.pages import pages_bp

    # Every blueprint below manages or exposes rule/decoder/Wazuh-Manager
    # data -- gate all of them behind login. This is the direct-check
    # pattern flask_login's own login_required docstring recommends for
    # exactly this use (applying the check outside a single view
    # function), rather than a decorator trick. MUST run before
    # register_blueprint() below -- Flask locks a blueprint's setup
    # (before_request etc.) once it has been registered once.
    def _require_login():
        if not current_user.is_authenticated:
            return login_manager.unauthorized()

    for bp in (builder_bp, api_bp, tester_bp, importer_bp, pages_bp):
        bp.before_request(_require_login)

    app.register_blueprint(builder_bp, url_prefix='/builder')
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(tester_bp, url_prefix='/tester')
    app.register_blueprint(importer_bp, url_prefix='/importer')
    # pages_bp is registered WITHOUT a prefix -- its routes (/decoder, /rule,
    # /decoders, /rules, /sync, /import-export, /log-tester, /pcre2-tester)
    # are the actual pages people navigate to, distinct from the /builder,
    # /api, /tester, /importer namespaces above which are pure JSON APIs.
    app.register_blueprint(pages_bp)

    @app.route('/')
    def index():
        # Go straight to the new default landing page. (builder.index(),
        # at /builder/, still exists and redirects here too -- kept only
        # for anything that might still hit it directly -- but this is now
        # the one real entry point, avoiding an unnecessary double-hop
        # through /builder/ on every fresh visit.)
        return redirect(url_for('pages.decoder_builder_page'))

    # -- flask create-user CLI -------------------------------------------
    # No self-registration route by design -- this is an internal SOC
    # tool; whoever administers the deployment creates accounts by
    # running this on the server:
    #   flask --app app:create_app create-user <username>
    # (prompts for password so it never lands in shell history).
    import click
    from werkzeug.security import generate_password_hash
    from datetime import datetime, timezone

    @app.cli.command('create-user')
    @click.argument('username')
    @click.password_option()
    def create_user(username, password):
        """Create a new login account."""
        col = get_users_collection()
        if col is None:
            click.echo('MongoDB tidak tersedia -- cek MONGO_URI.')
            return
        username = username.strip()
        if not username:
            click.echo('Username tidak boleh kosong.')
            return
        if col.find_one({'username': username}):
            click.echo(f'User "{username}" sudah ada.')
            return
        col.insert_one({
            'username': username,
            'password_hash': generate_password_hash(password),
            'is_active': True,
            'created_at': datetime.now(timezone.utc),
            'last_login_at': None,
        })
        click.echo(f'User "{username}" dibuat.')

    # -- flask set-reviewer CLI -------------------------------------------
    # Sama alasannya dengan create-user: internal SOC tool, tidak ada UI
    # admin untuk toggle role — dijalankan lewat CLI oleh siapa yang
    # administer deployment:
    #   flask --app app:create_app set-reviewer <username>
    #   flask --app app:create_app set-reviewer <username> --unset
    # Menggantikan cara manual mongosh yang didokumentasikan sementara di
    # set_reviewer_manual.md (lihat LARAS_ROADMAP.md Phase B) — begitu
    # command ini dipakai, dokumen manual itu jadi murni fallback kalau
    # CLI tidak bisa dijalankan untuk suatu alasan.
    @app.cli.command('set-reviewer')
    @click.argument('username')
    @click.option('--unset', is_flag=True, default=False,
                  help='Cabut status reviewer alih-alih memberikannya.')
    def set_reviewer(username, unset):
        """Tandai (atau cabut) user sebagai reviewer promotion ke Prod."""
        col = get_users_collection()
        if col is None:
            click.echo('MongoDB tidak tersedia -- cek MONGO_URI.')
            return
        username = username.strip()
        if not username:
            click.echo('Username tidak boleh kosong.')
            return
        user_doc = col.find_one({'username': username})
        if user_doc is None:
            click.echo(f'User "{username}" tidak ditemukan -- buat dulu dengan `flask create-user {username}`.')
            return

        new_value = not unset
        if user_doc.get('is_reviewer', False) == new_value:
            state = 'sudah' if new_value else 'sudah bukan'
            click.echo(f'User "{username}" {state} reviewer -- tidak ada perubahan.')
            return

        col.update_one({'username': username}, {'$set': {'is_reviewer': new_value}})
        action = 'Dicabut dari' if unset else 'Ditetapkan sebagai'
        click.echo(f'{action} reviewer: "{username}".')

    # -- APScheduler (Phase E: backup otomatis terjadwal) --------------
    # Dijalankan hanya kalau BACKUP_ENABLED=True. Guard reloader:
    # `flask run --debug` (atau app.run(debug=True)) menjalankan create_app
    # DUA KALI -- sekali di proses parent reloader, sekali di child yang
    # benar-benar serve. Tanpa guard, scheduler ikut start dua kali dan
    # job backup berjalan dobel. WERKZEUG_RUN_MAIN di-set 'true' HANYA di
    # proses child (yang melayani request); proses parent reloader tidak
    # punya env var itu. Jadi start scheduler hanya di proses yang
    # melayani request -- parent reloader tidak usah start (job-nya dobel
    # tidak berguna, dia cuma nunggu perubahan file).
    import os as _os
    scheduler.init_app(app)
    if not Config.SCHEDULER_ENABLED:
        # Deployment multi-worker: worker ini sengaja tidak menjalankan
        # scheduler (SCHEDULER_ENABLED=False) supaya job tidak dobel per
        # worker. Lihat komentar SCHEDULER_ENABLED di config.py.
        app.logger.info(
            '[Scheduler] SCHEDULER_ENABLED=False -- scheduler tidak dijalankan di proses ini.'
        )
        return app
    if _os.environ.get('WERKZEUG_RUN_MAIN') == 'true' or not app.config['DEBUG']:
        import logging as _logging

        any_job = False

        # -- Job: backup otomatis --
        if Config.BACKUP_ENABLED:
            try:
                trigger = CronTrigger.from_crontab(Config.BACKUP_CRON)
            except ValueError:
                app.logger.warning(
                    '[Scheduler] BACKUP_CRON tidak valid ("%s") -- backup otomatis tidak dijadwalkan.',
                    Config.BACKUP_CRON,
                )
            else:
                scheduler.add_job(
                    'scheduled_backup',
                    _run_scheduled_backup,
                    trigger=trigger,
                    replace_existing=True,
                    misfire_grace_time=3600,
                    coalesce=True,
                )
                any_job = True
                app.logger.info('[Scheduler] Backup otomatis dijadwalkan: %s', Config.BACKUP_CRON)
        else:
            app.logger.info('[Scheduler] BACKUP_ENABLED=False -- backup otomatis non-aktif.')

        # -- Job: sync katalog vendor/product dari feed KEV (Phase F) --
        if Config.KEV_SYNC_ENABLED:
            try:
                kev_trigger = CronTrigger.from_crontab(Config.KEV_SYNC_CRON)
            except ValueError:
                app.logger.warning(
                    '[Scheduler] KEV_SYNC_CRON tidak valid ("%s") -- sync katalog KEV tidak dijadwalkan.',
                    Config.KEV_SYNC_CRON,
                )
            else:
                scheduler.add_job(
                    'kev_catalog_sync',
                    _run_kev_sync,
                    trigger=kev_trigger,
                    replace_existing=True,
                    misfire_grace_time=3600,
                    coalesce=True,
                )
                any_job = True
                app.logger.info('[Scheduler] Sync katalog KEV dijadwalkan: %s', Config.KEV_SYNC_CRON)
        else:
            app.logger.info('[Scheduler] KEV_SYNC_ENABLED=False -- sync katalog KEV non-aktif.')

        # -- Job: usulan draft rule AI (Phase F, Opsi C) --
        if Config.AI_PROPOSAL_ENABLED:
            try:
                ai_trigger = CronTrigger.from_crontab(Config.AI_PROPOSAL_CRON)
            except ValueError:
                app.logger.warning(
                    '[Scheduler] AI_PROPOSAL_CRON tidak valid ("%s") -- pipeline AI tidak dijadwalkan.',
                    Config.AI_PROPOSAL_CRON,
                )
            else:
                scheduler.add_job(
                    'ai_rule_proposals',
                    _run_ai_proposals,
                    trigger=ai_trigger,
                    replace_existing=True,
                    misfire_grace_time=3600,
                    coalesce=True,
                )
                any_job = True
                app.logger.info('[Scheduler] Usulan rule AI dijadwalkan: %s', Config.AI_PROPOSAL_CRON)
        else:
            app.logger.info('[Scheduler] AI_PROPOSAL_ENABLED=False -- pipeline AI non-aktif.')

        if any_job:
            scheduler.start()
        else:
            _logging.getLogger(__name__).info(
                '[Scheduler] Tidak ada job yang aktif -- scheduler tidak dijalankan.'
            )

    return app


if __name__ == '__main__':
    app = create_app()
    app.run(host='0.0.0.0', port=5000, debug=app.config['DEBUG'])