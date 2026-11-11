"""
services/jobs.py
Shared definitions of the scheduled jobs (Phase E / Phase F).

WHY THIS MODULE EXISTS
----------------------
Before containerization (Phase G), the job bodies lived as private
functions in app.py (_run_scheduled_backup / _run_kev_sync /
_run_ai_proposals) and were registered with flask_apscheduler inside
create_app(). That couples the jobs to a full Flask app instance, which
is fine for a single-process dev deployment but wrong for the container
split we now run:

    - container `app`     -> HTTP only,  SCHEDULER_ENABLED=False
    - container `scheduler` -> cron only, no HTTP, no Flask

The scheduler container therefore imports the job bodies from HERE and
drives them with a plain apscheduler BlockingScheduler (see
scheduler_runner.py). app.py imports the SAME functions for its embedded
dev/legacy mode. One source of truth: the cron schedule is defined once
in config.py, the job behaviour once here.

NOTHING in this module imports Flask. The jobs talk to MongoDB directly
through database.py and to external systems through services/*. That
keeps the scheduler container small and means a Flask import error can
never take down scheduled backups.
"""

from __future__ import annotations

import logging

from config import Config
from database import get_db, get_kev_catalog_collection, get_tech_stack_collection
from services.notification import notify

logger = logging.getLogger(__name__)


def run_scheduled_backup() -> None:
    """
    Job terjadwal: backup semua koleksi ke S3 + notifikasi.

    Extracted verbatim from app.py::_run_scheduled_backup — behaviour is
    unchanged, only the location moved.
    """
    from services.backup_utils import create_backup

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


def run_kev_sync() -> None:
    """
    Job terjadwal: sinkronkan katalog vendor/product dari feed KEV ke
    `kev_catalog` (sumber dropdown Tech Stack). Hanya menyisipkan pasangan
    yang belum ada -- tidak pernah menghapus entri lama.
    """
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


def run_ai_proposals() -> None:
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


def run_exploitdb_retry() -> None:
    """
    Job terjadwal: proses antrean retry Exploit-DB yang sudah jatuh tempo.

    Antrean PERSISTEN di `exploitdb_cache` (status retry_pending +
    next_retry_at), bukan sleep/date-job APScheduler -- job ad-hoc di
    BlockingScheduler hilang saat container restart. Cron berjalan tiap
    menit dan hanya mengambil entri yang next_retry_at-nya lewat, sehingga
    retry pertama benar-benar +/- 5 menit.

    Notifikasi hanya dikirim saat ada yang PULIH atau MENYERAH. Kegagalan
    pertama sudah dinotifikasi oleh pipeline AI; mengirim notifikasi tiap
    percobaan akan membanjiri Telegram saat Cloudflare memblokir.
    """
    from services import exploitdb_utils

    db = get_db()
    if db is None:
        return

    result = exploitdb_utils.process_retry_queue(db, limit=Config.EXPLOITDB_RETRY_BATCH)
    if not result.get('success') or not result.get('processed'):
        return

    recovered = result.get('recovered', 0)
    exhausted = result.get('exhausted', 0)
    if recovered:
        notify(
            'Retry Exploit-DB berhasil',
            f'{recovered} CVE berhasil dicek ulang.',
            level='success',
        )
    if exhausted:
        notify(
            'Retry Exploit-DB menyerah',
            f'{exhausted} CVE tetap gagal setelah '
            f'{Config.EXPLOITDB_MAX_ATTEMPTS} percobaan.',
            level='error',
        )


def run_exploitdb_refresh() -> None:
    """
    Job terjadwal: cek ulang CVE yang sudah punya proposal pending untuk
    menangkap exploit yang terbit BELAKANGAN. Hanya menandai
    `needs_review`; draft rule TIDAK diubah.
    """
    if not Config.EXPLOITDB_ENABLED:
        return

    from services import exploitdb_utils

    db = get_db()
    if db is None:
        return

    result = exploitdb_utils.refresh_pending_proposals(
        db, limit=Config.EXPLOITDB_REFRESH_BATCH, notify_new=False,
    )
    if not result.get('success'):
        return

    new_exploits = result.get('new_exploits', 0)
    if new_exploits:
        notify(
            'Exploit baru ditemukan',
            f'{new_exploits} proposal kini punya exploit publik di Exploit-DB '
            f'dan ditandai needs_review (draft TIDAK diubah).',
            level='warning',
        )


# Registry consumed by BOTH app.py (embedded mode) and scheduler_runner.py
# (dedicated container). Each entry:
#   (job_id, job_function, Config attribute holding the 5-field cron,
#    Config attribute holding the on/off flag, human label)
#
# Keeping this a plain list (not a dict keyed by name) makes the
# registration loop in both callers trivially identical.
JOB_REGISTRY = (
    ('scheduled_backup', run_scheduled_backup, 'BACKUP_CRON', 'BACKUP_ENABLED', 'Backup otomatis'),
    ('kev_catalog_sync', run_kev_sync, 'KEV_SYNC_CRON', 'KEV_SYNC_ENABLED', 'Sync katalog KEV'),
    ('ai_rule_proposals', run_ai_proposals, 'AI_PROPOSAL_CRON', 'AI_PROPOSAL_ENABLED', 'Usulan rule AI'),
    ('exploitdb_retry', run_exploitdb_retry, 'EXPLOITDB_RETRY_CRON', 'EXPLOITDB_RETRY_ENABLED', 'Retry Exploit-DB'),
    ('exploitdb_refresh', run_exploitdb_refresh, 'EXPLOITDB_REFRESH_CRON', 'EXPLOITDB_REFRESH_ENABLED', 'Refresh Exploit-DB'),
)


def iter_enabled_jobs():
    """
    Yield (job_id, func, cron_string, label) for every job whose
    *_ENABLED flag is True and whose cron string parses.

    Invalid cron is logged and SKIPPED, never raised — matches the
    original app.py behaviour where a bad cron only produced a warning
    and the remaining jobs still registered.
    """
    from apscheduler.triggers.cron import CronTrigger

    for job_id, func, cron_attr, enabled_attr, label in JOB_REGISTRY:
        if not getattr(Config, enabled_attr, False):
            logger.info('[Jobs] %s=False -- %s non-aktif.', enabled_attr, label)
            continue

        cron_string = getattr(Config, cron_attr, '')
        try:
            CronTrigger.from_crontab(cron_string)
        except ValueError:
            logger.warning(
                '[Jobs] %s tidak valid ("%s") -- %s tidak dijadwalkan.',
                cron_attr, cron_string, label,
            )
            continue

        yield job_id, func, cron_string, label
