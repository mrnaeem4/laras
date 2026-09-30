import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    # ── Flask ─────────────────────────────────────────────────────────────
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'

    # ── Session (server-side, stored in MongoDB) ────────────────────────
    # Chosen over the default signed-cookie session specifically so a
    # compromised/offboarded account can be logged out INSTANTLY by
    # deleting its session documents (sessions_col.delete_many({'user_id':
    # ...})) — a signed cookie session can't be revoked before it expires
    # short of rotating SECRET_KEY, which would log out every user at
    # once. See services/session_utils.py (created in blueprints/auth.py)
    # for the revoke helper.
    SESSION_TYPE = 'mongodb'
    SESSION_MONGODB_DB = os.environ.get('SESSION_MONGODB_DB') or None  # None -> app.py falls back to MONGO_DB_NAME
    SESSION_MONGODB_COLLECT = 'sessions'
    SESSION_PERMANENT = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    # HTTPS-only cookie — only enable once the app is actually served over
    # TLS, or the browser will silently refuse to send the cookie at all
    # and login will appear to "not stick". Off by default (matches
    # WAZUH_API_VERIFY_CERT=False default, i.e. this app assumes a
    # non-TLS/self-signed local deployment unless told otherwise).
    SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
    # Also used server-side by Flask-Session as each session document's
    # expiry — 8h to comfortably cover one SOC shift. Override via env
    # (seconds) if your shifts run differently.
    PERMANENT_SESSION_LIFETIME = int(os.environ.get('SESSION_LIFETIME_SECONDS', 8 * 3600))

    # ── CSRF (Flask-WTF) ─────────────────────────────────────────────────
    # Default WTF_CSRF_TIME_LIMIT is a FIXED 3600s (1h) regardless of how
    # long the session itself stays valid. Left at default, anyone with a
    # tab open longer than 1h would start getting "CSRF token expired" on
    # every POST/PUT/DELETE even though their 8h session is still fine —
    # confusing and indistinguishable from a real bug. None here means
    # "no separate token expiry" (verified against flask_wtf.csrf._get_config,
    # which uses config.get(key, default) — an explicit None IS honoured,
    # it does not fall back to the 3600 default), so the token stays valid
    # for as long as the session itself does.
    WTF_CSRF_TIME_LIMIT = None

    # ── Wazuh Manager API (Phase C: Dev/Prod terpisah, 24 Agustus 2026) ───
    # [DEPRECATED] WAZUH_API_* lama TIDAK dipakai lagi oleh WazuhAPI (lihat
    # services/wazuh_api.py) -- dipertahankan di sini HANYA supaya .env lama
    # yang masih punya baris ini tidak menyebabkan error saat load, tapi
    # tidak dibaca oleh kode manapun. WAJIB migrasi ke WAZUH_DEV_API_*/
    # WAZUH_PROD_API_* di bawah.
    WAZUH_API_URL = os.environ.get('WAZUH_API_URL')
    WAZUH_API_USER = os.environ.get('WAZUH_API_USER')
    WAZUH_API_PASSWORD = os.environ.get('WAZUH_API_PASSWORD')
    WAZUH_API_VERIFY_CERT = os.environ.get('WAZUH_API_VERIFY_CERT', 'False').lower() == 'true'

    # Keputusan eksplisit (24 Agustus 2026): TIDAK ada fallback ke
    # WAZUH_API_* lama untuk Prod, sekalipun secara historis manager
    # tunggal yang lama itu berfungsi sebagai Prod (tempat gate 4-eyes
    # dipasang di Phase B). Alasannya: fallback diam-diam gampang bikin
    # deployment lupa mengonfigurasi Prod dengan benar dan tidak sadar
    # masih jalan di atas config lama. Kedua environment WAJIB diisi
    # eksplisit di .env -- tidak ada default apapun (termasuk untuk URL),
    # supaya app gagal dengan jelas (lihat WazuhAPI.__init__ warning) kalau
    # env belum dikonfigurasi, bukan diam-diam nyambung ke tempat yang salah.
    WAZUH_DEV_API_URL = os.environ.get('WAZUH_DEV_API_URL')
    WAZUH_DEV_API_USER = os.environ.get('WAZUH_DEV_API_USER')
    WAZUH_DEV_API_PASSWORD = os.environ.get('WAZUH_DEV_API_PASSWORD')
    WAZUH_DEV_API_VERIFY_CERT = os.environ.get('WAZUH_DEV_API_VERIFY_CERT', 'False').lower() == 'true'

    WAZUH_PROD_API_URL = os.environ.get('WAZUH_PROD_API_URL')
    WAZUH_PROD_API_USER = os.environ.get('WAZUH_PROD_API_USER')
    WAZUH_PROD_API_PASSWORD = os.environ.get('WAZUH_PROD_API_PASSWORD')
    WAZUH_PROD_API_VERIFY_CERT = os.environ.get('WAZUH_PROD_API_VERIFY_CERT', 'False').lower() == 'true'

    # ── MongoDB ───────────────────────────────────────────────────────────
    MONGO_URI = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/')
    MONGO_DB_NAME = os.environ.get('MONGO_DB_NAME', 'wazuh_rule_management')

    # ── Backup (Phase E) ──────────────────────────────────────────────────
    # Env variables berikut WAJIB diisi untuk fitur backup berfungsi
    # (S3/MinIO storage). Endpoint dan scheduler tetap ada tanpa konfigurasi
    # -- mereka akan mengembalikan error yang jelas kalau belum diisi.
    #
    # Target penyimpanan: S3-compatible (MinIO, AWS S3, dsb). Endpoint
    # wajib eksplisit (mis. http://localhost:9000 untuk MinIO lokal);
    # region bisa dikosongkan kalau MinIO tidak memakainya.
    BACKUP_ENABLED = os.environ.get('BACKUP_ENABLED', 'False').lower() == 'true'
    S3_ENDPOINT_URL = os.environ.get('S3_ENDPOINT_URL')
    S3_ACCESS_KEY = os.environ.get('S3_ACCESS_KEY')
    S3_SECRET_KEY = os.environ.get('S3_SECRET_KEY')
    S3_BUCKET = os.environ.get('S3_BUCKET', 'laras-backups')
    S3_REGION = os.environ.get('S3_REGION', '')
    S3_PREFIX = os.environ.get('S3_PREFIX', 'backups')

    # Jadwal backup otomatis (5-field cron: menit jam hari bulan hari_minggu
    # -- APScheduler's CronTrigger.from_crontab menolak 6 field).
    # Default: setiap hari pukul 02:00.
    # Lihat docs: https://apscheduler.readthedocs.io/en/stable/modules/schedulers/base.html
    BACKUP_CRON = os.environ.get('BACKUP_CRON', '0 2 * * *')

    # Koleksi yang ikut di-backup. Default semua koleksi penting LARAS.
    BACKUP_COLLECTIONS = os.environ.get(
        'BACKUP_COLLECTIONS',
        'rules,decoders,rule_history,decoder_history,promotion_requests,users,manager_actions',
    ).split(',')

    # ── Notifications (Phase E) ───────────────────────────────────────────
    # Channel saat ini: Telegram saja (keputusan 3 September 2026).
    # TIDAK pakai email -- tidak ada SMTP configuration di sini.
    # Kosongkan TELEGRAM_BOT_TOKEN dan notifikasi menjadi no-op (app tetap
    # berjalan normal tanpa error).
    TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN')
    TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID')

    # ── KEV feed (Phase F: CSIRT Tangerang Kota advisories) ───────────────
    # Sumber katalog KEV eksternal. Endpoint-nya mengembalikan JSON
    # {success, filters, meta, data:[advisory,...]} dan mendukung filter
    # ?vendor= / ?product= / ?cve= / ?severity= / ?dateFrom= / ?dateTo=.
    #
    # Dua job terpisah, keduanya dijalankan scheduler (BUKAN request-cycle):
    #   1. sync katalog vendor/product -> koleksi `kev_catalog`, dipakai
    #      sebagai sumber dropdown di form Tech Stack.
    #   2. (opsional) pipeline AI -> usulan draft rule ke `ai_proposals`.
    #
    # KEV_SYNC_ENABLED=False -> job tidak dijadwalkan (endpoint manual tetap
    # ada, mengembalikan error jelas kalau URL kosong). Pola ini sama dengan
    # BACKUP_ENABLED di Phase E.
    KEV_SYNC_ENABLED = os.environ.get('KEV_SYNC_ENABLED', 'False').lower() == 'true'
    KEV_ADVISORIES_URL = os.environ.get(
        'KEV_ADVISORIES_URL',
        'https://csirt.tangerangkota.go.id/api/advisories',
    )
    # Timeout HTTP (detik) untuk satu panggilan ke feed KEV.
    KEV_HTTP_TIMEOUT = int(os.environ.get('KEV_HTTP_TIMEOUT', '90'))
    # Jadwal sync katalog vendor/product (5-field cron: menit jam hari bulan
    # hari_minggu -- APScheduler's CronTrigger.from_crontab menolak 6 field).
    # Default: setiap 6 jam pada menit 15 (00:15, 06:15, 12:15, 18:15).
    KEV_SYNC_CRON = os.environ.get('KEV_SYNC_CRON', '15 */6 * * *')
    # Verifikasi sertifikat TLS feed KEV. False untuk self-signed/chain lokal.
    KEV_VERIFY_CERT = os.environ.get('KEV_VERIFY_CERT', 'True').lower() == 'true'

    # ── LLM (Phase F: AI rule proposal, Opsi C) ───────────────────────────
    # Provider OpenAI-compatible (chat/completions). Default mengarah ke
    # Kiyara Router. Base URL TANPA '/chat/completions' -- kode menambahkan
    # path-nya sendiri supaya tidak dobel kalau user menulis salah satu
    # bentuk.
    LLM_PROVIDER_URL = os.environ.get('LLM_PROVIDER_URL', 'https://kiyararouter.web.id/v1')
    LLM_MODEL = os.environ.get('LLM_MODEL', 'z-ai/glm-5.3')
    LLM_API_KEY = os.environ.get('LLM_API_KEY')
    # Timeout (detik) untuk satu panggilan chat/completions. Model reasoning
    # bisa lambat -- default longgar.
    LLM_HTTP_TIMEOUT = int(os.environ.get('LLM_HTTP_TIMEOUT', '180'))
    LLM_MAX_TOKENS = int(os.environ.get('LLM_MAX_TOKENS', '4096'))
    LLM_TEMPERATURE = float(os.environ.get('LLM_TEMPERATURE', '0.2'))
    # Aktifkan pipeline AI terjadwal (usulan draft rule dari KEV yang relevan
    # dengan tech_stack). False -> job tidak dijadwalkan; endpoint manual
    # tetap bisa dipakai untuk uji coba satu CVE.
    AI_PROPOSAL_ENABLED = os.environ.get('AI_PROPOSAL_ENABLED', 'False').lower() == 'true'
    AI_PROPOSAL_CRON = os.environ.get('AI_PROPOSAL_CRON', '30 */6 * * *')
    # Batas jumlah usulan yang dibuat per satu run job terjadwal (jaga biaya
    # token + hindari banjir draft sekaligus).
    AI_PROPOSAL_MAX_PER_RUN = int(os.environ.get('AI_PROPOSAL_MAX_PER_RUN', '10'))

    # ── Scheduler election ────────────────────────────────────────────────
    # Di deployment multi-proses (gunicorn -w N, waitress dengan >1 worker),
    # SETIAP worker akan menjalankan create_app() dan -- tanpa guard --
    # menyalakan scheduler sendiri, sehingga tiap job cron berjalan sekali
    # per worker (notifikasi dobel, dan usulan AI dobel -> biaya token).
    #
    # Guard reloader werkzeug saja tidak cukup untuk kasus itu. Solusinya:
    # set SCHEDULER_ENABLED=False di SEMUA worker kecuali satu (deployment
    # yang menjalankan scheduler sebagai proses/worker khusus), atau
    # biarkan True untuk deployment satu-proses (dev / waitress satu worker).
    # Lihat juga migrate.py-style pola env -> tidak ada auto-deteksi jumlah
    # worker: keputusan eksplisit operator.
    SCHEDULER_ENABLED = os.environ.get('SCHEDULER_ENABLED', 'True').lower() == 'true'