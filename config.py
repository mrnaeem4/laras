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

    # ── Exploit-DB (Phase F: exploit enrichment) ──────────────────────────
    # Setiap advisory CVE yang akan diusulkan dicek ke Exploit-DB. Hasilnya
    # dipakai sebagai KONTEKS TAMBAHAN untuk LLM (bukan auto-deploy): hanya
    # metadata exploit + potongan kode yang diperlakukan sebagai teks inert.
    #
    # Endpoint pencarian Exploit-DB adalah endpoint DataTables: parameter
    # `columns[...]` WAJIB lengkap, kalau tidak server membalas HTTP 500.
    # CVE dikirim TANPA prefix "CVE-" (mis. cve=2026-109618).
    #
    # Kode exploit diambil dari /raw/<id> (text/plain), BUKAN /download/<id>
    # (attachment biner). Modul ini tidak pernah mengeksekusi kode tersebut
    # dan tidak pernah menuliskannya ke disk.
    EXPLOITDB_ENABLED = os.environ.get('EXPLOITDB_ENABLED', 'False').lower() == 'true'
    EXPLOITDB_SEARCH_URL = os.environ.get(
        'EXPLOITDB_SEARCH_URL', 'https://www.exploit-db.com/search',
    )
    EXPLOITDB_RAW_URL = os.environ.get(
        'EXPLOITDB_RAW_URL', 'https://www.exploit-db.com/raw/{edb_id}',
    )
    EXPLOITDB_USER_AGENT = os.environ.get(
        'EXPLOITDB_USER_AGENT',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
        '(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    )
    EXPLOITDB_HTTP_TIMEOUT = int(os.environ.get('EXPLOITDB_HTTP_TIMEOUT', '30'))
    EXPLOITDB_VERIFY_CERT = os.environ.get('EXPLOITDB_VERIFY_CERT', 'True').lower() == 'true'
    EXPLOITDB_PAGE_SIZE = int(os.environ.get('EXPLOITDB_PAGE_SIZE', '15'))
    # Batas jumlah match yang disimpan / dikirim ke LLM.
    EXPLOITDB_MAX_RESULTS = int(os.environ.get('EXPLOITDB_MAX_RESULTS', '5'))
    # Berapa exploit teratas yang kode sumbernya ikut diambil (paling mahal:
    # satu request HTTP per exploit). 0 = metadata saja.
    EXPLOITDB_MAX_CODE_FETCH = int(os.environ.get('EXPLOITDB_MAX_CODE_FETCH', '2'))
    # Batas karakter potongan kode yang disimpan + dikirim ke LLM.
    EXPLOITDB_MAX_CODE_CHARS = int(os.environ.get('EXPLOITDB_MAX_CODE_CHARS', '3000'))
    # Batas byte yang dibaca dari /raw/<id> sebelum di-decode (anti response
    # raksasa). Potongan di atas MAX_CODE_CHARS tetap di-truncate.
    EXPLOITDB_MAX_RAW_BYTES = int(os.environ.get('EXPLOITDB_MAX_RAW_BYTES', '65536'))

    # Cache per CVE: hasil "ada exploit" relatif stabil (7 hari), hasil
    # "tidak ada exploit" dicek ulang lebih sering (24 jam) karena exploit
    # bisa terbit belakangan.
    EXPLOITDB_CACHE_TTL_HIT_HOURS = int(os.environ.get('EXPLOITDB_CACHE_TTL_HIT_HOURS', '168'))
    EXPLOITDB_CACHE_TTL_MISS_HOURS = int(os.environ.get('EXPLOITDB_CACHE_TTL_MISS_HOURS', '24'))

    # Retry queue (persisten di MongoDB, bukan sleep/date-job APScheduler).
    # Backoff percobaan ke-1 sengaja 5 menit sesuai permintaan.
    EXPLOITDB_MAX_ATTEMPTS = int(os.environ.get('EXPLOITDB_MAX_ATTEMPTS', '5'))
    EXPLOITDB_RETRY_BACKOFF_MINUTES = [
        int(x) for x in os.environ.get(
            'EXPLOITDB_RETRY_BACKOFF_MINUTES', '5,15,60,360',
        ).split(',') if x.strip().isdigit()
    ] or [5, 15, 60, 360]
    # Job retry berjalan tiap menit dan hanya memproses entri yang
    # next_retry_at-nya sudah lewat -- jadi jarak retry benar-benar +/- 5
    # menit, bukan dibulatkan ke kelipatan 5 menit seperti cron */5.
    # Default mengikuti EXPLOITDB_ENABLED: begitu enrichment diaktifkan,
    # retry ikut aktif (tanpa retry, kegagalan sementara kehilangan konteks
    # exploit). Bisa dimatikan eksplisit lewat EXPLOITDB_RETRY_ENABLED=False.
    EXPLOITDB_RETRY_ENABLED = os.environ.get(
        'EXPLOITDB_RETRY_ENABLED',
        os.environ.get('EXPLOITDB_ENABLED', 'False'),
    ).lower() == 'true'
    EXPLOITDB_RETRY_CRON = os.environ.get('EXPLOITDB_RETRY_CRON', '* * * * *')
    EXPLOITDB_RETRY_BATCH = int(os.environ.get('EXPLOITDB_RETRY_BATCH', '5'))

    # Refresh sweep: cek ulang CVE yang sudah punya proposal pending, supaya
    # exploit yang terbit BELAKANGAN tetap tertangkap. Tidak mengubah draft;
    # hanya menandai needs_review.
    EXPLOITDB_REFRESH_ENABLED = os.environ.get('EXPLOITDB_REFRESH_ENABLED', 'False').lower() == 'true'
    EXPLOITDB_REFRESH_CRON = os.environ.get('EXPLOITDB_REFRESH_CRON', '0 3 * * *')
    EXPLOITDB_REFRESH_BATCH = int(os.environ.get('EXPLOITDB_REFRESH_BATCH', '20'))
    EXPLOITDB_REFRESH_TTL_HOURS = int(os.environ.get('EXPLOITDB_REFRESH_TTL_HOURS', '168'))

    # Rate limiter global (lintas proses: web + scheduler). Semua request ke
    # Exploit-DB -- search, /raw, retry, refresh -- wajib mengklaim slot ini
    # dulu. Tanpa ini, retry per-CVE bisa berubah menjadi burst paralel dan
    # memicu blokir Cloudflare.
    EXPLOITDB_MAX_CONCURRENT = int(os.environ.get('EXPLOITDB_MAX_CONCURRENT', '2'))
    EXPLOITDB_MIN_INTERVAL_SECONDS = float(os.environ.get('EXPLOITDB_MIN_INTERVAL_SECONDS', '2'))
    # Slot yang tidak pernah dilepas (proses mati di tengah fetch) dianggap
    # basi setelah waktu ini.
    EXPLOITDB_SLOT_LEASE_SECONDS = int(os.environ.get('EXPLOITDB_SLOT_LEASE_SECONDS', '180'))
    # Saat mengambil kode (/raw) setelah search, tunggu slot rate limiter
    # sebentar (bukan menyerah) supaya excerpt benar-benar didapat. Ini
    # jeda pendek yang disengaja, bukan retry 5 menit.
    EXPLOITDB_CODE_WAIT_SECONDS = float(os.environ.get('EXPLOITDB_CODE_WAIT_SECONDS', '5'))

    # Circuit breaker: N kegagalan berturut-turut dalam window -> jeda total.
    EXPLOITDB_CIRCUIT_FAILURE_THRESHOLD = int(
        os.environ.get('EXPLOITDB_CIRCUIT_FAILURE_THRESHOLD', '3'))
    EXPLOITDB_CIRCUIT_WINDOW_SECONDS = int(
        os.environ.get('EXPLOITDB_CIRCUIT_WINDOW_SECONDS', '60'))
    EXPLOITDB_CIRCUIT_COOLDOWN_SECONDS = int(
        os.environ.get('EXPLOITDB_CIRCUIT_COOLDOWN_SECONDS', '600'))

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