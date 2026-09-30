# LARAS — Wazuh Rule & Decoder Management

**LARAS** (*Selaras*) adalah aplikasi web internal untuk tim SOC yang dipakai membangun, memvalidasi, menguji, mem-versioning, dan mem-promosikan **Wazuh Rules & Decoders** — dari draft di komputer analis sampai aktif di Wazuh Manager **Prod**, tanpa menulis XML secara manual.

Filosofi utama:

- **Human-in-the-loop.** Rule AI tetap masuk sebagai draft dan wajib lewat gate yang sama dengan rule buatan manusia.
- **4-eyes.** Perubahan ke Prod harus disetujui user lain yang berperan sebagai reviewer.
- **Tercatat.** Setiap perubahan punya history append-only (siapa/kapan/apa) dan bisa di-rollback.
- **Teruji sebelum Prod.** Alur wajib: Draft → Deploy Dev → Logtest → Passed → Promote Prod.

---

## Daftar Isi

1. [Fitur Utama](#1-fitur-utama)
2. [Arsitektur & Alur Lifecycle](#2-arsitektur--alur-lifecycle)
3. [Prasyarat](#3-prasyarat)
4. [Instalasi](#4-instalasi)
5. [Konfigurasi (.env)](#5-konfigurasi-env)
6. [Menjalankan Aplikasi](#6-menjalankan-aplikasi)
7. [Akun & CLI](#7-akun--cli)
8. [Migrasi Data](#8-migrasi-data)
9. [Halaman UI](#9-halaman-ui)
10. [API Endpoint](#10-api-endpoint)
11. [Backup, Scheduler & Notifikasi](#11-backup-scheduler--notifikasi)
12. [Threat Intelligence (KEV) & AI Rule Proposal](#12-threat-intelligence-kev--ai-rule-proposal)
13. [Struktur Proyek](#13-struktur-proyek)
14. [Troubleshooting](#14-troubleshooting)

---

## 1. Fitur Utama

| Fitur | Keterangan |
|-------|------------|
| **Rule Builder** | Wizard 6 langkah untuk membuat rule Wazuh, termasuk static field, dynamic field, MITRE ATT&CK, dan Test Samples. |
| **Decoder Builder** | Membuat decoder (`parent`, `prematch`, `regex` osregex/pcre2, `order`). |
| **Rule / Decoder List** | Tabel pencarian & filter, badge status sync Dev/Prod, dan stepper lifecycle. |
| **Import / Export** | Upload XML ruleset ke MongoDB, atau export kembali sebagai file XML. |
| **Sync & Manager** | Pull/push/diff file antara MongoDB dan Wazuh Manager Dev/Prod, plus restart manager. |
| **Promotion (4-eyes)** | Ajukan promote ke Prod, disetujui reviewer lain, baru di-push. |
| **Versioning & Rollback** | History append-only per rule/decoder, diff antar versi, dan rollback (otomatis masuk antrean promote). |
| **Log Tester** | Kirim log ke `wazuh-logtest` Wazuh Manager **Dev** dan lihat hasil analisisnya. |
| **PCRE2 Tester** | Uji & validasi pola regex/PCRE2 secara lokal (tanpa koneksi Wazuh). |
| **Tech Stack Inventory** | Inventaris vendor/product/versi infrastruktur, dipakai sebagai filter relevansi CVE/KEV. |
| **AI Proposals** | Usulan draft rule otomatis dari advisory KEV yang relevan dengan tech stack — untuk direview manusia. |
| **Backup & Restore** | Backup koleksi MongoDB ke S3/MinIO, terjadwal atau on-demand, plus restore. |
| **Auth & Session** | Login (Flask-Login), session server-side di MongoDB, CSRF protection, session bisa dicabut seketika. |

---

## 2. Arsitektur & Alur Lifecycle

![Laras.io Architecture](/static/img/Laras%20Architecture.jpeg "Laras.io Architecture")

- **Dua Wazuh Manager** dikonfigurasi terpisah: `dev` dan `prod`.
- **Push manual** (`/api/wazuh/push`) **selalu ke Dev** dan bebas gate — dipakai untuk testing.
- **Satu-satunya jalur ke Prod** adalah **promote** yang lewat approval reviewer (`approved_by != proposed_by`).
- Status lifecycle rule **dihitung on-the-fly** (tidak disimpan sebagai field mutable) dari `sync_state` + `test_results`, dengan state: `draft` → `deployed_dev` → `tested` → `passed` → `promoted_prod`.

Status sync per environment: `new`, `synced`, `modified_local`, `conflict`.

---

## 3. Prasyarat

| Prasyarat | Versi / Catatan |
|-----------|-----------------|
| Python | 3.10+ |
| pip | 22+ |
| MongoDB | 6.x (wajib — app butuh MongoDB untuk login & data) |
| Wazuh Manager Dev & Prod | v4.x, REST API aktif di port `55000` |
| S3/MinIO | Opsional, hanya untuk fitur Backup |
| Telegram Bot | Opsional, hanya untuk notifikasi |

Cek versi Python:

```bash
python --version
```

---

## 4. Instalasi

```bash
# Masuk ke direktori proyek
cd wz_rule_management

# Buat virtual environment
python -m venv venv

# Aktifkan (Windows PowerShell)
venv\Scripts\activate
# Aktifkan (Linux / macOS)
# source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

Dependensi utama (`requirements.txt`):

| Package | Versi | Fungsi |
|---------|-------|--------|
| Flask | 3.0.0 | Web framework |
| Werkzeug | 3.0.1 | WSGI utilities / hashing password |
| requests | 2.32.3 | HTTP client ke Wazuh API & feed KEV/LLM |
| lxml | 5.1.0 | Parsing & generasi XML |
| xmltodict | 0.13.0 | Parsing XML pendukung |
| python-dotenv | 1.0.0 | Membaca `.env` |
| pymongo | 4.6.1 | Driver MongoDB |
| Flask-Login | 0.6.3 | Autentikasi |
| Flask-Session | 0.8.0 | Session server-side (MongoDB) |
| Flask-WTF | 1.3.0 | CSRF protection |
| APScheduler | 3.10.4 | Scheduler job terjadwal |
| Flask-APScheduler | 1.13.1 | Integrasi scheduler dengan Flask |
| boto3 | 1.34.151 | Klien S3/MinIO (backup) |

---

## 5. Konfigurasi (.env)

Salin template lalu sesuaikan:

```bash
# Windows
copy .env.example .env
# Linux / macOS
cp .env.example .env
```

### 5.1 Variabel Flask & Session

| Variabel | Default | Keterangan |
|----------|---------|------------|
| `SECRET_KEY` | `dev-secret-key-...` | Kunci session Flask. **Wajib diganti** di produksi. |
| `DEBUG` | `False` | Mode debug Flask. Matikan di produksi. |
| `SESSION_LIFETIME_SECONDS` | `28800` (8 jam) | Umur session, cover satu shift SOC. |
| `SESSION_MONGODB_DB` | `MONGO_DB_NAME` | Nama DB tempat session disimpan. |
| `SESSION_COOKIE_SECURE` | `False` | Set `True` hanya jika app sudah disajikan via HTTPS. |

### 5.2 Wazuh Manager API (Dev & Prod terpisah)

> Kedua environment **wajib diisi eksplisit**. Tidak ada fallback ke `WAZUH_API_*` lama — app akan gagal dengan jelas jika belum dikonfigurasi.

| Variabel | Contoh | Keterangan |
|----------|--------|------------|
| `WAZUH_DEV_API_URL` | `https://dev-wazuh:55000` | Base URL Wazuh Manager Dev. |
| `WAZUH_DEV_API_USER` | `wazuh` | User API Dev. |
| `WAZUH_DEV_API_PASSWORD` | `wazuh` | Password API Dev. |
| `WAZUH_DEV_API_VERIFY_CERT` | `False` | Verifikasi TLS Dev (self-signed → `False`). |
| `WAZUH_PROD_API_URL` | `https://prod-wazuh:55000` | Base URL Wazuh Manager Prod. |
| `WAZUH_PROD_API_USER` | `wazuh` | User API Prod. |
| `WAZUH_PROD_API_PASSWORD` | `wazuh` | Password API Prod. |
| `WAZUH_PROD_API_VERIFY_CERT` | `False` | Verifikasi TLS Prod. |

### 5.3 MongoDB

| Variabel | Default | Keterangan |
|----------|---------|------------|
| `MONGO_URI` | `mongodb://localhost:27017/` | URI koneksi MongoDB (dukung auth: `mongodb://user:pass@host:27017/`). |
| `MONGO_DB_NAME` | `wazuh_rule_management` | Nama database. |

> Jika MongoDB tidak tersedia, app tetap start, tetapi login dan seluruh fitur berbasis data akan mengembalikan error 503.

### 5.4 Backup (S3/MinIO)

| Variabel | Default | Keterangan |
|----------|---------|------------|
| `BACKUP_ENABLED` | `False` | Aktifkan scheduler backup otomatis. |
| `S3_ENDPOINT_URL` | – | Endpoint S3/MinIO, mis. `http://localhost:9000`. |
| `S3_ACCESS_KEY` / `S3_SECRET_KEY` | – | Kredensial S3. |
| `S3_BUCKET` | `laras-backups` | Bucket tujuan (dibuat otomatis bila belum ada). |
| `S3_REGION` | *(kosong)* | Region S3 (boleh kosong untuk MinIO). |
| `S3_PREFIX` | `backups` | Prefix key objek. |
| `BACKUP_CRON` | `0 2 * * *` | Jadwal backup (cron **5-field**). |
| `BACKUP_COLLECTIONS` | `rules,decoders,rule_history,decoder_history,promotion_requests,users,manager_actions` | Koleksi yang ikut di-backup. |

### 5.5 Notifikasi Telegram

| Variabel | Default | Keterangan |
|----------|---------|------------|
| `TELEGRAM_BOT_TOKEN` | *(kosong)* | Token bot. Kosongkan untuk menonaktifkan notifikasi. |
| `TELEGRAM_CHAT_ID` | *(kosong)* | Chat ID tujuan. |

### 5.6 KEV Feed & LLM

| Variabel | Default | Keterangan |
|----------|---------|------------|
| `KEV_SYNC_ENABLED` | `False` | Aktifkan job sync katalog vendor/product. |
| `KEV_ADVISORIES_URL` | `https://csirt.tangerangkota.go.id/api/advisories` | Sumber feed advisory. |
| `KEV_HTTP_TIMEOUT` | `90` | Timeout HTTP feed (detik). |
| `KEV_SYNC_CRON` | `15 */6 * * *` | Jadwal sync katalog (cron 5-field). |
| `KEV_VERIFY_CERT` | `True` | Verifikasi TLS feed KEV. |
| `LLM_PROVIDER_URL` | `https://kiyararouter.web.id/v1` | Base URL provider OpenAI-compatible (tanpa `/chat/completions`). |
| `LLM_MODEL` | `z-ai/glm-5.3` | Nama model. |
| `LLM_API_KEY` | *(kosong)* | API key provider. |
| `LLM_HTTP_TIMEOUT` | `180` | Timeout panggilan LLM (detik). |
| `LLM_MAX_TOKENS` | `4096` | Batas token respons. |
| `LLM_TEMPERATURE` | `0.2` | Suhu sampling. |
| `AI_PROPOSAL_ENABLED` | `False` | Aktifkan job usulan rule AI. |
| `AI_PROPOSAL_CRON` | `30 */6 * * *` | Jadwal pipeline AI (cron 5-field). |
| `AI_PROPOSAL_MAX_PER_RUN` | `10` | Batas usulan baru per run. |

### 5.7 Scheduler

| Variabel | Default | Keterangan |
|----------|---------|------------|
| `SCHEDULER_ENABLED` | `True` | Di deployment multi-worker, set `False` di semua worker kecuali satu agar job cron tidak berjalan dobel. |

> **Catatan cron:** APScheduler `CronTrigger.from_crontab()` hanya menerima **5 field** (`menit jam hari bulan hari_minggu`). Nilai 6-field akan membuat job tidak pernah dijadwalkan.

---

## 6. Menjalankan Aplikasi

### 6.1 Development

```bash
python app.py
```

Aplikasi berjalan di **http://localhost:5000** (host `0.0.0.0`, port `5000`).

### 6.2 Production (Waitress)

```bash
pip install waitress
waitress-serve --host=0.0.0.0 --port=5000 "app:create_app()"
```

Atau Gunicorn (Linux/macOS):

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 "app:create_app()"
```

> Untuk multi-worker, atur `SCHEDULER_ENABLED=False` di semua worker kecuali satu.

### 6.3 Mengubah Port

Edit bagian akhir `app.py`:

```python
app.run(host='0.0.0.0', port=5000, debug=app.config['DEBUG'])
```

---

## 7. Akun & CLI

Tidak ada halaman registrasi mandiri. Akun dibuat oleh admin lewat CLI:

```bash
# Membuat akun (akan meminta password secara interaktif)
flask --app app:create_app create-user <username>

# Memberi status reviewer (boleh approve promote ke Prod)
flask --app app:create_app set-reviewer <username>

# Mencabut status reviewer
flask --app app:create_app set-reviewer <username> --unset
```

Login di **http://localhost:5000/auth/login**.

> Gate 4-eyes menegakkan dua hal saat approve: approver harus `is_reviewer=True`, **dan** `approved_by != proposed_by`.

---

## 8. Migrasi Data

Untuk instalasi lama (sebelum arsitektur Dev/Prod) yang masih punya field sync flat:

```bash
python migrate.py
```

Skrip ini menjalankan `migrate_sync_fields_to_env_state('prod')` — menyalin `sync_status`/`last_synced_hash`/`last_synced_at` lama ke `sync_state.prod.*` secara non-destruktif dan idempotent. Jalankan sekali, sadar oleh operator (tidak otomatis saat startup).

---

## 9. Halaman UI

| Path | Halaman |
|------|---------|
| `/` | Redirect ke Decoder Builder |
| `/decoder` | Decoder Builder |
| `/rule` | Rule Builder |
| `/decoders` | Saved Decoders |
| `/rules` | Saved Rules |
| `/import-export` | Import / Export XML |
| `/sync` | Sync & Manager (pull/push/diff/restart/promotion) |
| `/tech-stack` | Tech Stack Inventory |
| `/ai-proposals` | Review usulan draft rule AI |
| `/log-tester` | Live Log Tester (ke Wazuh Dev) |
| `/pcre2-tester` | PCRE2 Pattern Tester (lokal) |
| `/auth/login` | Login |

---

## 10. API Endpoint

Semua endpoint di bawah **wajib login**. Kirim header `Content-Type: application/json` dan sertakan CSRF token sesuai kebutuhan.

### Autentikasi Wazuh (debug)

| Method | Endpoint | Keterangan |
|--------|----------|------------|
| `POST` | `/api/auth` | Autentikasi manual ke Wazuh (`{"env": "dev"|"prod"}`). Operasi normal self-authenticate otomatis. |

### Autocomplete & User

| Method | Endpoint | Keterangan |
|--------|----------|------------|
| `GET` | `/api/autocomplete/sids` | Daftar rule ID dari MongoDB (untuk `if_sid`). |
| `GET` | `/api/autocomplete/groups` | Daftar group tag unik. |
| `GET` | `/api/autocomplete/decoders` | Daftar nama decoder. |
| `GET` | `/api/me` | Info user login (username, `is_reviewer`). |

### Builder (Rule & Decoder)

| Method | Endpoint | Keterangan |
|--------|----------|------------|
| `POST` | `/builder/decoder/xml` | Generate XML decoder (tanpa simpan). |
| `POST` | `/builder/decoder/save` | Generate + simpan decoder. |
| `GET` | `/builder/decoder/list` | List decoder. |
| `GET` | `/builder/decoder/<id>` | Detail decoder. |
| `DELETE` | `/builder/decoder/<id>` | Hapus decoder. |
| `GET` | `/builder/decoder/history` | History versi decoder. |
| `POST` | `/builder/decoder/rollback` | Rollback decoder. |
| `POST` | `/builder/rule/xml` | Generate XML rule (tanpa simpan). |
| `POST` | `/builder/rule/save` | Generate + simpan rule (wajib ≥1 test sample `expect_match=true`). |
| `GET` | `/builder/rule/list` | List rule. |
| `GET` | `/builder/rule/<id>` | Detail rule. |
| `DELETE` | `/builder/rule/<id>` | Hapus rule. |
| `POST` | `/builder/rule/<id>/test-results` | Simpan snapshot hasil "Run All Samples". |
| `POST` | `/builder/rule/<id>/deploy-dev` | Deploy satu rule custom ke Dev + reload. |
| `GET` | `/builder/rule/<id>/history` | History versi rule. |
| `POST` | `/builder/rule/<id>/rollback/<version>` | Rollback rule (otomatis buat promotion request bila perlu). |

### Import / Export

| Method | Endpoint | Keterangan |
|--------|----------|------------|
| `POST` | `/importer/upload/rules` | Upload XML rules → parse → upsert MongoDB. |
| `POST` | `/importer/upload/decoders` | Upload XML decoders → parse → upsert MongoDB. |
| `GET` | `/importer/export/rules` | Export rule terpilih sebagai file XML. |
| `GET` | `/importer/export/decoders` | Export decoder terpilih sebagai file XML. |

### Sync & Wazuh Manager

| Method | Endpoint | Keterangan |
|--------|----------|------------|
| `GET` | `/api/wazuh/files?env=dev|prod` | Overview sync per file. |
| `GET` | `/api/wazuh/diff/<file_type>/<filename>?env=` | Diff lokal vs remote. |
| `POST` | `/api/wazuh/pull` | Pull dari Dev/Prod (`{"env", "filenames"}`). |
| `POST` | `/api/wazuh/push` | Push ke **Dev saja**, tanpa gate. |
| `POST` | `/api/wazuh/restart` | Restart manager Dev/Prod (`{"env"}`). |
| `POST` | `/api/wazuh/promote/request` | Ajukan promote ke Prod. |
| `GET` | `/api/wazuh/promote/requests` | List promotion request. |
| `POST` | `/api/wazuh/promote/<id>/approve` | Approve (reviewer saja) → push ke Prod. |
| `POST` | `/api/wazuh/promote/<id>/reject` | Reject / batalkan. |

### Tech Stack, KEV & AI

| Method | Endpoint | Keterangan |
|--------|----------|------------|
| `GET` | `/api/tech-stack` | List item tech stack. |
| `POST` | `/api/tech-stack` | Tambah item. |
| `PUT` | `/api/tech-stack/<id>` | Ubah item. |
| `DELETE` | `/api/tech-stack/<id>` | Hapus item. |
| `GET` | `/api/kev/status` | Status katalog KEV + konfigurasi job. |
| `GET` | `/api/kev/catalog/vendors` | Vendor dari katalog KEV (dropdown). |
| `GET` | `/api/kev/catalog/products` | Product dari katalog KEV (dropdown). |
| `POST` | `/api/kev/sync` | Sync katalog KEV on-demand. |
| `GET` | `/api/ai/proposals` | List usulan draft rule AI. |
| `POST` | `/api/ai/proposals/generate` | Jalankan pipeline AI on-demand. |
| `POST` | `/api/ai/proposals/<id>/dismiss` | Tandai usulan sebagai dismissed. |

### Backup

| Method | Endpoint | Keterangan |
|--------|----------|------------|
| `POST` | `/api/backup` | Buat backup on-demand. |
| `GET` | `/api/backups` | List backup yang ada. |
| `POST` | `/api/backup/restore` | Restore backup (destruktif — drop lalu insert ulang koleksi terpilih). |

### Tester

| Method | Endpoint | Keterangan |
|--------|----------|------------|
| `POST` | `/tester/logtest` | Kirim log ke `wazuh-logtest` (selalu ke **Dev**). |
| `POST` | `/tester/pcre2/test` | Uji pola PCRE2 terhadap string log (lokal). |
| `POST` | `/tester/pcre2/validate` | Validasi syntax PCRE2. |

**Contoh — uji PCRE2:**

```json
// POST /tester/pcre2/test
{
  "pattern": "(?P<srcip>\\d{1,3}(?:\\.\\d{1,3}){3})",
  "log": "Failed login from 192.168.1.50 port 22"
}
```

```json
// Response
{
  "match_found": true,
  "matches": ["192.168.1.50"],
  "extracted": { "srcip": "192.168.1.50" },
  "pattern_info": { "valid": true, "group_names": ["srcip"] }
}
```

---

## 11. Backup, Scheduler & Notifikasi

- **Backup** mengekspor koleksi terpilih ke JSON gzip dan mengunggahnya ke S3/MinIO (via `boto3`). Tersedia on-demand (`POST /api/backup`) dan terjadwal (`BACKUP_CRON`).
- **Restore** bersifat destruktif: koleksi terpilih di-drop lalu di-insert ulang dari isi backup, dengan konfirmasi ganda di UI.
- **Scheduler** (APScheduler) menjalankan tiga job independen, masing-masing punya flag sendiri:
  1. Backup otomatis — `BACKUP_ENABLED`
  2. Sync katalog KEV — `KEV_SYNC_ENABLED`
  3. Usulan rule AI — `AI_PROPOSAL_ENABLED`
  Scheduler hanya start jika minimal satu job aktif.
- **Notifikasi** memakai Telegram (abstraction `BaseNotifier`); jika token kosong, notifikasi menjadi no-op. Event yang dinotifikasi antara lain: promotion diajukan/disetujui/ditolak, push ke Dev gagal, dan restart Dev/Prod.

---

## 12. Threat Intelligence (KEV) & AI Rule Proposal

- **Sumber feed:** API CSIRT Tangerang Kota (`/api/advisories`) — JSON bergaya KEV dengan filter `vendor`, `product`, `cve`, `severity`, `dateFrom`, `dateTo`. Karena tidak ada header CORS, feed **wajib dipanggil server-side**.
- **Sync katalog** (`kev_catalog`) menyimpan pasangan vendor/product unik untuk mengisi dropdown form Tech Stack. Sync bersifat idempotent — hanya menyisipkan yang belum ada.
- **Pipeline AI** (`services/ai_utils.py`):
  1. Ambil advisory KEV.
  2. Filter relevansi terhadap `tech_stack`.
  3. Skor prioritas deterministik.
  4. Minta LLM menyusun draft rule.
  5. Simpan sebagai usulan `pending` di koleksi `ai_proposals`.

**Jaminan keamanan:** AI **tidak pernah** menulis langsung ke `rules`/`decoders`, tidak push ke Wazuh, dan tidak melewati gate. Semua usulan menunggu keputusan manusia di halaman `/ai-proposals` (bisa di-prefill ke Rule Builder, tapi tidak auto-save). Teks feed diperlakukan sebagai data (anti prompt-injection).

Kontrak bentuk XML Wazuh sebagai satu sumber kebenaran ada di `services/wazuh_contract.py`, dipakai bersama oleh prompt LLM, normalizer, dan XML generator.

---

## 13. Struktur Proyek

```
laras/
├── app.py                  # Factory create_app(), registrasi blueprint, CLI, scheduler
├── config.py               # Kelas Config (baca .env)
├── database.py             # Koneksi MongoDB, index, collection helper, migrasi sync_state
├── migrate.py              # Skrip migrasi Phase C (single-manager → Dev/Prod)
├── requirements.txt
├── .env.example
│
├── blueprints/             # Route handlers
│   ├── auth.py             # Login/logout, User model, revoke session
│   ├── builder.py          # CRUD rule & decoder, history, rollback, deploy-dev
│   ├── api.py              # Autocomplete, sync/push/pull/diff, promote, tech-stack, KEV, AI, backup
│   ├── importer.py         # Upload & export XML
│   ├── tester.py           # Logtest & PCRE2 tester
│   └── pages.py            # Route halaman UI
│
├── services/               # Business logic
│   ├── wazuh_api.py        # Klien Wazuh REST API (env-aware, pull/push/logtest/restart)
│   ├── wazuh_contract.py   # Kontrak elemen XML Wazuh (sumber kebenaran)
│   ├── xml_generator.py    # Form data → XML
│   ├── xml_parser.py       # XML → dokumen
│   ├── sync_utils.py       # content_hash & status sync per environment
│   ├── history_utils.py    # Versioning append-only
│   ├── lifecycle_utils.py  # Hitung lifecycle_status
│   ├── promotion_utils.py  # Workflow 4-eyes
│   ├── pcre2_service.py    # Validasi & uji PCRE2
│   ├── wazuh_compat.py     # Deteksi pola yang tidak kompatibel dengan parser Wazuh
│   ├── backup_utils.py     # Backup/restore S3
│   ├── notification.py     # Notifikasi Telegram
│   ├── tech_stack_utils.py # Inventaris tech stack
│   ├── kev_utils.py        # Fetch & sync feed KEV
│   └── ai_utils.py         # Pipeline usulan rule AI
│
├── templates/              # Jinja2: base + satu template per halaman + partials/ (modal)
└── static/
    ├── css/                # app.css, app-dark.css
    ├── img/                # icon dan logo laras
    └── js/                 # Satu file JS per halaman + common.js, csrf.js, sync_common.js
```

### Koleksi MongoDB

`rules`, `decoders`, `rule_history`, `decoder_history`, `users`, `manager_actions`, `promotion_requests`, `tech_stack`, `kev_catalog`, `ai_proposals`, `sessions`, `session_index`.

Koleksi audit (`rule_history`, `decoder_history`, `manager_actions`) dibungkus **append-only** — update/delete melempar `RuntimeError`. `promotion_requests` dan `ai_proposals` dibungkus **no-delete** — status boleh berubah, dokumen tidak boleh dihapus.

---

## 14. Troubleshooting

**Login gagal / "MongoDB tidak tersedia"**
Pastikan MongoDB berjalan dan `MONGO_URI` benar. Cek koneksi:
```bash
python -c "from pymongo import MongoClient; print(MongoClient('mongodb://localhost:27017/', serverSelectionTimeoutMS=3000).server_info()['version'])"
```

**Tidak bisa login karena belum ada akun**
Buat akun lewat CLI (lihat [bagian 7](#7-akun--cli)):
```bash
flask --app app:create_app create-user admin
```

**`ModuleNotFoundError: No module named 'flask'`**
Virtual environment belum aktif atau dependencies belum terinstall:
```bash
venv\Scripts\activate        # Windows
pip install -r requirements.txt
```

**App start tetapi semua fitur error 503**
MongoDB tidak terjangkau saat startup. App sengaja tetap boot tanpa MongoDB; restart setelah MongoDB hidup.

**Connect / push ke Wazuh gagal**
1. Pastikan Wazuh Manager Dev/Prod berjalan: `systemctl status wazuh-manager`.
2. Periksa format URL: `https://IP:55000`.
3. Periksa user/password API.
4. Untuk self-signed certificate, set `WAZUH_DEV_API_VERIFY_CERT=False` / `WAZUH_PROD_API_VERIFY_CERT=False`.
5. Pastikan port `55000` bisa diakses dari host aplikasi.

**Log Tester tidak akurat / PASS-FAIL menyesatkan**
`wazuh-logtest` menguji terhadap ruleset yang **sedang aktif di Wazuh Dev** (hasil push + reload terakhir), bukan draft di wizard. Jalankan "Deploy & Run All" agar rule tersimpan, ter-deploy ke Dev, lalu diuji — hasil baru dipersist bila versinya terkini.

**Job terjadwal tidak jalan**
Pastikan cron memakai **5 field**. Nilai 6-field ditolak `CronTrigger.from_crontab()` sehingga job tidak pernah didaftarkan. Cek juga flag `*_ENABLED` terkait.

**Job cron berjalan dobel**
Terjadi di deployment multi-worker. Set `SCHEDULER_ENABLED=False` di semua worker kecuali satu.

**CSRF token expired**
`WTF_CSRF_TIME_LIMIT` sudah diset `None` agar token valid selama session. Jika masih terjadi, hapus cookie dan login ulang.
