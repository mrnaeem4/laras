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
4. [Instalasi](#4-instalasi) — [Docker](#41-jalur-docker-direkomendasikan) · [manual](#42-jalur-manual-tanpa-docker)
5. [Konfigurasi (.env)](#5-konfigurasi-env)
6. [Menjalankan Aplikasi](#6-menjalankan-aplikasi)
7. [Akun & CLI](#7-akun--cli)
8. [Halaman UI](#8-halaman-ui)
9. [API Endpoint](#9-api-endpoint)
10. [Backup, Scheduler & Notifikasi](#10-backup-scheduler--notifikasi)
11. [Threat Intelligence (KEV) & AI Rule Proposal](#11-threat-intelligence-kev--ai-rule-proposal)
12. [Struktur Proyek](#12-struktur-proyek)
13. [Operasi Docker](#13-operasi-docker)
14. [Troubleshooting](#14-troubleshooting)
15. [Checklist Go-Live](#15-checklist-go-live)
16. [Catatan Keamanan Container](#16-catatan-keamanan-container)

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

### 3.1 Jalur Docker

| Item | Catatan |
|------|---------|
| Docker Desktop (Windows) | Backend WSL2. Cek: `docker --version` dan `docker compose version`. |
| OpenSSL | Untuk membuat sertifikat TLS. Sudah ada di Git for Windows / Git Bash. Cek: `openssl version`. |
| Wazuh Manager Dev & Prod | v4.x, REST API port `55000` **dapat dijangkau dari dalam container**. |
| Port host bebas | `5000` (HTTPS app), `27017` (Mongo bila container), `9000`/`9001` (MinIO bila container). |
| MongoDB | Wajib — versi container (profile `local-mongo`) **atau** eksternal. |
| S3/MinIO | Opsional, hanya untuk fitur Backup. Container (profile `local-minio`) **atau** eksternal. |

### 3.2 Jalur manual (tanpa Docker)

| Prasyarat | Versi / Catatan |
|-----------|-----------------|
| Python | 3.10+ |
| pip | 22+ |
| MongoDB | 6.x (wajib — app butuh MongoDB untuk login & data) |
| Wazuh Manager Dev & Prod | v4.x, REST API aktif di port `55000` |
| S3/MinIO | Opsional, hanya untuk fitur Backup |
| Telegram Bot | Opsional, hanya untuk notifikasi |

---

## 4. Instalasi

### 4.1 Jalur Docker (direkomendasikan)

#### 4.1.1 Model deployment

LARAS berjalan sebagai **satu image** yang dipakai oleh **dua peran**. MongoDB dan MinIO opsional (container sendiri atau eksternal).

```
                    ┌──────────────────────┐
   browser ──HTTPS──▶  app (gunicorn+TLS) │  SCHEDULER_ENABLED=false
                    │  read_only + tmpfs   │
                    └───────────┬──────────┘
                                │
                    ┌───────────▼──────────┐
                    │  mongo (profile)     │  opsional / eksternal
                    └───────────▲──────────┘
                                │
                    ┌───────────┴──────────┐
                    │  scheduler           │  SCHEDULER_ENABLED=true
                    │  BlockingScheduler   │  tanpa HTTP
                    └──────────────────────┘
```

| Service | Peran | Port | `SCHEDULER_ENABLED` |
|---------|-------|------|---------------------|
| `app` | Web HTTPS (gunicorn + TLS self-signed) | `5000` (host) → `5000` | **false** |
| `scheduler` | Cron saja (`BlockingScheduler`, tanpa Flask) | – | **true** |
| `mongo` | Database — profile `local-mongo` | `127.0.0.1:27017` | – |
| `minio` | Object storage — profile `local-minio` | `127.0.0.1:9000/9001` | – |

#### 4.1.2 Pilih environment


| Lingkungan | Mongo | MinIO | Perintah `up` |
|------------|-------|-------|---------------|
| **Lokal / uji coba** | container | container | `docker compose --profile local-mongo --profile local-minio up -d --build` |
| **Staging** | container | eksternal | `docker compose --profile local-mongo up -d --build` |
| **Produksi** | eksternal | eksternal | `docker compose up -d --build` |

Pada produksi, MongoDB dan MinIO **sebaiknya eksternal**: punya backup, replika, dan lifecycle sendiri. Menjalankan database produksi di dalam compose yang sama membuat `docker compose down -v` (satu perintah salah) berpotensi menghapus rules dan audit trail.

Nilai `.env` per environment:

| Variabel | Lokal | Produksi eksternal |
|----------|-------|--------------------|
| `MONGO_URI` | `mongodb://admin:admin@mongo:27017/?authSource=admin` | `mongodb://<user>:<pass>@<host>:27017/?authSource=admin` |
| `S3_ENDPOINT_URL` | `http://minio:9000` | `https://<endpoint-s3-anda>` |
| `SECRET_KEY` | string acak | **string acak kuat, unik per environment** |
| `DEBUG` | `false` oleh compose | `false` oleh compose |
| `SESSION_COOKIE_SECURE` | `true` | `true` |
| `WAZUH_*_API_URL` | `https://host.docker.internal:55000` | `https://<wazuh-dev>:55000` / `https://<wazuh-prod>:55000` |
| `TZ` | `Asia/Jakarta` | sesuai zona operasional SOC |


#### 4.1.3 Kredensial default — WAJIB diganti

Template `.env.docker.example` memakai kredensial contoh yang **diketahui publik**. Semuanya aman hanya untuk uji di mesin sendiri.

| Variabel | Default template | Dipakai oleh | Risiko bila dibiarkan |
|----------|------------------|--------------|------------------------|
| `MONGO_ROOT_USER` / `MONGO_ROOT_PASSWORD` | `admin` / `admin` | container `mongo` (profile `local-mongo`) | Siapa pun yang bisa menjangkau port 27017 bisa membaca/menghapus rules & audit trail |
| `S3_ACCESS_KEY` / `S3_SECRET_KEY` | `minioadmin` / `minioadmin` | MinIO **dan** kredensial S3 aplikasi | Kredensial bawaan MinIO yang sudah publik; backup bisa dibaca/ditimpa |
| `SECRET_KEY` | `ganti-dengan-string-acak-yang-kuat` | session Flask | Pemalsuan session bila nilainya diketahui |
| `TELEGRAM_BOT_TOKEN` / `LLM_API_KEY` / `WAZUH_*_API_PASSWORD` | kosong | layanan eksternal | Tidak berbahaya bila kosong; jangan pakai nilai contoh |

Aturan praktis:

1. **`admin/admin` → ganti password kuat**, lalu **samakan** dengan password di `MONGO_URI`. Keduanya harus identik — bila tidak, aplikasi gagal konek (gejala: `MongoDB tidak tersedia` / login 503).
2. **`minioadmin/minioadmin` → ganti**, karena pada profile `local-minio` kedua nilai itu juga menjadi kredensial root MinIO.
3. `SECRET_KEY` → generate:
   ```powershell
   python -c "import secrets; print(secrets.token_urlsafe(48))"
   ```
4. Bila memakai Mongo/MinIO **eksternal**, kredensial default di atas tidak dipakai — tetapi tetap pastikan akun yang dipakai aplikasi bukan akun default milik server tersebut.

Contoh mengganti dengan aman (jangan menyalin nilai ini):

```dotenv
MONGO_ROOT_USER=laras_app
MONGO_ROOT_PASSWORD=<password-kuat-hasil-generate>
MONGO_URI=mongodb://laras_app:<password-kuat-hasil-generate>@mongo:27017/?authSource=admin
S3_ACCESS_KEY=<key-baru>
S3_SECRET_KEY=<secret-baru>
```

#### 4.1.4 Langkah deploy

**1. Siapkan `.env`**

```powershell
copy .env.docker.example .env
```

Yang **wajib** diubah: `SECRET_KEY`, `WAZUH_DEV_API_URL`/`WAZUH_PROD_API_URL`, kredensial Mongo/MinIO (lihat 4.1.3), dan `TZ`.

> **Jebakan hostname.** Di dalam container, `localhost` berarti container itu sendiri.
> - Wazuh di host yang sama → `host.docker.internal`
> - **MongoDB yang berjalan di host** → `mongodb://host.docker.internal:27017/`
> - Mongo/MinIO sebagai container → nama service (`mongo`, `minio`)
> - Eksternal → hostname yang bisa di-resolve dari container
>
> `MONGO_DB_NAME` harus **sama** dengan DB yang sudah berisi data Anda. Bila berbeda, aplikasi tampak kosong (DB baru dibuat, data lama tidak terlihat).

**2. Buat sertifikat TLS self-signed**

```powershell
# Windows (PowerShell)
powershell -ExecutionPolicy Bypass -File deploy\generate-selfsigned.ps1
```

```bash
# Linux / macOS / Git Bash
sh deploy/generate-selfsigned.sh
```

Menghasilkan `deploy/certs/cert.pem` + `deploy/certs/key.pem`, dengan SAN `localhost` + seluruh IP lokal. Script menulis ke file sementara, **memverifikasi key dan cert berpasangan**, lalu mempublikasikan secara atomik — bila gagal, tidak ada file yang ditinggalkan.

Bila IP LAN berubah, regenerasi lalu `docker compose up -d --force-recreate app`.

> **Tanpa sertifikat, container `app` GAGAL START (fail closed).** karena `SESSION_COOKIE_SECURE=true`.

**3. Jalankan stack**

```powershell
docker compose --profile local-mongo --profile local-minio up -d --build   # semua internal
docker compose up -d --build                                              # Mongo/MinIO eksternal
docker compose --profile local-mongo up -d --build                        # campuran
```

**4. Bootstrap data (one-shot, manual)**

```powershell
# Migrasi (Phase C: field sync_state dev/prod)
docker compose --profile local-mongo run --rm app python migrate.py

# Buat akun admin (meminta password secara interaktif)
docker compose --profile local-mongo run --rm app flask --app app:create_app create-user admin

# Tandai admin sebagai reviewer (agar gate 4-eyes bisa diuji)
docker compose --profile local-mongo run --rm app flask --app app:create_app set-reviewer admin
```

Hilangkan `--profile local-mongo` bila memakai Mongo eksternal.

> `create-user` meminta password lewat prompt interaktif (`click.password_option`) sehingga password tidak masuk shell history. **Jalankan langsung di terminal**, jangan lewat pipeline.

**5. Akses aplikasi**

```
https://localhost:5000
```

Browser akan memperingatkan sertifikat self-signed — klik **Advanced → Proceed**. Peringatan ini normal dan hanya hilang bila `cert.pem` diimpor ke trust store klien (langkah manual per mesin).

#### 4.1.5 Verifikasi pasca-deploy

Jangan tandai deploy selesai sebelum semua lulus.

```powershell
docker compose ps
```

| # | Cek | Kriteria lulus |
|---|-----|----------------|
| 1 | `app` | `Up ... (healthy)` |
| 2 | `scheduler` | `Up` **tanpa** `(healthy)` — normal, lihat catatan di bawah |
| 3 | `mongo` | `Up ... (healthy)` — bila profile aktif |
| 4 | HTTPS melayani | `docker exec laras-app-1 python -c "import ssl,urllib.request; print(urllib.request.urlopen('https://127.0.0.1:5000/auth/login', context=ssl._create_unverified_context()).status)"` → `200` |
| 5 | Login berhasil | Login di browser, lalu **refresh** — sesi harus bertahan |
| 6 | Mongo terhubung | `docker compose exec app python -c "from database import get_db; db=get_db(); print('collections:', sorted(db.list_collection_names()))"` |
| 7 | Sesi server-side | `docker compose exec app python -c "from database import get_db; db=get_db(); print('sessions:', db['sessions'].count_documents({}), 'index:', db['session_index'].count_documents({}))"` |
| 8 | Wazuh API | Tidak ada log `[WazuhAPI] Konfigurasi ... belum lengkap` |
| 9 | Zona waktu | Log scheduler memakai offset `+07:00` (WIB), bukan `+00:00` |


Cek aktivitas cron (bila job diaktifkan): `docker compose logs -f scheduler` — cari `[Scheduler] ... dijadwalkan: <cron>`, lalu `Running job ...` dan `... executed successfully`.

#### 4.1.6 Mode tanpa TLS (HANYA debugging lokal)

Default: `app` menolak start tanpa sertifikat. Untuk debugging lokal tanpa membuat sertifikat, ada escape hatch eksplisit. **Jangan dipakai di produksi** (trafik plaintext).

```dotenv
ALLOW_INSECURE_HTTP=true
# WAJIB berpasangan: cookie Secure di atas HTTP membuat login tidak tersimpan.
SESSION_COOKIE_SECURE=false
```

Lalu `docker compose up -d --force-recreate app`, akses `http://localhost:5000`.

Entrypoint **menolak start** bila `ALLOW_INSECURE_HTTP=true` tetapi `SESSION_COOKIE_SECURE` masih `true` — mencegah kombinasi kontradiktif yang gejalanya ("login tidak menempel") sulit didiagnosis. Pada mode ini healthcheck otomatis memeriksa HTTP, bukan HTTPS.

Kembali ke mode normal: `ALLOW_INSECURE_HTTP=false` (atau hapus), `SESSION_COOKIE_SECURE=true`, lalu `--force-recreate app`.

### 4.2 Jalur manual (tanpa Docker)

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
| Flask-APScheduler | 1.13.1 | Integrasi scheduler dengan Flask (mode embedded) |
| gunicorn | 22.0.0 | WSGI server produksi + terminasi TLS (self-signed) di container `app` |
| boto3 | 1.34.151 | Klien S3/MinIO (backup) |

---

## 5. Konfigurasi (.env)

Dua template tersedia:

| Template | Untuk | Perintah |
|----------|-------|----------|
| `.env.docker.example` | Deployment Docker | `copy .env.docker.example .env` |
| `.env.example` | Menjalankan di host (manual/dev) | `copy .env.example .env` |

Perbedaan penting: pada container, `localhost` di `MONGO_URI`/`S3_ENDPOINT_URL`/`WAZUH_*_API_URL` menunjuk container itu sendiri. Lihat [4.1.4](#414-langkah-deploy).

### 5.1 Variabel Flask & Session

| Variabel | Default | Keterangan |
|----------|---------|------------|
| `SECRET_KEY` | `dev-secret-key-...` | Kunci session Flask. **Wajib diganti** di produksi. |
| `DEBUG` | `False` | Mode debug Flask. Di container **dipaksa `false`** oleh compose. |
| `SESSION_LIFETIME_SECONDS` | `28800` (8 jam) | Umur session, cover satu shift SOC. |
| `SESSION_MONGODB_DB` | `MONGO_DB_NAME` | Nama DB tempat session disimpan. |
| `SESSION_COOKIE_SECURE` | `False` | Set `True` bila app disajikan via HTTPS (compose memaksa `true` kecuali mode insecure). |

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
| `MONGO_URI` | `mongodb://localhost:27017/` | URI koneksi (dukung auth: `mongodb://user:pass@host:27017/`). |
| `MONGO_DB_NAME` | `wazuh_rule_management` | Nama database. Harus cocok dengan DB berisi data Anda. |
| `MONGO_ROOT_USER` / `MONGO_ROOT_PASSWORD` | `admin` / `admin` *(template Docker)* | Kredensial container Mongo. **Ganti** — lihat [4.1.3](#413-kredensial-default--wajib-diganti). |
| `MONGO_PORT` | `27017` | Port host untuk container Mongo (di-bind `127.0.0.1`). |

> Jika MongoDB tidak tersedia, app tetap start, tetapi login dan seluruh fitur berbasis data mengembalikan error 503.

### 5.4 Backup (S3/MinIO)

| Variabel | Default | Keterangan |
|----------|---------|------------|
| `BACKUP_ENABLED` | `False` | Aktifkan scheduler backup otomatis. |
| `S3_ENDPOINT_URL` | – | Endpoint S3/MinIO, mis. `http://localhost:9000` (host) / `http://minio:9000` (container). |
| `S3_ACCESS_KEY` / `S3_SECRET_KEY` | – | Kredensial S3. **Ganti default `minioadmin`.** |
| `S3_BUCKET` | `laras-backups` | Bucket tujuan (dibuat otomatis bila belum ada). |
| `S3_REGION` | *(kosong)* | Region S3 (boleh kosong untuk MinIO). |
| `S3_PREFIX` | `backups` | Prefix key objek. |
| `BACKUP_CRON` | `0 2 * * *` | Jadwal backup (cron **5-field**), dievaluasi pada zona `TZ`. |
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
| `SCHEDULER_ENABLED` | `True` | Di deployment multi-worker, set `False` di semua worker kecuali satu. Di container, **dipaksa** `false` (app) / `true` (scheduler). |
| `TZ` | *(container: `Asia/Jakarta`)* | Zona waktu container; semua cron dievaluasi di zona ini. |

> **Catatan cron:** APScheduler `CronTrigger.from_crontab()` hanya menerima **5 field** (`menit jam hari bulan hari_minggu`). Nilai 6-field membuat job tidak pernah dijadwalkan.

---

## 6. Menjalankan Aplikasi

Bagian ini untuk **jalur manual** (tanpa Docker). Untuk Docker lihat [4.1](#41-jalur-docker-direkomendasikan).

### 6.1 Development

```bash
python app.py
```

Berjalan di **http://localhost:5000** (host `0.0.0.0`, port `5000`).

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

Tidak ada halaman registrasi mandiri. Akun dibuat lewat CLI.

**Di host:**

```bash
flask --app app:create_app create-user <username>          # meminta password interaktif
flask --app app:create_app set-reviewer <username>         # beri status reviewer
flask --app app:create_app set-reviewer <username> --unset # cabut status reviewer
```

**Di container:**

```powershell
docker compose --profile local-mongo run --rm app flask --app app:create_app create-user <username>
docker compose --profile local-mongo run --rm app flask --app app:create_app set-reviewer <username>
docker compose --profile local-mongo run --rm app flask --app app:create_app set-reviewer <username> --unset
```

Login di `/auth/login`.

> Gate 4-eyes menegakkan dua hal saat approve: approver harus `is_reviewer=True`, **dan** `approved_by != proposed_by`. Untuk menguji alur ini, buat minimal **dua** akun dan jadikan keduanya reviewer.

---

## 8. Halaman UI

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

## 9. API Endpoint

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

## 10. Backup, Scheduler & Notifikasi

- **Backup** mengekspor koleksi terpilih ke JSON gzip dan mengunggahnya ke S3/MinIO (via `boto3`). Tersedia on-demand (`POST /api/backup`) dan terjadwal (`BACKUP_CRON`). Backup menulis ke S3/MinIO, **bukan** ke disk container (container `app` read-only).
- **Restore** bersifat destruktif: koleksi terpilih di-drop lalu di-insert ulang dari isi backup, dengan konfirmasi ganda di UI. Restore menolak jalan bila `BACKUP_ENABLED=false`.
- **Scheduler** (APScheduler) menjalankan tiga job independen, masing-masing punya flag sendiri:
  1. Backup otomatis — `BACKUP_ENABLED`
  2. Sync katalog KEV — `KEV_SYNC_ENABLED`
  3. Usulan rule AI — `AI_PROPOSAL_ENABLED`
  Scheduler hanya start jika minimal satu job aktif.
- **Notifikasi** memakai Telegram (abstraction `BaseNotifier`); jika token kosong, notifikasi menjadi no-op. Event yang dinotifikasi antara lain: promotion diajukan/disetujui/ditolak, push ke Dev gagal, dan restart Dev/Prod.

### Backup & restore di Docker

```powershell
# Backup manual
docker compose exec app python -c "from database import get_db; from services.backup_utils import create_backup; print(create_backup(get_db(), 'manual'))"

# Daftar backup
docker compose exec app python -c "from services.backup_utils import list_backups; [print(b) for b in list_backups()]"
```

> **Kegagalan S3.** `create_backup` mengembalikan dict `{'success': False, ...}` untuk kasus yang ditangani (mis. `BACKUP_ENABLED=false`, kredensial kosong). Namun bila endpoint S3/MinIO **tidak bisa dijangkau**, botocore melempar `EndpointConnectionError` yang **tidak ditangkap** — perintah akan menampilkan traceback, bukan dict. Ini **bukan** berarti backup jalan: pastikan container MinIO hidup (`docker compose ps minio`) atau endpoint eksternal benar, dan `S3_ENDPOINT_URL` memakai `minio:9000` (nama service), bukan `localhost:9000`. Job terjadwal punya gejala sama.

**Uji restore (wajib sebelum go-live).** `restore_backup` **DESTRUKTIF** — koleksi terpilih di-drop lalu di-insert ulang. Karena itu:

- **Jangan pernah** menguji restore ke database produksi.
- Syarat: `BACKUP_ENABLED=true`.
- Uji ke **MongoDB terpisah**:

```powershell
docker compose exec -e MONGO_URI="mongodb://<user>:<pass>@<host-uji>:27017/?authSource=admin" app \
  python -c "from services.backup_utils import restore_backup; print(restore_backup('<s3_key>'))"
```

Backup yang belum pernah diuji restore belum bisa disebut backup.

---

## 11. Threat Intelligence (KEV) & AI Rule Proposal

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

## 12. Struktur Proyek

```
laras/
├── app.py                  # Factory create_app(), registrasi blueprint, CLI, scheduler embedded
├── config.py               # Kelas Config (baca .env)
├── database.py             # Koneksi MongoDB, index, collection helper, migrasi sync_state
├── migrate.py              # Skrip migrasi Phase C (single-manager → Dev/Prod)
├── scheduler_runner.py     # Entrypoint container cron (BlockingScheduler, tanpa Flask)
├── requirements.txt
├── .env.example            # Template env untuk host/manual
├── .env.docker.example     # Template env untuk Docker
│
├── Dockerfile              # Multi-stage alpine, non-root, healthcheck mode-aware
├── docker-compose.yml      # Service, profile mongo/minio, hardening
├── .dockerignore
├── .gitattributes          # LF untuk .sh/Dockerfile/compose
│
├── deploy/
│   ├── generate-selfsigned.ps1   # Generator sertifikat TLS (Windows)
│   ├── generate-selfsigned.sh    # Generator sertifikat TLS (Linux/macOS)
│   └── certs/                    # cert.pem + key.pem (gitignored)
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
│   ├── jobs.py             # Definisi job terjadwal (dipakai app.py & scheduler_runner.py)
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

## 13. Operasi Docker

### 13.1 Docker Cheatsheet

```powershell
# Lihat log
docker compose logs -f app scheduler
docker compose logs --tail 100 app
docker compose logs --since 1h scheduler

# Restart setelah ubah .env (env_file dibaca saat container DIBUAT, bukan restart)
docker compose up -d --force-recreate app scheduler

# Rebuild setelah perubahan kode
docker compose up -d --build

# Statistik sumber daya
docker stats --no-stream

# Matikan (data Mongo/MinIO TETAP ada — named volume)
docker compose down

# Matikan DAN HAPUS DATA (hati-hati: rules + audit history ikut terhapus)
docker compose down -v
```

### 13.2 Upgrade

**Selalu backup dulu** bila upgrade menyentuh data.

```powershell
# 1. Backup manual (bila BACKUP_ENABLED=true) — atau lewat UI /api/backup
docker compose exec app python -c "from database import get_db; from services.backup_utils import create_backup; print(create_backup(get_db(), 'upgrade'))"

# 2. Ambil kode versi baru
git pull

# 3. Build image baru
docker compose build --pull

# 4. Recreate
docker compose up -d app scheduler

# 5. Migrasi bila rilis menyertakan perubahan skema
docker compose --profile local-mongo run --rm app python migrate.py

# 6. Verifikasi (lihat 4.1.5)
docker compose ps
docker compose logs --tail 50 app scheduler
```

Catatan: `env_file` dibaca saat container **dibuat** — perubahan `.env` butuh `--force-recreate`, bukan `restart`. Migrasi **tidak** dijalankan otomatis oleh entrypoint.

### 13.3 Rollback

**Kode:**

```powershell
git log --oneline -10                 # temukan commit terakhir yang baik
git checkout <commit-yang-baik>
docker compose build
docker compose up -d app scheduler
```

**Data:** restore dari backup terakhir yang diketahui baik (lihat 11). **Destruktif** — koleksi terpilih di-drop. Setelah restore, jalankan migrasi ulang bila perlu.

**Yang TIDAK bisa di-rollback:** koleksi audit bersifat **append-only** (`rule_history`, `decoder_history`, `manager_actions` — update/delete melempar `RuntimeError`). Restore adalah satu-satunya jalur mengganti isinya, dan itu mengganti seluruh koleksi. Ini konsekuensi desain yang disengaja untuk integritas audit trail.

### 13.4 Debug di dalam container (root filesystem read-only)

Container `app` dan `scheduler` berjalan `read_only: true` — hanya `/tmp/app` (tmpfs) yang bisa ditulis.

```powershell
# Menjalankan script dari stdin — tidak menulis apa pun ke disk
Get-Content skrip.py -Raw | docker compose exec -T app python -

# Satu perintah pendek
docker compose exec app python -c "print('ok')"

# Menyuntikkan file (mount read-only, bukan copy)
docker compose run --rm -v "${PWD}/skrip.py:/app/skrip.py:ro" app python skrip.py
```

> **`docker cp` ke container ini akan GAGAL** dengan `container rootfs is marked read-only`. Ini disengaja (hardening). Jangan mengubah `read_only: true` hanya demi menyalin file.

### 13.5 Rotasi log

Driver default (`json-file`) tidak berotasi. Untuk deployment jangka panjang, tambahkan ke service `app` dan `scheduler` di `docker-compose.yml`:

```yaml
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "5"
```

### 13.6 Menyalakan/mematikan job

Lewat `.env`, lalu recreate `scheduler`:

```dotenv
BACKUP_ENABLED=true
KEV_SYNC_ENABLED=true
AI_PROPOSAL_ENABLED=false
```

```powershell
docker compose up -d --force-recreate scheduler
```

### 13.7 Referensi perintah

| Tujuan | Perintah |
|--------|----------|
| Build image | `docker compose build --pull` |
| Jalankan (lokal penuh) | `docker compose --profile local-mongo --profile local-minio up -d --build` |
| Jalankan (produksi) | `docker compose up -d --build` |
| Status | `docker compose ps` |
| Log | `docker compose logs -f app scheduler` |
| Migrasi | `docker compose --profile local-mongo run --rm app python migrate.py` |
| Buat user | `docker compose --profile local-mongo run --rm app flask --app app:create_app create-user <user>` |
| Set reviewer | `docker compose --profile local-mongo run --rm app flask --app app:create_app set-reviewer <user>` |
| Backup manual | `docker compose exec app python -c "from database import get_db; from services.backup_utils import create_backup; print(create_backup(get_db(),'manual'))"` |
| Daftar backup | `docker compose exec app python -c "from services.backup_utils import list_backups; [print(b) for b in list_backups()]"` |
| Recreate setelah ubah `.env` | `docker compose up -d --force-recreate app scheduler` |
| Bongkar (data aman) | `docker compose down` |
| Bongkar + hapus data | `docker compose down -v` |

---

## 14. Troubleshooting

### 14.1 Aplikasi umum

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
Terjadi di deployment multi-worker. Set `SCHEDULER_ENABLED=False` di semua worker kecuali satu (di Docker ini sudah dipaksa).

**CSRF token expired**
`WTF_CSRF_TIME_LIMIT` sudah diset `None` agar token valid selama session. Jika masih terjadi, hapus cookie dan login ulang.

### 14.2 Docker

| Gejala | Penyebab & solusi |
|--------|-------------------|
| `app` restart terus, log `FATAL: sertifikat TLS tidak ditemukan` | Cert belum dibuat → jalankan script di 4.1.4, lalu `docker compose up -d --force-recreate app`. Ini fail-closed yang disengaja. |
| `app` `unhealthy` | Cek `docker compose logs app`. Bila TLS aktif, probe HTTPS harus bisa mencapai `/auth/login`. |
| `scheduler` tampil `Up` tanpa `(healthy)` | **Normal.** Tidak melayani HTTP; healthcheck image dinonaktifkan (`healthcheck: disable: true`). |
| Aplikasi login tapi datanya kosong | `MONGO_DB_NAME` tidak cocok dengan DB berisi data Anda (mis. data di `laras_app` tapi `.env` memakai `wazuh_rule_management`). Samakan. |
| `MongoDB tidak tersedia` setelah pakai kredensial sendiri | Password di `MONGO_URI` **berbeda** dari `MONGO_ROOT_PASSWORD`. Keduanya harus identik. |
| `MongoDB tidak tersedia` (hostname) | `localhost` di container = container itu sendiri. Mongo di host → `host.docker.internal:27017`; Mongo container → `mongo:27017`. |
| Container `mongo` tidak ikut jalan | Profile belum aktif. Tambahkan `--profile local-mongo`. |
| Login "tidak menempel" (langsung logout) | `SESSION_COOKIE_SECURE=true` tapi diakses via `http://`. Pakai `https://`, atau (debug saja) `ALLOW_INSECURE_HTTP=true` + `SESSION_COOKIE_SECURE=false`. |
| `FATAL: ALLOW_INSECURE_HTTP=true tapi SESSION_COOKIE_SECURE=true` | Konfigurasi kontradiktif. Set `SESSION_COOKIE_SECURE=false` (lihat 4.1.6). |
| Job cron jalan jam yang salah | `TZ` salah. `BACKUP_CRON=0 2 * * *` = 02:00 di zona `TZ`, bukan UTC. |
| Push ke Wazuh gagal dari container | `localhost` tidak menunjuk host. Pakai `host.docker.internal` atau IP LAN. |
| `docker stop` scheduler lama | Normal bila ada job berjalan: scheduler menunggu job selesai (backup tidak terpotong). Beri `docker stop -t 120`. |
| `docker cp` gagal (`rootfs is marked read-only`) | Disengaja. Pakai pipe stdin atau `-v ...:ro` (lihat 14.4). |
| Build gagal di `lxml` | Wheel musllinux tidak tersedia → sudah diatasi build-stage (toolchain di builder, bukan runtime). |
| Uji login via script dapat `400 Bad Request` (`referrer header is missing`) | **Benar dan disengaja** — CSRF Flask-WTF mewajibkan `Referer`/`Origin` pada POST. Kirim header itu atau gunakan browser. Jangan matikan CSRF hanya agar script berjalan. |

---

## 15. Checklist Go-Live

Untuk deployment produksi, semua harus tercentang:

- [ ] `SECRET_KEY` diganti dari default dan **unik** untuk environment ini
- [ ] **Kredensial default diganti** — `MONGO_ROOT_PASSWORD` bukan `admin`, `S3_ACCESS_KEY`/`S3_SECRET_KEY` bukan `minioadmin` ([4.1.3](#413-kredensial-default--wajib-diganti))
- [ ] `MONGO_URI` memakai password **sama** dengan `MONGO_ROOT_PASSWORD`, dan `MONGO_DB_NAME` cocok dengan DB berisi data Anda
- [ ] `DEBUG` — tidak perlu diubah; compose memaksa `false`. Verifikasi: `docker compose exec app python -c "from config import Config; print(Config.DEBUG)"` → `False`
- [ ] `SESSION_COOKIE_SECURE=true` (akses via HTTPS)
- [ ] Sertifikat TLS dibuat untuk **hostname/IP produksi** (bukan hanya localhost)
- [ ] Mongo & MinIO **eksternal** dengan backup terjadwal sendiri
- [ ] `BACKUP_ENABLED=true`, `BACKUP_CRON` benar (uji zona waktu)
- [ ] **Latihan restore sudah dilakukan** ke DB uji (bagian 11)
- [ ] Minimal dua akun reviewer untuk gate 4-eyes
- [ ] Kredensial Wazuh Dev & Prod valid; `*_VERIFY_CERT` sesuai (self-signed → `false`)
- [ ] `TELEGRAM_BOT_TOKEN`/`TELEGRAM_CHAT_ID` diisi bila notifikasi diinginkan
- [ ] `deploy/certs/` **tidak** masuk git (`git status` bersih dari cert/key)
- [ ] Port Mongo/MinIO hanya di `127.0.0.1`, tidak terekspos
- [ ] Rotasi log dikonfigurasi (14.5)
- [ ] Prosedur upgrade (14.2) dan rollback (14.3) dipahami operator

---

## 16. Catatan Keamanan Container

- Image berjalan sebagai **non-root** (`appuser`, uid 10001), `read_only: true` dengan `tmpfs` untuk `/tmp/app`, dan `no-new-privileges`.
- `.env` tidak pernah masuk image (`.dockerignore`), hanya di-inject saat runtime.
- Port Mongo/MinIO di-bind ke `127.0.0.1` saja — tidak terekspos ke jaringan.
- `app` **fail closed** tanpa sertifikat, dan menolak konfigurasi cookie/TLS yang kontradiktif. Tidak ada jalur "diam-diam turun ke plaintext".
- Healthcheck memeriksa **mode yang benar-benar diharapkan** (HTTPS bila TLS, HTTP bila insecure) sehingga container yang menyajikan plaintext karena cert rusak ditandai `unhealthy`.
- **Kredensial default template (`admin`/`admin`, `minioadmin`/`minioadmin`) bersifat publik** — lihat [4.1.3](#413-kredensial-default--wajib-diganti).
- Sertifikat self-signed **bukan** keamanan produksi. Bila nanti dipasang CA internal atau sertifikat resmi, cukup ganti isi `deploy/certs/` dan restart — kode tidak perlu berubah. `ProxyFix` sudah terpasang bila TLS dipindahkan ke reverse proxy.
