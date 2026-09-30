"""
blueprints/api.py
REST API endpoints: Wazuh auth + MongoDB-backed autocomplete data + Sync Manager.

[Phase C, 24 Agustus 2026] Sekarang dua instance WazuhAPI terpisah --
wazuh_api_dev dan wazuh_api_prod -- BUKAN satu instance seperti sebelum
Dev/Prod ada. Endpoint yang menyentuh Wazuh Manager sekarang perlu tahu
environment mana yang dimaksud:
  - pull/diff/restart: terima parameter `env` ('dev'|'prod'), keduanya
    valid target (operator boleh cek/reload manapun).
  - push (/wazuh/push): SELALU ke Dev, tidak menerima parameter env --
    keputusan eksplisit (24 Agustus 2026): satu-satunya jalur ke Prod
    adalah lewat promote (4-eyes), push manual tidak pernah menyentuh
    Prod sama sekali.
  - promote/approve: SELALU ke Prod (pakai wazuh_api_prod.push_selected)
    -- itu memang satu-satunya tujuan promote.

Routes:
  POST /api/auth              → autentikasi manual (jarang dipakai --
                                  operasi normal self-authenticate lewat
                                  WazuhAPI, lihat wazuh_api.py)
  GET  /api/autocomplete/sids     → list all rule IDs from MongoDB
  GET  /api/autocomplete/groups   → list all unique group tags from MongoDB
  GET  /api/autocomplete/decoders → list all decoder names from MongoDB
  GET  /api/me                → info user login (username, is_reviewer)
  GET  /api/wazuh/files?env=  → per-file sync overview (env wajib)
  GET  /api/wazuh/diff/<file_type>/<filename>?env= → diff lokal vs remote (env wajib)
  POST /api/wazuh/pull        → pull dari Dev/Prod (body: env, filenames)
  POST /api/wazuh/push        → push ke Dev SAJA, tanpa gate
  POST /api/wazuh/restart     → restart Dev/Prod (body: env)
  POST /api/wazuh/promote/request        → ajukan promote ke Prod
  GET  /api/wazuh/promote/requests       → list promotion request
  POST /api/wazuh/promote/<id>/approve   → approve (reviewer only) -> push ke Prod
  POST /api/wazuh/promote/<id>/reject    → reject/batalkan
  GET  /api/tech-stack*                  → inventaris tech stack (Phase E)
  GET  /api/kev/catalog/vendors          → vendor dari katalog KEV (dropdown)
  GET  /api/kev/catalog/products         → product dari katalog KEV (dropdown)
  POST /api/kev/sync                     → sync on-demand katalog KEV (Phase F)
  GET  /api/kev/status                   → status katalog + konfigurasi job
  GET  /api/ai/proposals                 → daftar usulan draft rule AI (Phase F)
  POST /api/ai/proposals/generate        → jalankan pipeline AI on-demand
  POST /api/ai/proposals/<id>/dismiss    → tandai usulan AI sebagai dismissed
"""

from __future__ import annotations

from datetime import datetime, timezone
import re

from bson import ObjectId
from bson.errors import InvalidId
from flask import Blueprint, current_app, jsonify, request
from flask_login import current_user

from database import (
    get_decoders_collection, get_rules_collection, get_manager_actions_collection,
    get_promotion_requests_collection, get_users_collection, get_db,
    get_tech_stack_collection, get_kev_catalog_collection, get_ai_proposals_collection,
)
from config import Config
from services.wazuh_api import WazuhAPI
from services import promotion_utils, backup_utils, tech_stack_utils, kev_utils, ai_utils
from services.notification import notify

api_bp = Blueprint('api', __name__)

# [Phase C] Dua instance terpisah -- lihat docstring modul ini dan
# WazuhAPI's docstring (services/wazuh_api.py) untuk alasan kenapa bukan
# satu instance dengan parameter env di tiap panggilan.
wazuh_api_dev = WazuhAPI(env='dev')
wazuh_api_prod = WazuhAPI(env='prod')


def _wazuh_api_for(env: str) -> WazuhAPI:
    """Pilih instance yang benar berdasarkan string env dari request.
    Melempar ValueError kalau env bukan 'dev'/'prod' -- caller (route)
    menangkap ini dan balikin 400."""
    env = (env or '').lower()
    if env == 'dev':
        return wazuh_api_dev
    if env == 'prod':
        return wazuh_api_prod
    raise ValueError(f"env harus 'dev' atau 'prod', diterima: {env!r}")


# ── Wazuh auth (manual, jarang dipakai) ─────────────────────────────────

@api_bp.route('/auth', methods=['POST'])
def authenticate():
    """
    Autentikasi manual ke Wazuh API dan dapatkan JWT token.

    [Phase C] Perlu body {"env": "dev"|"prod"} -- endpoint ini terutama
    untuk debugging/verifikasi kredensial dari luar (mis. lewat
    Postman), BUKAN dipakai operasi normal aplikasi (semua endpoint lain
    self-authenticate otomatis lewat WazuhAPI, lihat wazuh_api.py).
    """
    payload = request.get_json(silent=True) or {}
    try:
        wazuh_api = _wazuh_api_for(payload.get('env', ''))
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400

    token = wazuh_api.authenticate()
    if token:
        return jsonify({'token': token, 'expires_in': 900})
    return jsonify({'error': f'Autentikasi ke Wazuh {payload.get("env")} gagal -- cek log server.'}), 401


# ── Autocomplete endpoints (tidak terkait Wazuh Manager -- tidak berubah) ─

@api_bp.route('/autocomplete/sids', methods=['GET'])
def autocomplete_sids():
    """
    Return all rule IDs stored in MongoDB for use as autocomplete options
    in the `if_sid` field.

    Response: [ { "id": 100001, "description": "..." }, ... ]
    """
    col = get_rules_collection()
    if col is None:
        return jsonify([])

    q = request.args.get('q', '').strip()
    query: dict = {}
    if q:
        try:
            numeric_q = int(q)
            query = {'rule_id': {'$gte': numeric_q, '$lt': numeric_q + 10 ** (len(q))}}
        except ValueError:
            query = {'description': {'$regex': q, '$options': 'i'}}

    docs = list(
        col.find(query, {'_id': 0, 'rule_id': 1, 'description': 1})
           .sort('rule_id', 1)
           .limit(100)
    )
    return jsonify([{'id': d['rule_id'], 'description': d.get('description', '')} for d in docs])


@api_bp.route('/autocomplete/groups', methods=['GET'])
def autocomplete_groups():
    """
    Return all unique group tag values from the `rules` collection.
    Useful for the `if_group` and `group` fields autocomplete.

    Response: [ "authentication_failed", "syslog", ... ]
    """
    col = get_rules_collection()
    if col is None:
        return jsonify([])

    q = request.args.get('q', '').strip()

    pipeline = [
        {'$unwind': '$groups'},
        {'$group': {'_id': '$groups'}},
        {'$sort': {'_id': 1}},
        {'$limit': 200},
    ]
    if q:
        pipeline.insert(0, {'$match': {'groups': {'$regex': q, '$options': 'i'}}})

    groups = [doc['_id'] for doc in col.aggregate(pipeline) if doc['_id']]
    return jsonify(groups)


@api_bp.route('/autocomplete/decoders', methods=['GET'])
def autocomplete_decoders():
    """
    Return all decoder names stored in MongoDB.
    Useful for the `parent` and `decoded_as` field autocomplete.

    Response: [ "syslog", "nginx", "my_custom_decoder", ... ]
    """
    col = get_decoders_collection()
    if col is None:
        return jsonify([])

    q = request.args.get('q', '').strip()
    query: dict = {}
    if q:
        query = {'name': {'$regex': q, '$options': 'i'}}

    docs = list(
        col.find(query, {'_id': 0, 'name': 1})
           .sort('name', 1)
           .limit(200)
    )
    return jsonify([d['name'] for d in docs])


# ── Current user info ────────────────────────────────────────────────

@api_bp.route('/me', methods=['GET'])
def get_current_user_info():
    """
    Info user yang sedang login — dipakai frontend untuk SEMBUNYIKAN
    kontrol yang perlu role tertentu (tombol Approve promotion request,
    yang cuma valid untuk is_reviewer=True). Ini murni UX/kenyamanan —
    TIDAK menambah lapisan otorisasi baru; guard yang sebenarnya tetap
    di promotion_utils.approve_promotion_request() di server. Kalaupun
    endpoint ini dilewati/dipalsukan, approve tetap ditolak server-side.
    """
    col = get_users_collection()
    is_reviewer = False
    if col is not None:
        user_doc = col.find_one({'username': current_user.username})
        is_reviewer = bool(user_doc.get('is_reviewer')) if user_doc else False
    return jsonify({'username': current_user.username, 'is_reviewer': is_reviewer})


# ── Backup (Phase E) ───────────────────────────────────────────────────

@api_bp.route('/backup', methods=['POST'])
def create_backup_now():
    """
    Backup on-demand: ekspor semua koleksi ke JSON gzip lalu upload ke
    S3/MinIO. Notifikasi dikirim ke Telegram setelah selesai (berhasil
    maupun gagal).
    """
    db = get_db()
    if db is None:
        return jsonify({'success': False, 'error': 'MongoDB tidak tersedia.'}), 503

    result = backup_utils.create_backup(db, triggered_by=_get_username_or_system())
    if result.get('success'):
        notify(
            'Backup on-demand selesai',
            f"ID: {result.get('backup_id')}\n"
            f"Total dokumen: {result.get('total_documents', 0)}\n"
            f"Ukuran: {result.get('size_bytes', 0) // 1024} KB\n"
            f"Dipicu oleh: {_get_username_or_system()}",
            level='success',
        )
        return jsonify(result), 201

    notify(
        'Backup on-demand GAGAL',
        f"Dipicu oleh: {_get_username_or_system()}\n{result.get('error', '')}",
        level='error',
    )
    return jsonify(result), 400


@api_bp.route('/backups', methods=['GET'])
def list_backups():
    """Daftar backup yang tersedia di S3/MinIO, terbaru dulu."""
    backups = backup_utils.list_backups()
    return jsonify(backups)


@api_bp.route('/backup/restore', methods=['POST'])
def restore_backup():
    """
    Restore koleksi dari satu backup di S3/MinIO. DESTRUKTIF: koleksi yang
    dipilih di-drop lalu di-insert ulang dari isi backup. Client wajib
    mengirim konfirmasi eksplisit (panggilan dari UI sudah melewati modal
    konfirmasi ganda). Body: { s3_key: str, collections: [str] | null }.
    collections null = restore semua koleksi yang ada di backup.
    """
    payload = request.get_json(silent=True) or {}
    s3_key = (payload.get('s3_key') or '').strip()
    if not s3_key:
        return jsonify({'success': False, 'error': 'Field "s3_key" wajib diisi.'}), 400

    collections = payload.get('collections')
    if collections is not None and not isinstance(collections, list):
        return jsonify({'success': False, 'error': 'Field "collections" harus berupa daftar nama atau null.'}), 400

    result = backup_utils.restore_backup(s3_key, collections)
    if result.get('success'):
        notify(
            'Restore backup selesai',
            f"Dipicu oleh: {_get_username_or_system()}\n"
            f"Backup: {s3_key}\n" + "\n".join(
                f"- {name}: {info.get('restored', 0)} restored (drop {info.get('dropped', 0)})"
                for name, info in (result.get('summary') or {}).items()
            ),
            level='success',
        )
        return jsonify(result), 200

    notify(
        'Restore backup GAGAL',
        f"Dipicu oleh: {_get_username_or_system()}\n{result.get('error', '')}",
        level='error',
    )
    return jsonify(result), 400


# ── Tech Stack (Phase E: inventaris infrastruktur) ─────────────────────

@api_bp.route('/tech-stack', methods=['GET'])
def list_tech_stack():
    """Daftar semua item tech stack (vendor, product, version, dsb)."""
    col = get_tech_stack_collection()
    if col is None:
        return jsonify({'success': False, 'error': 'MongoDB tidak tersedia.'}), 503
    return jsonify(tech_stack_utils.list_items(col))


@api_bp.route('/tech-stack', methods=['POST'])
def create_tech_stack_item():
    """Tambah item tech stack baru."""
    col = get_tech_stack_collection()
    if col is None:
        return jsonify({'success': False, 'error': 'MongoDB tidak tersedia.'}), 503
    result = tech_stack_utils.create_item(col, request.get_json(silent=True) or {}, _get_username_or_system())
    return jsonify(result), (201 if result.get('success') else 400)


@api_bp.route('/tech-stack/<item_id>', methods=['PUT'])
def update_tech_stack_item(item_id: str):
    """Update satu item tech stack."""
    col = get_tech_stack_collection()
    if col is None:
        return jsonify({'success': False, 'error': 'MongoDB tidak tersedia.'}), 503
    result = tech_stack_utils.update_item(col, item_id, request.get_json(silent=True) or {}, _get_username_or_system())
    return jsonify(result), (200 if result.get('success') else 400)


@api_bp.route('/tech-stack/<item_id>', methods=['DELETE'])
def delete_tech_stack_item(item_id: str):
    """Hapus satu item tech stack."""
    col = get_tech_stack_collection()
    if col is None:
        return jsonify({'success': False, 'error': 'MongoDB tidak tersedia.'}), 503
    result = tech_stack_utils.delete_item(col, item_id)
    return jsonify(result), (200 if result.get('success') else 400)


# ── KEV catalog (Phase F: vendor/product dari feed KEV) ────────────────

def _merge_with_tech_stack(catalog_col, ts_col, field: str, search: str, vendor: str = '') -> list[str]:
    """
    Gabungkan nilai unik dari katalog KEV dengan yang sudah ada di tech_stack.

    Satu implementasi dipakai oleh endpoint vendor DAN product supaya
    semantik search/filter konsisten (sebelumnya dua route menyalin logika
    ini dengan urutan filter yang berbeda). Search di-escape (re.escape) dan
    di-anchor untuk mencegah ReDoS + tetap bisa pakai index.

    field: 'vendor' atau 'product'.
    vendor: hanya relevan untuk field='product' -> filter product milik
            vendor tersebut (case-insensitive).
    """
    search = (search or '').strip()
    regex = {'$regex': '^' + re.escape(search), '$options': 'i'} if search else None

    query: dict = {}
    if regex:
        query[field] = regex
    if field == 'product' and (vendor or '').strip():
        query['vendor'] = {'$regex': '^' + re.escape(vendor.strip()) + '$', '$options': 'i'}

    values = {v for v in catalog_col.distinct(field, query) if v}

    if ts_col is not None:
        ts_query: dict = {}
        if regex:
            ts_query[field] = regex
        if field == 'product' and (vendor or '').strip():
            ts_query['vendor'] = {'$regex': '^' + re.escape(vendor.strip()) + '$', '$options': 'i'}
        values.update(v for v in ts_col.distinct(field, ts_query) if v)

    return sorted(values)


@api_bp.route('/kev/catalog/vendors', methods=['GET'])
def list_kev_vendors():
    """Vendor unik dari katalog KEV (+ vendor yang sudah dipakai di tech_stack).
    Dipakai sebagai sumber dropdown vendor di form Tech Stack."""
    col = get_kev_catalog_collection()
    if col is None:
        return jsonify({'success': False, 'error': 'MongoDB tidak tersedia.'}), 503
    search = (request.args.get('q') or '').strip()
    vendors = _merge_with_tech_stack(col, get_tech_stack_collection(), 'vendor', search)
    return jsonify({'success': True, 'vendors': vendors})


@api_bp.route('/kev/catalog/products', methods=['GET'])
def list_kev_products():
    """Product unik dari katalog KEV, opsional difilter per vendor."""
    col = get_kev_catalog_collection()
    if col is None:
        return jsonify({'success': False, 'error': 'MongoDB tidak tersedia.'}), 503
    vendor = (request.args.get('vendor') or '').strip()
    search = (request.args.get('q') or '').strip()
    products = _merge_with_tech_stack(col, get_tech_stack_collection(), 'product', search, vendor)
    return jsonify({'success': True, 'products': products})


@api_bp.route('/kev/sync', methods=['POST'])
def sync_kev_catalog():
    """Sync on-demand katalog vendor/product dari feed KEV (opsi manual di
    samping job terjadwal). Hanya menyisipkan pasangan yang belum ada."""
    catalog_col = get_kev_catalog_collection()
    if catalog_col is None:
        return jsonify({'success': False, 'error': 'MongoDB tidak tersedia.'}), 503

    result = kev_utils.sync_vendor_catalog(catalog_col, get_tech_stack_collection())
    if result.get('success'):
        notify(
            'Sync katalog KEV (manual)',
            f"Dipicu oleh: {_get_username_or_system()}\n"
            f"{result.get('inserted', 0)} pasangan baru dari "
            f"{result.get('total_pairs', 0)} total.",
            level='success',
        )
        return jsonify(result), 200

    notify(
        'Sync katalog KEV (manual) GAGAL',
        f"Dipicu oleh: {_get_username_or_system()}\n{result.get('error', '')}",
        level='error',
    )
    return jsonify(result), 502


@api_bp.route('/kev/status', methods=['GET'])
def kev_status():
    """Status ringkas katalog KEV + konfigurasi job (untuk UI)."""
    col = get_kev_catalog_collection()
    if col is None:
        return jsonify({'success': False, 'error': 'MongoDB tidak tersedia.'}), 503
    total = col.count_documents({})
    vendors = len(kev_utils.list_vendors(col))
    return jsonify({
        'success': True,
        'configured': bool((Config.KEV_ADVISORIES_URL or '').strip()),
        'sync_enabled': Config.KEV_SYNC_ENABLED,
        'sync_cron': Config.KEV_SYNC_CRON,
        'total_pairs': total,
        'total_vendors': vendors,
    })


# ── AI proposals (Phase F, Opsi C) ─────────────────────────────────────

def _serialize_proposal(doc: dict) -> dict:
    doc = dict(doc)
    if doc.get('_id') is not None:
        doc['_id'] = str(doc['_id'])
    doc['tech_stack_ids'] = [str(i) for i in (doc.get('tech_stack_ids') or [])]
    created = doc.get('created_at')
    if created is not None and hasattr(created, 'isoformat'):
        doc['created_at'] = created.isoformat()
    return doc


@api_bp.route('/ai/proposals', methods=['GET'])
def list_ai_proposals():
    """Daftar usulan draft rule dari AI. Filter opsional ?status=pending."""
    col = get_ai_proposals_collection()
    if col is None:
        return jsonify({'success': False, 'error': 'MongoDB tidak tersedia.'}), 503
    status = (request.args.get('status') or '').strip()
    query = {'status': status} if status else {}
    docs = col.find(query).sort('created_at', -1).limit(200)
    return jsonify({'success': True, 'items': [_serialize_proposal(d) for d in docs]})


@api_bp.route('/ai/proposals/generate', methods=['POST'])
def generate_ai_proposals():
    """
    Jalankan pipeline AI on-demand (satu run, sinkron) untuk uji coba.
    Sama dengan job terjadwal: hanya advisory KEV yang relevan dengan
    tech_stack, hasilnya tersimpan sebagai usulan pending (TIDAK disimpan
    sebagai rule).
    """
    db = get_db()
    if db is None:
        return jsonify({'success': False, 'error': 'MongoDB tidak tersedia.'}), 503
    if not (Config.LLM_API_KEY or '').strip():
        return jsonify({'success': False, 'error': 'LLM_API_KEY belum dikonfigurasi di .env.'}), 400

    payload = request.get_json(silent=True) or {}
    try:
        max_items = int(payload.get('max_items') or 5)
    except (TypeError, ValueError):
        max_items = 5
    max_items = max(1, min(max_items, 20))

    result = ai_utils.run_proposal_job(db, max_items=max_items)
    status = 200 if result.get('success') else 502
    return jsonify(result), status


@api_bp.route('/ai/proposals/<proposal_id>/dismiss', methods=['POST'])
def dismiss_ai_proposal(proposal_id: str):
    """Tandai usulan sebagai dismissed (tidak dihapus -- jejak audit tetap)."""
    col = get_ai_proposals_collection()
    if col is None:
        return jsonify({'success': False, 'error': 'MongoDB tidak tersedia.'}), 503
    try:
        oid = ObjectId(proposal_id)
    except (InvalidId, TypeError):
        return jsonify({'success': False, 'error': 'ID tidak valid.'}), 400

    result = col.update_one(
        {'_id': oid},
        {'$set': {
            'status': 'dismissed',
            'dismissed_at': datetime.now(timezone.utc),
            'dismissed_by': _get_username_or_system(),
        }},
    )
    if result.matched_count == 0:
        return jsonify({'success': False, 'error': 'Usulan tidak ditemukan.'}), 404
    return jsonify({'success': True})


# ── Wazuh Sync & Manager ────────────────────────────────────────────────

def _filenames_arg(payload: dict, key: str):
    """
    Extract a filename-list argument from the request body.
    Key absent from payload entirely -> None (means "all files of this type").
    Key present (even as []) -> that explicit list.
    """
    if key not in payload:
        return None
    val = payload.get(key)
    return val if isinstance(val, list) else []


def _log_manager_action(action: str, success: bool, detail: str | None = None, env: str | None = None) -> None:
    """
    Append-only audit trail for actions against the live Wazuh Manager
    that don't go through rule/decoder versioning (services/history_utils.py)
    because they don't touch rule/decoder *content* — restart being the
    obvious one, and the most operationally sensitive action in this app
    (it affects a SIEM's availability — Dev atau Prod tergantung `env`).
    Never raises: a logging failure must not block or mask the actual
    restart outcome.
    """
    col = get_manager_actions_collection()
    if col is None:
        return
    try:
        username = current_user.username if current_user and current_user.is_authenticated else 'system'
    except RuntimeError:
        username = 'system'
    try:
        col.insert_one({
            'action': action,
            'env': env,
            'success': success,
            'detail': detail,
            'triggered_by': username,
            'triggered_at': datetime.now(timezone.utc),
        })
    except Exception:
        current_app.logger.exception('Gagal mencatat manager_actions untuk action=%s env=%s', action, env)


@api_bp.route('/wazuh/files', methods=['GET'])
def wazuh_sync_overview():
    """Per-file sync overview combining Wazuh Manager + MongoDB, untuk UI pilih pull/push.
    Query param WAJIB: ?env=dev atau ?env=prod."""
    try:
        wazuh_api = _wazuh_api_for(request.args.get('env', ''))
    except ValueError as exc:
        return jsonify({'success': False, 'message': str(exc)}), 400
    try:
        return jsonify(wazuh_api.get_sync_overview()), 200
    except Exception as e:
        current_app.logger.error(f"Error mengambil sync overview: {str(e)}")
        return jsonify({'success': False, 'message': f'Gagal mengambil daftar file: {str(e)}'}), 500


@api_bp.route('/wazuh/diff/<file_type>/<path:filename>', methods=['GET'])
def wazuh_file_diff(file_type: str, filename: str):
    """Side-by-side XML diff: MongoDB (rebuilt) vs file di Wazuh Manager.
    Query param WAJIB: ?env=dev atau ?env=prod -- diff dibandingkan ke
    environment yang mana."""
    try:
        wazuh_api = _wazuh_api_for(request.args.get('env', ''))
    except ValueError as exc:
        return jsonify({'success': False, 'message': str(exc)}), 400
    try:
        result = wazuh_api.get_file_diff(file_type, filename)
        status = 200 if result.get('success') else 400
        return jsonify(result), status
    except Exception as e:
        current_app.logger.error(f"Error membangun diff: {str(e)}")
        return jsonify({'success': False, 'message': f'Gagal membangun diff: {str(e)}'}), 500


@api_bp.route('/wazuh/pull', methods=['POST'])
def pull_from_wazuh():
    """
    Pull rules/decoders dari Wazuh Manager (Dev ATAU Prod) ke MongoDB.

    Body: { "env": "dev"|"prod" (WAJIB), "rule_filenames": [...], "decoder_filenames": [...] }
    Key filename yang tidak dikirim = ambil semua file jenis tersebut.
    Key dikirim sebagai [] = jangan ambil jenis tersebut sama sekali.

    Pull dari Prod TIDAK digate -- ini cuma membaca state Prod ke Mongo
    untuk deteksi drift/perbandingan, tidak mengubah apapun di server.
    """
    payload = request.get_json(silent=True) or {}
    try:
        wazuh_api = _wazuh_api_for(payload.get('env', ''))
    except ValueError as exc:
        return jsonify({'success': False, 'message': str(exc)}), 400

    try:
        result = wazuh_api.pull_selected(
            rule_filenames=_filenames_arg(payload, 'rule_filenames'),
            decoder_filenames=_filenames_arg(payload, 'decoder_filenames'),
        )
        return jsonify(result), 200
    except Exception as e:
        current_app.logger.error(f"Error pada pull Wazuh: {str(e)}")
        return jsonify({'success': False, 'message': f'Gagal melakukan pull data: {str(e)}'}), 500


@api_bp.route('/wazuh/push', methods=['POST'])
def push_to_wazuh():
    """
    Push rules/decoders lokal dari MongoDB ke Wazuh Manager Dev.

    [Phase C, 24 Agustus 2026] SELALU ke Dev -- endpoint ini TIDAK
    menerima parameter env dan TIDAK bisa push ke Prod. Ini keputusan
    eksplisit (24 Agustus 2026): satu-satunya jalur ke Prod adalah lewat
    /wazuh/promote/request -> /approve (4-eyes) -- lihat
    services/promotion_utils.py. Endpoint ini sebelumnya (Phase B)
    dikunci total karena manager tunggal yang ada saat itu berfungsi
    sebagai Prod; sekarang Dev sudah ada sebagai target terpisah yang
    ungated, endpoint ini dibuka lagi UNTUK DEV SAJA.

    Body (opsional): { "rule_filenames": [...], "decoder_filenames": [...], "force": false }
    force=true tetap push meski ada dokumen berstatus conflict (di Dev)
    — gunakan hanya setelah user meninjau diff.
    """
    payload = request.get_json(silent=True) or {}
    try:
        result = wazuh_api_dev.push_selected(
            rule_filenames=_filenames_arg(payload, 'rule_filenames'),
            decoder_filenames=_filenames_arg(payload, 'decoder_filenames'),
            force=bool(payload.get('force', False)),
        )
        if not result.get('success') or result.get('errors'):
            notify(
                'Push ke Dev GAGAL',
                f"Oleh: {_get_username_or_system()}\n"
                f"Message: {result.get('message', '')}\n"
                f"Errors: {result.get('errors', [])}",
                level='error',
            )
        return jsonify(result), 200
    except Exception as e:
        current_app.logger.error(f"Error pada push ke Dev: {str(e)}")
        notify(
            'Push ke Dev ERROR',
            f"Oleh: {_get_username_or_system()}\n{str(e)}",
            level='error',
        )
        return jsonify({'success': False, 'message': f'Gagal melakukan push data ke Dev: {str(e)}'}), 500


@api_bp.route('/wazuh/restart', methods=['POST'])
def restart_wazuh():
    """
    Kirim perintah restart service ke Wazuh Manager (Dev ATAU Prod).

    Body: { "env": "dev"|"prod" (WAJIB) }

    TIDAK digate -- baik restart Dev maupun Prod bebas dipicu siapa saja
    yang login (keputusan 22 Agustus 2026: reload cuma mengaktifkan
    konten yang sudah lolos gate di titik push/promote sebelumnya, gate
    kedua di sini redundant). Tetap dicatat ke `manager_actions`
    (_log_manager_action) terlepas dari berhasil/gagal, dengan `env`
    disertakan supaya audit trail tahu server mana yang di-restart.
    """
    payload = request.get_json(silent=True) or {}
    env = (payload.get('env') or '').lower()
    try:
        wazuh_api = _wazuh_api_for(env)
    except ValueError as exc:
        return jsonify({'success': False, 'message': str(exc)}), 400

    try:
        result = wazuh_api.restart_manager()
        if result.get('success'):
            _log_manager_action('restart', success=True, env=env)
            notify(
                'Restart Wazuh Manager',
                f"Environment: {env.upper()}\nDipicu oleh: {_get_username_or_system()}\nBerhasil dikirim.",
                level='success',
            )
            return jsonify({'success': True, 'data': result.get('data'), 'message': f'Perintah restart Wazuh Manager {env.upper()} berhasil dikirim.'}), 200
        _log_manager_action('restart', success=False, detail=result.get('error'), env=env)
        notify(
            'Restart Wazuh Manager GAGAL',
            f"Environment: {env.upper()}\nDipicu oleh: {_get_username_or_system()}\n{result.get('error') or 'Error tidak diketahui'}",
            level='error',
        )
        return jsonify({'success': False, 'message': result.get('error') or f'Gagal merestart Wazuh Manager {env.upper()}.'}), 502
    except Exception as e:
        current_app.logger.error(f"Error pada restart Wazuh {env}: {str(e)}")
        _log_manager_action('restart', success=False, detail=str(e), env=env)
        notify(
            'Restart Wazuh Manager ERROR',
            f"Environment: {env.upper()}\nDipicu oleh: {_get_username_or_system()}\n{str(e)}",
            level='error',
        )
        return jsonify({'success': False, 'message': f'Gagal merestart Wazuh Manager {env.upper()}: {str(e)}'}), 500


# ── Promotion (4-eyes approval, SELALU menuju Prod) ─────────────────────

def _get_username_or_system() -> str:
    """Sama seperti pola _current_username() di wazuh_api.py — fallback
    'system' seharusnya tidak pernah muncul dalam pemakaian normal
    karena blueprint ini sudah di-gate login, tapi jaga-jaga saja."""
    try:
        return current_user.username if current_user and current_user.is_authenticated else 'system'
    except RuntimeError:
        return 'system'


def _serialize_promotion(req: dict) -> dict:
    """ObjectId tidak bisa langsung di-jsonify — konversi ke string."""
    req = dict(req)
    req['_id'] = str(req['_id'])
    return req


@api_bp.route('/wazuh/promote/request', methods=['POST'])
def request_promotion():
    """
    Ajukan promotion request untuk sekumpulan file rule/decoder -- SELALU
    menuju Prod (tidak ada parameter env, promote cuma satu arah).

    Body (opsional): { "rule_filenames": [...], "decoder_filenames": [...], "force": false }
    Semantik None/[]/[...] sama seperti /wazuh/push.
    Ditolak (400) kalau ada file yang belum pernah synced ke Dev, atau
    (tanpa force) ada file berstatus conflict di Prod.
    """
    payload = request.get_json(silent=True) or {}
    result = promotion_utils.create_promotion_request(
        get_promotion_requests_collection(),
        get_rules_collection(),
        get_decoders_collection(),
        _filenames_arg(payload, 'rule_filenames'),
        _filenames_arg(payload, 'decoder_filenames'),
        _get_username_or_system(),
        force=bool(payload.get('force', False)),
    )
    if result.get('success'):
        result['request'] = _serialize_promotion(result['request'])
        return jsonify(result), 201
    return jsonify(result), 400


@api_bp.route('/wazuh/promote/requests', methods=['GET'])
def list_promotions():
    """
    List promotion request. Query param opsional ?status=pending
    (atau approved/rejected) untuk filter.
    """
    status_filter = request.args.get('status')
    reqs = promotion_utils.list_promotion_requests(get_promotion_requests_collection(), status_filter)
    return jsonify([_serialize_promotion(r) for r in reqs])


@api_bp.route('/wazuh/promote/<request_id>/approve', methods=['POST'])
def approve_promotion(request_id: str):
    """
    Approve promotion request dan LANGSUNG jalankan push ke Wazuh Manager
    PROD (wazuh_api_prod.push_selected). Ditolak (400) kalau approver
    bukan reviewer, approver == proposer (4-eyes), atau request sudah
    tidak pending lagi.
    """
    try:
        oid = ObjectId(request_id)
    except InvalidId:
        return jsonify({'success': False, 'error': 'ID request tidak valid.'}), 400

    result = promotion_utils.approve_promotion_request(
        get_promotion_requests_collection(),
        get_users_collection(),
        wazuh_api_prod.push_selected,
        oid,
        _get_username_or_system(),
    )
    return jsonify(result), (200 if result.get('success') else 400)


@api_bp.route('/wazuh/promote/<request_id>/reject', methods=['POST'])
def reject_promotion(request_id: str):
    """
    Tolak atau batalkan promotion request yang masih pending. Proposer
    boleh membatalkan pengajuannya sendiri; user lain juga boleh reject.
    Tidak mengubah dokumen rule/decoder — hanya mengubah status request.
    """
    try:
        oid = ObjectId(request_id)
    except InvalidId:
        return jsonify({'success': False, 'error': 'ID request tidak valid.'}), 400

    result = promotion_utils.reject_promotion_request(
        get_promotion_requests_collection(), oid, _get_username_or_system()
    )
    return jsonify(result), (200 if result.get('success') else 400)