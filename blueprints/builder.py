"""
blueprints/builder.py
Form views and CRUD handlers for Rules and Decoders.

Routes:
  GET  /builder/             → render index.html
  POST /builder/decoder/xml  → generate XML (no save)
  POST /builder/decoder/save → generate XML + upsert to MongoDB
  POST /builder/rule/xml     → generate XML (no save)
  POST /builder/rule/save    → generate XML + upsert to MongoDB
  GET  /builder/decoder/list → list all decoders from MongoDB
  GET  /builder/rule/list    → list all rules from MongoDB
  DELETE /builder/decoder/<name>  → delete decoder by name
  DELETE /builder/rule/<int:rule_id> → delete rule by id

Phase A audit (22 Agustus 2026): changed_by (last_modified_by) dan
history versioning (Phase 2 & 3) sudah lengkap di semua write path di
file ini sejak sebelum audit ini — tidak ada perubahan pada bagian itu.
Yang ditambahkan audit ini:
  - rollback_rule() & rollback_decoder() sekarang mengimplementasikan
    "Opsi Tengah" (lihat LARAS_ROADMAP.md Phase A) — restore ke draft
    TETAP otomatis membuat promotion request kalau hasil restore-nya
    beda dari server, supaya rollback cepat masuk antrean approval
    tanpa menghapus gate 4-eyes.
  - save_rule(): rule_id non-numerik sekarang balikin 400 yang jelas,
    bukan 500 generik dari ValueError yang tidak ditangkap.
  - save_rule(): `_id` ditambahkan ke reserved-fields strip list,
    konsisten dengan save_decoder() — pencegahan, bukan bug yang
    pernah kejadian.
"""

from __future__ import annotations

from datetime import datetime, timezone
from bson import ObjectId
import json
from flask import Blueprint, jsonify, redirect, render_template, request, url_for
from flask_login import current_user
from pymongo import errors as mongo_errors

from database import (
    get_decoders_collection, get_rules_collection, init_db as db,
    get_rule_history_collection, get_decoder_history_collection,
    get_promotion_requests_collection, get_tech_stack_collection,
)
from services.xml_generator import XMLGenerator
from services.sync_utils import (
    rule_content_hash,
    decoder_content_hash,
    resolve_sync_status,
    resolve_env_sync_status,
    env_sync_status_only,
    env_sync_state_nested,
    get_env_sync_state,
    SYNC_STATUS_SYNCED,
    SYNC_STATUS_NEW,
    SYNC_STATUS_CONFLICT,
)
from services.history_utils import (
    record_rule_version, record_rule_deletion,
    record_decoder_group_version,
    CHANGE_SOURCE_APP_EDIT, CHANGE_SOURCE_DELETED, CHANGE_SOURCE_ROLLBACK,
)
from services.wazuh_compat import scan_rule_doc
from services.wazuh_api import WazuhAPI
from services import promotion_utils
from services.lifecycle_utils import compute_rule_lifecycle_status

builder_bp = Blueprint('builder', __name__)
xml_generator = XMLGenerator()


# ── helpers ───────────────────────────────────────────────────────────

def _serialise(doc: dict) -> dict:
    """Convert MongoDB _id (ObjectId) to string for JSON serialisation."""
    if doc and '_id' in doc:
        doc['_id'] = str(doc['_id'])
    # [Fitur baru, 4 September 2026] tech_stack_ids disimpan sebagai
    # daftar ObjectId (lihat _normalize_tech_stack_ids) — diubah ke string
    # supaya frontend bisa menampilkan/mengirim ulang tanpa masalah JSON.
    if doc and doc.get('tech_stack_ids'):
        doc['tech_stack_ids'] = [str(i) for i in doc['tech_stack_ids']]
    return doc


def _db_unavailable():
    return jsonify({'error': 'MongoDB is not available. Check your MONGO_URI configuration.'}), 503


def _normalize_filename(raw: str) -> str:
    """Trim and ensure a `.xml` extension so 'my_rules' and 'my_rules.xml'
    saved from the wizard don't accidentally become two different files."""
    name = (raw or '').strip()
    if name and not name.lower().endswith('.xml'):
        name += '.xml'
    return name


def _normalize_tech_stack_ids(raw) -> tuple[list | None, dict | None]:
    """
    [Fitur baru, 4 September 2026] Validasi daftar tech_stack_ids dari
    client sebelum disimpan ke dokumen rule.

    Accept:
      - list of ObjectId/string yang valid (masing-masing harus ada di
        collection `tech_stack`)
      - None / list kosong  -> [] (rule tidak terhubung ke stack manapun)
      - string yang bukan ObjectId -> 400 (bukan 500 dari ObjectId() err)

    Return (normalized_list, None) kalau valid, atau (None, error_dict)
    kalau ada ID yang tidak valid/tidak ditemukan. Dipanggil di save_rule()
    -- metadata LARAS, TIDAK masuk RULE_CONTENT_FIELDS (lihat sync_utils.py)
    sehingga tidak mempengaruhi content_hash/XML yang dikirim ke Wazuh.
    """
    if raw is None:
        return [], None
    if not isinstance(raw, list):
        return None, {'error': 'Field "tech_stack_ids" harus berupa daftar ID.'}

    cleaned = []
    ts_col = get_tech_stack_collection()
    for item in raw:
        if isinstance(item, ObjectId):
            oid = item
        else:
            try:
                oid = ObjectId(str(item))
            except Exception:
                return None, {'error': f'Tech stack ID tidak valid: "{item}".'}
        if ts_col is None or ts_col.find_one({'_id': oid}, {'_id': 1}) is None:
            return None, {'error': f'Tech stack item tidak ditemukan: "{item}".'}
        cleaned.append(oid)
    return cleaned, None


def _with_flat_sync_status(doc: dict) -> dict:
    """
    [Phase C, 24 Agustus 2026] Tambah sync_status_dev/sync_status_prod
    yang sudah "diratakan" dari sync_state nested, lalu buang sync_state
    mentah dari response -- frontend list (rule_list.js/decoder_list.js)
    cukup baca dua field flat ini untuk render badge, tidak perlu tahu
    struktur nested sync_state sama sekali. Dipakai di list_rules()/
    list_decoders() sebelum jsonify.
    """
    doc['sync_status_dev'] = get_env_sync_state(doc, 'dev').get('sync_status', SYNC_STATUS_NEW)
    doc['sync_status_prod'] = get_env_sync_state(doc, 'prod').get('sync_status', SYNC_STATUS_NEW)
    doc.pop('sync_state', None)
    return doc


def _with_lifecycle_status(doc: dict) -> dict:
    """
    [Fitur baru, 27 Agustus 2026] Tambah lifecycle_status yang DIHITUNG
    (bukan dibaca dari field tersimpan -- lihat services/lifecycle_utils.py
    untuk kenapa) ke response rule. HARUS dipanggil SEBELUM
    _with_flat_sync_status() membuang `sync_state` mentah dari dict,
    karena compute_rule_lifecycle_status() butuh itu.
    """
    doc['lifecycle_status'] = compute_rule_lifecycle_status(doc)
    return doc


def _auto_promote_after_rollback(filename: str, is_rule: bool, needs_promote: bool) -> dict | None:
    """
    Phase A "Opsi Tengah": setelah rollback me-restore konten ke MongoDB,
    otomatis ajukan promotion request untuk filename yang bersangkutan —
    TAPI hanya kalau hasil restore-nya benar-benar berbeda dari yang
    sedang live di Prod (needs_promote=True). Kalau kebetulan rollback
    menghasilkan konten yang persis sama dengan Prod, tidak ada gunanya
    bikin promotion request kosong untuk reviewer approve.

    [Phase C, 24 Agustus 2026] needs_promote dihitung oleh caller
    terhadap sync_state.prod SECARA SPESIFIK (bukan status flat lagi) --
    promote selalu menuju Prod, jadi "apakah ada yang perlu
    dipromosikan" berarti "apakah beda dari Prod", bukan dari Dev.
    create_promotion_request() sendiri yang akan menolak (dengan pesan
    jelas) kalau ternyata file ini belum pernah synced ke Dev sama
    sekali -- guard itu tidak diduplikasi di sini.

    Gate 4-eyes TETAP berlaku di sini — fungsi ini cuma MENGAJUKAN
    (proposed_by = current_user.username), bukan langsung push. Reviewer
    lain tetap harus approve lewat panel Promotion Requests seperti
    promotion request biasa. force=False selalu dipakai di sini — kalau
    ternyata ada conflict, itu dikembalikan ke response rollback supaya
    user tahu harus mengajukan ulang manual dengan force kalau memang
    mau menimpa conflict tersebut (rollback TIDAK mengasumsikan force
    atas nama user).

    Return None kalau tidak perlu promote (needs_promote=False) atau
    kalau promotion_requests collection tidak tersedia (MongoDB down —
    gagal diam-diam di sini, rollback dokumennya sendiri tetap berhasil;
    caller yang putuskan bagaimana melaporkan ini ke user).
    """
    if not needs_promote:
        return None

    requests_col = get_promotion_requests_collection()
    if requests_col is None:
        return {'success': False, 'error': 'Rollback tersimpan, tapi promotion_requests collection tidak tersedia untuk auto-propose.'}

    result = promotion_utils.create_promotion_request(
        requests_col,
        get_rules_collection(),
        get_decoders_collection(),
        rule_filenames=[filename] if is_rule else [],
        decoder_filenames=[] if is_rule else [filename],
        proposed_by=current_user.username,
        force=False,
    )
    # [FIX 24 Agustus 2026] create_promotion_request() balikin entry mentah
    # dari MongoDB berisi ObjectId di 'request'['_id'] kalau sukses —
    # jsonify() tidak bisa serialisasi ObjectId (beda dari api.py's
    # request_promotion endpoint yang sudah lewat _serialize_promotion()
    # sebelum di-jsonify; jalur rollback ini belum). Tanpa ini, rollback
    # yang berhasil me-restore rule/decoder TETAP gagal dengan 500 gara-
    # gara response JSON-nya sendiri, bukan gara-gara rollback-nya.
    if result.get('success') and result.get('request', {}).get('_id') is not None:
        result['request']['_id'] = str(result['request']['_id'])
    return result


# ── index ─────────────────────────────────────────────────────────────

@builder_bp.route('/')
def index():
    # The old single-page app (templates/index.html + one giant
    # dynamic_forms.js) is being split into separate pages per menu item
    # for easier debugging — see blueprints/pages.py. This route now just
    # sends the person to the new default landing page instead of
    # rendering the old shell. templates/index.html and
    # static/js/dynamic_forms.js are kept around as migration REFERENCE
    # (every new page/JS file's docstring cites exact line numbers in
    # them) until the migration is complete — do not delete either yet.
    return redirect(url_for('pages.decoder_builder_page'))


# ══════════════════════════════════════════════════════════════════════
# DECODER endpoints
# ══════════════════════════════════════════════════════════════════════

@builder_bp.route('/decoder/xml', methods=['POST'])
def generate_decoder_xml():
    """Generate decoder XML without persisting to DB."""
    data = request.get_json() or {}
    try:
        xml = xml_generator.generate_decoder(data)
        return jsonify({'xml': xml})
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400


@builder_bp.route('/decoder/save', methods=['POST'])
def save_decoder():
    """
    Generate decoder XML and persist to MongoDB.

    Wazuh allows multiple decoders sharing the same `name` ("sibling
    decoders" — see xml_parser.parse_decoder_xml), so `name` is no
    longer treated as a unique key here:
      - Editing an existing decoder: client sends `_id` -> that exact
        document is updated in place.
      - Creating a new decoder: client omits `_id` (or sends null/'') ->
        a brand-new document is always inserted, even if a decoder with
        the same `name` already exists. This is intentional.
    """
    col = get_decoders_collection()
    if col is None:
        return _db_unavailable()

    data = request.get_json() or {}
    try:
        xml = xml_generator.generate_decoder(data)
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400

    name = data.get('name', '').strip()
    doc = {k: v for k, v in data.items()}
    doc['name'] = name

    # Free-text note describing WHY this change was made — goes to
    # decoder_history's commit_message, never onto the live document
    # itself (it describes this specific save, not the decoder's content).
    commit_message = (data.get('commit_message') or '').strip() or None

    # Sync-tracking fields are server-managed — never trust them from the
    # client payload, whatever the caller happened to send.
    for reserved in ('origin', 'ruleset_type',
                      'last_synced_hash', 'last_synced_at', 'sync_status',
                      'content_hash', '_id', 'commit_message'):
        doc.pop(reserved, None)

    raw_id = (data.get('_id') or '').strip()
    existing = None
    object_id = None
    if raw_id:
        try:
            object_id = ObjectId(raw_id)
        except Exception:
            return jsonify({'error': f'ID decoder tidak valid: "{raw_id}".'}), 400
        existing = col.find_one({'_id': object_id}, {'filename': 1, 'sync_state': 1, 'content_hash': 1})
        if existing is None:
            return jsonify({'error': f'Decoder dengan ID "{raw_id}" tidak ditemukan.'}), 404

    # `filename` is the canonical field pull/push/diff group by. If the
    # client (e.g. a "save to file" dropdown in the wizard) sent one, use
    # it; otherwise keep whatever was already stored; otherwise fall back
    # to a sensible default for a brand-new app-created decoder.
    incoming_filename = _normalize_filename(data.get('filename', ''))
    doc['filename'] = incoming_filename or (existing.get('filename') if existing else None) or 'local_decoder.xml'

    new_hash = decoder_content_hash(doc)
    doc['content_hash'] = new_hash
    # Phase 2: who last touched this document's content — distinct from
    # sync_status/last_synced_* which track server-sync state, not
    # authorship.
    doc['last_modified_by'] = current_user.username

    if object_id is not None:
        # [Phase C, 24 Agustus 2026] Decoder yang sudah ada -- status
        # PER ENVIRONMENT dihitung ulang relatif ke snapshot terakhir
        # yang synced ke masing-masing env (last_synced_hash TIDAK
        # berubah di sini -- itu cuma berubah saat benar-benar
        # push/promote terjadi, bukan saat save biasa). Dot-path dari
        # env_sync_status_only() AMAN di sini karena lewat $set.
        # `existing` is guaranteed above for an update, but the untyped
        # Mongo collection makes that narrowing invisible to static checkers.
        existing_doc = existing or {}
        doc.update(env_sync_status_only('dev', resolve_env_sync_status(existing_doc, 'dev', new_hash)))
        doc.update(env_sync_status_only('prod', resolve_env_sync_status(existing_doc, 'prod', new_hash)))
        col.update_one({'_id': object_id}, {'$set': doc})
        saved_id = object_id
        upserted = False
    else:
        doc.update({
            'origin': 'app_created',
            'ruleset_type': 'custom',
        })
        # [Phase C] TIDAK perlu set sync_state eksplisit untuk decoder
        # BARU -- field yang absen otomatis berarti SYNC_STATUS_NEW
        # untuk kedua environment (lihat get_env_sync_state()'s default),
        # persis status yang benar untuk decoder yang belum pernah
        # disentuh Dev maupun Prod. insert_one() di bawah TIDAK lewat
        # $set -- kalaupun perlu diisi, harus pakai env_sync_state_nested(),
        # BUKAN dot-path (lihat catatan di sync_utils.py).
        result = col.insert_one(doc)
        saved_id = result.inserted_id
        upserted = True

    # Phase 3: append a version entry if this save actually changed the
    # decoder group's content (re-reads the live group — see
    # record_decoder_group_version's docstring for why).
    record_decoder_group_version(
        get_decoder_history_collection(), col, doc['filename'], name,
        current_user.username, CHANGE_SOURCE_APP_EDIT, commit_message=commit_message,
    )

    return jsonify({
        'xml': xml,
        'saved': True,
        '_id': str(saved_id),
        'upserted': upserted,
        # [Phase C] Tidak ada lagi satu "sync_status" tunggal -- status
        # sekarang per environment. doc.get() dengan dot-key string
        # persis karena itulah cara field ini disimpan di dict Python
        # (lihat env_sync_status_only()) sebelum di-$set ke MongoDB.
        'sync_status_dev': doc.get('sync_state.dev.sync_status', SYNC_STATUS_NEW),
        'sync_status_prod': doc.get('sync_state.prod.sync_status', SYNC_STATUS_NEW),
    })

 
def _paginate_args():
    q = (request.args.get("q") or "").strip()
    page = max(int(request.args.get("page", 1) or 1), 1)
    per_page = min(max(int(request.args.get("per_page", 10) or 10), 1), 100)
    return q, page, per_page

@builder_bp.route("/decoder/list", methods=['GET'])
def list_decoders():
    """List decoders with pagination and search."""
    # 1. Panggil koleksi menggunakan helper function
    col = get_decoders_collection()
    if col is None:
        return _db_unavailable()

    q, page, per_page = _paginate_args()
    query = {}
    if q:
        query = {"$or": [
            {"name": {"$regex": q, "$options": "i"}},
            {"parent": {"$regex": q, "$options": "i"}},
        ]}
        
    # 2. Gunakan 'col' untuk melakukan query
    total = col.count_documents(query)
    cursor = (col.find(query, {
                    "name": 1, "parent": 1, "type": 1, "program_name": 1, "updated_at": 1, "filename": 1,
                    "sync_state": 1,
                })
                .sort("updated_at", -1)
                .skip((page - 1) * per_page)
                .limit(per_page))

    items = [_with_flat_sync_status(_serialise(doc)) for doc in cursor]
    return jsonify({"items": items, "total": total, "page": page, "per_page": per_page})

@builder_bp.route('/decoder/<decoder_id>', methods=['GET'])
def get_decoder(decoder_id: str):
    """Return a single decoder document by MongoDB _id.

    `name` is not unique for decoders (Wazuh "sibling decoders" allow
    multiple decoders sharing a name — see xml_parser.parse_decoder_xml),
    so `_id` is the only reliable way to address one specific document.
    """
    col = get_decoders_collection()
    if col is None:
        return _db_unavailable()

    try:
        object_id = ObjectId(decoder_id)
    except Exception:
        return jsonify({'error': f'ID decoder tidak valid: "{decoder_id}".'}), 400

    doc = col.find_one({'_id': object_id})
    if not doc:
        return jsonify({'error': f'Decoder dengan ID "{decoder_id}" tidak ditemukan.'}), 404
    return jsonify(_serialise(doc))


@builder_bp.route('/decoder/order-fields', methods=['GET'])
def get_decoder_order_fields():
    """
    [Fitur baru, 26 Agustus 2026] Union semua field <order> dari SETIAP
    dokumen decoder yang berbagi `name` yang sama (sibling) — dipakai
    Rule Builder's Test Samples auto-grading untuk verifikasi decoder
    benar-benar mengekstrak field yang seharusnya untuk sample yang
    expect_match=true (lihat gradeLogtestResult() di rule_builder.js).

    Query param: ?name=<decoder_name>

    KETERBATASAN JUJUR: sibling decoder yang berbagi `name` bisa saja
    punya `order` yang BEDA (varian pola log berbeda, dipilih Wazuh saat
    runtime lewat `program_name`/`prematch` — lihat catatan sibling
    decoder di xml_parser.py). Endpoint ini TIDAK TAHU sibling mana yang
    sebenarnya dipakai Wazuh untuk satu log tertentu — response
    /tester/logtest cuma kasih tahu NAMA decoder yang dipakai
    (`output.decoder.name`), bukan sibling mana persisnya. Jadi yang
    dikembalikan adalah UNION seluruh field dari semua sibling nama itu
    ("field yang mungkin diharapkan"), bukan jaminan mutlak — pemanggil
    (JS) harus perlakukan field yang hilang sebagai SINYAL untuk
    diselidiki, bukan bukti pasti ada bug (log yang match ke sibling
    varian LAIN secara sah bisa saja tidak mengisi field milik varian
    lain).
    """
    name = (request.args.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'Parameter "name" wajib diisi.'}), 400

    col = get_decoders_collection()
    if col is None:
        return _db_unavailable()

    fields = set()
    sibling_count = 0
    for doc in col.find({'name': name}, {'order': 1}):
        sibling_count += 1
        order_str = doc.get('order') or ''
        for f in order_str.split(','):
            f = f.strip()
            if f:
                fields.add(f)

    return jsonify({
        'name': name,
        'order_fields': sorted(fields),
        'sibling_count': sibling_count,
    })


@builder_bp.route('/decoder/<decoder_id>', methods=['DELETE'])
def delete_decoder(decoder_id: str):
    """Delete a single decoder document by MongoDB _id (see get_decoder)."""
    col = get_decoders_collection()
    if col is None:
        return _db_unavailable()

    try:
        object_id = ObjectId(decoder_id)
    except Exception:
        return jsonify({'error': f'ID decoder tidak valid: "{decoder_id}".'}), 400

    # Needed BEFORE deleting: record_decoder_group_version re-reads the
    # group by (filename, name) after the delete to snapshot whatever
    # siblings remain (or an empty list, acting as the deletion
    # tombstone — see history_utils.record_decoder_group_version).
    target = col.find_one({'_id': object_id}, {'filename': 1, 'name': 1})
    if target is None:
        return jsonify({'error': f'Decoder dengan ID "{decoder_id}" tidak ditemukan.'}), 404

    result = col.delete_one({'_id': object_id})
    if result.deleted_count == 0:
        return jsonify({'error': f'Decoder dengan ID "{decoder_id}" tidak ditemukan.'}), 404

    record_decoder_group_version(
        get_decoder_history_collection(), col, target.get('filename'), target.get('name'),
        current_user.username, CHANGE_SOURCE_DELETED,
    )

    return jsonify({'deleted': True, '_id': decoder_id})


# ══════════════════════════════════════════════════════════════════════
# RULE endpoints
# ══════════════════════════════════════════════════════════════════════
@builder_bp.route("/rule/list", methods=['GET'])
def list_rules():
    """List rules with pagination, search, and simplified multiple levels parameter."""
    col = get_rules_collection()
    if col is None:
        return _db_unavailable()

    q, page, per_page = _paginate_args()
    
    # --- PROSES FILTER MULTIPLE LEVEL (STRING PARSING) ---
    levels = []
    level_param = request.args.get('level') # Gunakan .get() biasa, bukan .getlist()
    
    if level_param:
        try:
            # Mengubah string "[0,1,2]" menjadi list asli Python [0, 1, 2]
            parsed_levels = json.loads(level_param)
            if isinstance(parsed_levels, list):
                # Memastikan semua item di dalamnya diubah menjadi integer untuk query MongoDB
                levels = [int(lvl) for lvl in parsed_levels if str(lvl).isdigit()]
        except (json.JSONDecodeError, ValueError):
            # Antisipasi jika format string yang dikirim rusak/invalid
            levels = []
    # ----------------------------------------------------

    # Inisialisasi klausa query
    query_clauses = []

    # Filter Pencarian (Query teks)
    if q:
        or_clauses = [
            {"description": {"$regex": q, "$options": "i"}},
            {"filename": {"$regex": q, "$options": "i"}},
            {"group": {"$regex": q, "$options": "i"}},
        ]
        if q.isdigit():
            or_clauses.append({"rule_id": int(q)})
        query_clauses.append({"$or": or_clauses})

    # Filter Level (Tetap menggunakan operator $in)
    if levels:
        query_clauses.append({"level": {"$in": levels}})

    # [Fitur baru, 4 September 2026] Filter Tech Stack — tampilkan hanya
    # rule yang terhubung ke item stack tertentu (?tech_stack=<ObjectId>).
    # Parameter tidak valid -> 400 (bukan 500 dari ObjectId() err).
    tech_stack_param = (request.args.get('tech_stack') or '').strip()
    if tech_stack_param:
        try:
            tech_stack_oid = ObjectId(tech_stack_param)
        except Exception:
            return jsonify({'error': f'Param "tech_stack" tidak valid: "{tech_stack_param}".'}), 400
        query_clauses.append({"tech_stack_ids": tech_stack_oid})

    # Gabungkan semua clause ke dalam query utama
    query = {"$and": query_clauses} if query_clauses else {}
        
    total = col.count_documents(query)
    cursor = (col.find(query, {
                    "rule_id": 1, "level": 1, "filename": 1, "description": 1, "group": 1, "updated_at": 1,
                    "sync_state": 1, "content_hash": 1, "test_results": 1, "tech_stack_ids": 1, "_id": 0
                })
                .sort("updated_at", -1)
                .skip((page - 1) * per_page)
                .limit(per_page))

    # [Fitur baru, 4 September 2026] Enrichment: kumpulkan semua tech_stack_ids
    # yang dirujuk rule di halaman ini, fetch sekali dari tech_stack, lalu
    # tempel label vendor/product ke tiap item — frontend cukup render tanpa
    # N+1 query.
    items = []
    ts_col = get_tech_stack_collection()
    ts_label_map: dict[str, dict] = {}
    docs = list(cursor)
    all_ts_ids = {str(i) for d in docs for i in (d.get('tech_stack_ids') or [])}
    if all_ts_ids and ts_col is not None:
        for ts_doc in ts_col.find({'_id': {'$in': [ObjectId(i) for i in all_ts_ids]}},
                                   {'vendor': 1, 'product': 1}):
            ts_label_map[str(ts_doc['_id'])] = {
                '_id': str(ts_doc['_id']),
                'vendor': ts_doc.get('vendor', ''),
                'product': ts_doc.get('product', ''),
            }
    for doc in docs:
        # tech_stack_ids di response harus string (jsonify tidak bisa
        # serialize ObjectId) — frontend pakai ini untuk render badge
        # dan mengirim ulang saat edit.
        doc['tech_stack_ids'] = [str(i) for i in (doc.get('tech_stack_ids') or [])]
        doc['tech_stack_items'] = [ts_label_map[i] for i in doc['tech_stack_ids'] if i in ts_label_map]
        # Urutan penting: lifecycle_status dulu (butuh sync_state utuh),
        # baru flatten sync_state (menghapusnya dari dict).
        items.append(_with_flat_sync_status(_with_lifecycle_status(doc)))
    return jsonify({"items": items, "total": total, "page": page, "per_page": per_page})

@builder_bp.route('/rule/xml', methods=['POST'])
def generate_rule_xml():
    """Generate rule XML without persisting to DB."""
    data = request.get_json() or {}
    try:
        xml = xml_generator.generate_rule(data)
        return jsonify({'xml': xml})
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400


@builder_bp.route('/rule/save', methods=['POST'])
def save_rule():
    """Generate rule XML and upsert the document into MongoDB."""
    col = get_rules_collection()
    if col is None:
        return _db_unavailable()

    data = request.get_json() or {}
    try:
        xml = xml_generator.generate_rule(data)
    except ValueError as exc:
        return jsonify({'error': str(exc)}), 400

    # 'rule_id' is the canonical key (matches the MongoDB schema); accept
    # 'id' too so older/alternate frontend payloads keep working.
    rule_id_str = str(data.get('rule_id') or data.get('id') or '').strip()
    if not rule_id_str:
        return jsonify({'error': 'Rule id is required.'}), 400
    # [FIX audit 22 Agustus 2026] rule_id non-numerik dulu bikin ValueError
    # tidak tertangani di bawah -> 500 generik. Sekarang balikin 400 yang
    # jelas ke client.
    try:
        rule_id_int = int(rule_id_str)
    except ValueError:
        return jsonify({'error': f'Rule id harus berupa angka, diterima: "{rule_id_str}".'}), 400

    # [Fitur baru, 26 Agustus 2026] test_samples WAJIB diisi sebelum rule
    # bisa disimpan (setiap save, bukan cuma create pertama kali) --
    # keputusan produk untuk memastikan tiap rule punya minimal satu
    # bukti konkret bahwa dia benar-benar match terhadap log nyata,
    # bukan cuma "lolos" logtest gate (Phase D, menyusul) tanpa ada apa-
    # apa yang divalidasi sama sekali. Minimal SATU sample dengan
    # expect_match=true (bukti positif) -- sample negatif (expect_match=
    # false, log yang HARUS TIDAK match, untuk menangkap over-matching/
    # false positive) direkomendasikan tapi tidak diwajibkan.
    #
    # SENGAJA tidak masuk ke RULE_CONTENT_FIELDS (sync_utils.py) --
    # test_samples murni metadata QA internal LARAS, TIDAK pernah
    # dikirim ke Wazuh Manager sebagai bagian dari XML rule. Kalau ikut
    # masuk content_hash, mengubah sample SAJA akan salah dianggap
    # "rule berubah, perlu di-push ulang", padahal XML yang dikirim ke
    # Wazuh sama sekali tidak berubah.
    test_samples = data.get('test_samples')
    if not isinstance(test_samples, list) or len(test_samples) == 0:
        return jsonify({'error': 'Minimal 1 sample log (test_samples) wajib diisi sebelum rule bisa disimpan.'}), 400

    cleaned_samples = []
    for i, sample in enumerate(test_samples):
        if not isinstance(sample, dict):
            return jsonify({'error': f'test_samples[{i}] harus berupa object.'}), 400
        log_text = (sample.get('log') or '').strip()
        if not log_text:
            return jsonify({'error': f'test_samples[{i}]: field "log" wajib diisi.'}), 400
        if not isinstance(sample.get('expect_match'), bool):
            return jsonify({'error': f'test_samples[{i}]: field "expect_match" wajib berupa boolean (true/false).'}), 400
        cleaned_samples.append({
            'log': log_text,
            'expect_match': sample['expect_match'],
            'note': (sample.get('note') or '').strip() or None,
        })

    if not any(s['expect_match'] is True for s in cleaned_samples):
        return jsonify({'error': 'Minimal 1 sample dengan expect_match=true (log yang HARUS match rule ini) wajib ada.'}), 400

    data['test_samples'] = cleaned_samples

    doc = {k: v for k, v in data.items()}
    doc.pop('id', None)  # don't store a stray duplicate of rule_id
    doc['rule_id'] = rule_id_int

    # Keep groups as an array for indexing/autocomplete
    group_text = doc.get('group', '')
    doc['groups'] = [g.strip() for g in group_text.split(',') if g.strip()]

    # Free-text note describing WHY this change was made — goes to
    # rule_history's commit_message, never onto the live document itself.
    commit_message = (data.get('commit_message') or '').strip() or None

    # Sync-tracking fields are server-managed — never trust them from the
    # client payload, whatever the caller happened to send.
    # [FIX audit 22 Agustus 2026] '_id' ditambahkan ke daftar ini, konsisten
    # dengan save_decoder() — rule diidentifikasi lewat rule_id, bukan _id,
    # jadi _id dari client (kalaupun ada) tidak boleh ikut ke $set (bisa
    # memicu error MongoDB "immutable field _id" kalau nilainya beda dari
    # dokumen yang di-update).
    for reserved in ('origin', 'ruleset_type',
                      'last_synced_hash', 'last_synced_at', 'sync_status',
                      'content_hash', 'commit_message', '_id'):
        doc.pop(reserved, None)

    # [Fitur baru, 4 September 2026] Tech Stack linkage — metadata LARAS,
    # disimpan sebagai daftar ObjectId yang TIDAK boleh ikut content_hash
    # (RULE_CONTENT_FIELDS tidak menyertakannya, lihat sync_utils.py),
    # jadi mengubah linkage tidak pernah memicu "rule berubah, perlu
    # di-push ulang". Divalidasi eksplisit (bukan langsung dipercaya dari
    # client) — setiap ID harus ObjectId valid DAN ada di tech_stack.
    raw_ts_ids = doc.pop('tech_stack_ids', None)
    normalized_ts_ids, ts_error = _normalize_tech_stack_ids(raw_ts_ids)
    if ts_error is not None:
        return jsonify(ts_error), 400
    doc['tech_stack_ids'] = normalized_ts_ids or []

    # Compare against whatever was last recorded sebagai "synced" PER
    # ENVIRONMENT (lihat services/sync_utils.py get_env_sync_state) untuk
    # menentukan apakah save ini bikin rule ini "modified_local" relatif
    # ke Dev, ke Prod, atau dua-duanya sekaligus -- keduanya independen,
    # rule bisa saja sudah modified_local ke Prod tapi masih sinkron ke
    # Dev (atau sebaliknya) tergantung riwayat push masing-masing.
    existing = col.find_one({'rule_id': doc['rule_id']}, {'filename': 1, '_wrapper_group': 1, 'sync_state': 1})

    # `filename` is the canonical field pull/push/diff group by. If the
    # client (e.g. a "save to file" dropdown in the wizard) sent one, use
    # it; otherwise keep whatever was already stored; otherwise fall back
    # to a sensible default for a brand-new app-created rule.
    incoming_filename = _normalize_filename(data.get('filename', ""))
    doc['filename'] = incoming_filename or (existing.get('filename') if existing else None) or 'local_rules.xml'

    # `_wrapper_group` is the name used for this rule's <group name="...">
    # wrapper block on rebuild — deliberately separate from this rule's own
    # `group` field. A single file CAN legitimately contain rules under
    # several different wrapper names (Wazuh's own default ruleset does
    # this routinely) — push rebuilds the file as one <group> block per
    # distinct wrapper (see xml_parser.build_rule_file_xml), so there's
    # nothing to warn about here. Accept it from the wizard's "wrapper
    # group" input; otherwise keep whatever was already recorded (e.g.
    # from a prior pull); otherwise leave it unset so push falls back to
    # this rule's own group.
    incoming_wrapper = (doc.pop('wrapper_group', '') or '').strip()
    if incoming_wrapper and not incoming_wrapper.endswith(','):
        incoming_wrapper += ','
    existing_wrapper = existing.get('_wrapper_group') if existing else None
    if incoming_wrapper or existing_wrapper:
        doc['_wrapper_group'] = incoming_wrapper or existing_wrapper

    new_hash = rule_content_hash(doc)
    doc['content_hash'] = new_hash
    doc['last_modified_by'] = current_user.username
    # [Phase C, 24 Agustus 2026] Status PER ENVIRONMENT, dihitung ulang
    # relatif ke snapshot terakhir yang synced ke masing-masing env.
    # existing bisa None (rule baru) -- resolve_env_sync_status/
    # get_env_sync_state menangani itu dengan fallback SYNC_STATUS_NEW,
    # dot-path AMAN di sini karena update_one di bawah selalu lewat $set
    # (termasuk saat upsert=True membuat dokumen baru).
    existing_for_status = existing or {}
    doc.update(env_sync_status_only('dev', resolve_env_sync_status(existing_for_status, 'dev', new_hash)))
    doc.update(env_sync_status_only('prod', resolve_env_sync_status(existing_for_status, 'prod', new_hash)))

    try:
        result = col.update_one(
            {'rule_id': doc['rule_id']},
            {
                '$set': doc,
                # Only applied when the document is newly created —
                # existing rules keep their real origin/sync history
                # untouched on every subsequent edit.
                '$setOnInsert': {
                    'origin': 'app_created',
                    'ruleset_type': 'custom',
                },
            },
            upsert=True,
        )
        # Phase 3: append a version entry if this save actually changed
        # the rule's content (no-op if unchanged — see record_rule_version).
        record_rule_version(get_rule_history_collection(), doc, current_user.username, CHANGE_SOURCE_APP_EDIT, commit_message=commit_message)

        # Known Wazuh-parser quirks (constructs that are valid XML but
        # still get rejected by Wazuh's own upload validator — see
        # services/wazuh_compat.py) are checked here too, not just at
        # push time, so the person finds out as early as possible.
        compat_warnings = scan_rule_doc(doc)
        # [FIX 27 Agustus 2026] `doc` di titik ini masih berisi dot-key
        # LITERAL (mis. 'sync_state.dev.sync_status') dari
        # env_sync_status_only() -- itu cuma valid untuk operator $set
        # MongoDB, BUKAN struktur nested asli yang bisa dibaca langsung
        # oleh get_env_sync_state()/compute_rule_lifecycle_status().
        # Re-fetch dari MongoDB supaya sync_state benar-benar nested
        # sebelum dihitung -- tanpa ini, lifecycle_status akan SELALU
        # salah (jatuh ke default SYNC_STATUS_NEW untuk dev & prod).
        fresh_doc = col.find_one({'rule_id': doc['rule_id']}, {'sync_state': 1, 'content_hash': 1, 'test_results': 1})
        lifecycle_status = compute_rule_lifecycle_status(fresh_doc) if fresh_doc else 'draft'
        return jsonify({
            'xml': xml,
            'saved': True,
            'upserted': result.upserted_id is not None,
            'sync_status_dev': doc.get('sync_state.dev.sync_status', SYNC_STATUS_NEW),
            'sync_status_prod': doc.get('sync_state.prod.sync_status', SYNC_STATUS_NEW),
            'lifecycle_status': lifecycle_status,
            'compat_warnings': compat_warnings,
        })
    except mongo_errors.DuplicateKeyError:
        return jsonify({'error': f'Rule ID {rule_id_str} already exists.'}), 409


@builder_bp.route('/rule/<int:rule_id>/test-results', methods=['POST'])
def record_rule_test_results(rule_id: int):
    """
    [Fitur baru, 27 Agustus 2026] Simpan snapshot hasil "Run All Samples"
    dari Rule Builder wizard (rule_builder.js's runAllTestSamples()) --
    SATU snapshot lengkap per pemanggilan, BUKAN update granular per-
    sample (keputusan eksplisit 27 Agustus 2026: snapshot penuh lebih
    robust, tidak rawan index array bergeser kalau sample ditambah/
    dihapus di antara dua kali Run).

    `content_hash` DISTEMPEL SERVER-SIDE dari dokumen yang benar-benar
    tersimpan saat ini -- TIDAK PERNAH dipercaya dari client -- supaya
    "kesegaran" test_results (dibandingkan
    services/lifecycle_utils.compute_rule_lifecycle_status) tidak bisa
    keliru/dipalsukan gara-gara client kirim hash yang salah.

    Body: { "samples": [{log, expect_match, passed, matched_rule_id, reason}, ...] }
    (bentuk persis yang sudah dihasilkan gradeLogtestResult() di
    rule_builder.js -- endpoint ini cuma menyimpan apa adanya, tidak
    menilai ulang).
    """
    col = get_rules_collection()
    if col is None:
        return _db_unavailable()

    payload = request.get_json(silent=True) or {}
    samples = payload.get('samples')
    if not isinstance(samples, list) or len(samples) == 0:
        return jsonify({'error': 'Field "samples" wajib diisi (hasil dari Run All Samples).'}), 400

    doc = col.find_one({'rule_id': rule_id}, {'content_hash': 1, 'sync_state': 1})
    if doc is None:
        return jsonify({'error': f'Rule {rule_id} tidak ditemukan -- simpan rule ini dulu sebelum merekam hasil test.'}), 404

    all_passed = all(bool(s.get('passed')) for s in samples)
    test_results = {
        'content_hash': doc.get('content_hash'),
        'tested_at': datetime.now(timezone.utc),
        'tested_by': current_user.username,
        'samples': samples,
        'all_passed': all_passed,
    }
    col.update_one({'rule_id': rule_id}, {'$set': {'test_results': test_results}})

    lifecycle_status = compute_rule_lifecycle_status({**doc, 'test_results': test_results})
    return jsonify({'saved': True, 'all_passed': all_passed, 'lifecycle_status': lifecycle_status})


@builder_bp.route('/rule/<int:rule_id>/deploy-dev', methods=['POST'])
def deploy_rule_to_dev(rule_id: int):
    """
    [8 September 2026] Deploy SATU rule ke Wazuh Dev lalu reload, supaya
    test samples dijalankan terhadap versi TERKINI di Dev -- bukan ruleset
    lama (wazuh-logtest menguji terhadap ruleset aktif, tidak ada jalur
    uji draft ad-hoc). Dipanggil otomatis oleh runAllTestSamples() di
    rule_builder.js SEBELUM menjalankan samples (tanpa modal konfirmasi).

    Batasan "Opsi 1 terbatas" (keputusan 8 September 2026):
      - Hanya SATU file (file tempat rule ini berada), bukan batch.
      - Hanya ke Dev -- tidak pernah menyentuh Prod.
      - Hanya rule custom: ruleset_type='default' (ruleset bawaan Wazuh)
        DITOLAK (read-only, guard ruleset-bawaan 7 September 2026).
      - Tidak pernah force: kalau file berstatus conflict di Dev,
        endpoint balikin 409 dan user harus selesaikan manual.
      - No-op kalau sync_state.dev.sync_status sudah 'synced' (tidak ada
        yang berubah sejak push terakhir) -- push+reload hanya terjadi
        saat benar-benar perlu.

    Alur: ambil rule dari MongoDB -> rebuild XML dari SELURUH dokumen
    file tsb (push_selected beroperasi per-file, konsisten dengan
    mekanisme push biasa) -> upload ke Dev -> reload analysisd.

    Prasyarat: rule SUDAH disimpan ke MongoDB (saveRule() dipanggil
    frontend sebelum endpoint ini) -- endpoint ini membaca dari
    database, bukan dari form wizard.
    """
    col = get_rules_collection()
    if col is None:
        return _db_unavailable()

    doc = col.find_one({'rule_id': rule_id}, {'filename': 1, 'ruleset_type': 1, 'sync_state': 1})
    if doc is None:
        return jsonify({
            'deployed': False, 'reason': 'not_saved',
            'error': f'Rule {rule_id} belum tersimpan di MongoDB. Simpan rule ini dulu (Save to MongoDB) sebelum deploy ke Dev.',
        }), 404

    if doc.get('ruleset_type') == 'default':
        return jsonify({
            'deployed': False, 'reason': 'builtin',
            'error': 'Rule ini berasal dari ruleset bawaan Wazuh (read-only). Deploy ke Dev diblokir agar tidak membuat duplikat.',
        }), 400

    filename = doc.get('filename') or 'local_rules.xml'
    dev_status = get_env_sync_state(doc, 'dev').get('sync_status', SYNC_STATUS_NEW)

    if dev_status == SYNC_STATUS_SYNCED:
        # Versi Dev sudah sama dengan MongoDB -- tidak perlu deploy ulang.
        return jsonify({
            'deployed': False, 'reason': 'already_synced',
            'message': f'Rule {rule_id} sudah sinkron dengan Dev ({filename}). Langsung jalankan test samples.',
        })

    if dev_status == SYNC_STATUS_CONFLICT:
        return jsonify({
            'deployed': False, 'reason': 'conflict',
            'error': f'File "{filename}" berstatus conflict di Dev. Selesaikan conflict dulu di Sync & Manager sebelum deploy otomatis.',
        }), 409

    # ── Push SATU file ke Dev ─────────────────────────────────────────
    wazuh_api_dev = WazuhAPI(env='dev')
    push_result = wazuh_api_dev.push_selected(
        rule_filenames=[filename],
        decoder_filenames=[],
        force=False,
    )

    if push_result.get('skipped_builtin'):
        return jsonify({
            'deployed': False, 'reason': 'builtin',
            'error': f'File "{filename}" mengandung ruleset bawaan Wazuh (read-only). Deploy diblokir.',
        }), 400

    if push_result.get('skipped_conflicts'):
        return jsonify({
            'deployed': False, 'reason': 'conflict',
            'error': f'File "{filename}" berstatus conflict di Dev. Selesaikan conflict dulu sebelum deploy otomatis.',
        }), 409

    if not push_result.get('success') or push_result.get('errors'):
        detail = push_result.get('errors') or [push_result.get('error') or 'Push ke Dev gagal tanpa detail.']
        return jsonify({
            'deployed': False, 'reason': 'push_failed',
            'error': '; '.join(str(e) for e in detail) if detail else 'Push ke Dev gagal.',
        }), 502

    # ── Reload Dev (analysisd) supaya logtest memakai versi terbaru ────
    reload_result = wazuh_api_dev.restart_manager()
    if not reload_result.get('success'):
        return jsonify({
            'deployed': False, 'reason': 'reload_failed',
            'error': f'File sudah di-push ke Dev, tapi reload analysisd gagal: {reload_result.get("error")}. Lakukan Reload manual di Sync & Manager.',
        }), 502

    return jsonify({
        'deployed': True,
        'filename': filename,
        'pushed_rules': push_result.get('pushed_rules', 0),
        'message': f'Rule {rule_id} di-deploy ke Dev ({filename}) & reload analysisd selesai.',
    })


@builder_bp.route('/rule/<int:rule_id>', methods=['GET'])
def get_rule(rule_id: int):
    """Return a single rule document by rule_id."""
    col = get_rules_collection()
    if col is None:
        return _db_unavailable()

    doc = col.find_one({'rule_id': rule_id})
    if not doc:
        return jsonify({'error': f'Rule {rule_id} not found.'}), 404
    # [Fitur baru, 27 Agustus 2026] lifecycle_status dihitung di sini --
    # SENGAJA tidak flatten sync_state seperti list_rules() karena
    # rule_builder.js's updateDevSyncTestWarning() butuh baca
    # sync_state.dev.sync_status dalam bentuk nested aslinya.
    doc = _with_lifecycle_status(doc)
    return jsonify(_serialise(doc))


@builder_bp.route('/rule/<int:rule_id>', methods=['DELETE'])
def delete_rule(rule_id: int):
    """Delete a rule document by rule_id."""
    col = get_rules_collection()
    if col is None:
        return _db_unavailable()

    result = col.delete_one({'rule_id': rule_id})
    if result.deleted_count == 0:
        return jsonify({'error': f'Rule {rule_id} not found.'}), 404

    record_rule_deletion(get_rule_history_collection(), rule_id, current_user.username)

    return jsonify({'deleted': True, 'rule_id': rule_id})


# ── Phase 4: version history + rollback ─────────────────────────────────

def _serialise_history(entry: dict) -> dict:
    """JSON-safe view of a rule_history/decoder_history entry."""
    out = dict(entry)
    out['_id'] = str(out['_id'])
    changed_at = out.get('changed_at')
    if changed_at is not None:
        out['changed_at'] = changed_at.isoformat()
    return out


@builder_bp.route('/rule/<int:rule_id>/history', methods=['GET'])
def get_rule_history(rule_id: int):
    """
    All recorded versions for this rule_id, newest first. Includes
    tombstone entries (change_source='deleted') if the rule was ever
    deleted and later recreated — those show up with snapshot=null.
    """
    hist_col = get_rule_history_collection()
    if hist_col is None:
        return _db_unavailable()
    entries = list(hist_col.find({'rule_id': rule_id}).sort('version_number', -1))
    return jsonify([_serialise_history(e) for e in entries])


@builder_bp.route('/rule/<int:rule_id>/rollback/<int:version_number>', methods=['POST'])
def rollback_rule(rule_id: int, version_number: int):
    """
    Restore rule_id's content to exactly what it was at version_number.

    This is implemented as an ordinary save (goes through the same
    content_hash/sync_status computation as save_rule, and itself
    records a NEW version via record_rule_version with
    change_source='rollback') — a rollback is a forward-moving edit
    that happens to copy old content, not a destructive rewind. Nothing
    about the version history between now and version_number is erased.

    Phase A "Opsi Tengah" (22 Agustus 2026): setelah restore, otomatis
    ajukan promotion request untuk filename ini kalau hasilnya beda dari
    server (lihat _auto_promote_after_rollback) — TIDAK langsung push,
    gate 4-eyes tetap berlaku, reviewer lain tetap harus approve.
    """
    hist_col = get_rule_history_collection()
    col = get_rules_collection()
    if hist_col is None or col is None:
        return _db_unavailable()

    payload = request.get_json(silent=True) or {}
    commit_message = (payload.get('commit_message') or '').strip() or f'Rollback ke versi {version_number}'

    entry = hist_col.find_one({'rule_id': rule_id, 'version_number': version_number})
    if entry is None:
        return jsonify({'error': f'Versi {version_number} untuk rule {rule_id} tidak ditemukan.'}), 404
    if entry.get('change_source') == CHANGE_SOURCE_DELETED:
        # record_rule_deletion deliberately carries the last-known
        # snapshot forward into a tombstone entry (so history display can
        # show what content existed right before deletion) — so checking
        # snapshot truthiness alone would never catch this. A tombstone
        # documents "this rule was deleted here", not a content state to
        # restore to; roll back to the version just before it instead.
        return jsonify({'error': f'Versi {version_number} adalah catatan penghapusan (tombstone), bukan versi konten — rollback ke versi sebelum penghapusan ini sebagai gantinya.'}), 400
    if not entry.get('snapshot'):
        return jsonify({'error': f'Versi {version_number} tidak memiliki data konten untuk di-rollback.'}), 400

    doc = dict(entry['snapshot'])
    # Very old history entries recorded before filename tracking was
    # added won't have one — fall back rather than write a rule with no
    # filename at all (which would break pull/push/diff's filename grouping).
    doc['filename'] = entry.get('filename') or 'local_rules.xml'

    existing = col.find_one({'rule_id': rule_id}, {'sync_state': 1})
    existing_for_status = existing or {}

    new_hash = rule_content_hash(doc)
    doc['content_hash'] = new_hash
    doc['last_modified_by'] = current_user.username
    # [Phase C, 24 Agustus 2026] Status PER ENVIRONMENT, sama seperti
    # save_rule() -- rollback adalah "edit" yang kebetulan menyalin
    # konten lama, jadi status dihitung dengan cara yang persis sama.
    dev_status = resolve_env_sync_status(existing_for_status, 'dev', new_hash)
    prod_status = resolve_env_sync_status(existing_for_status, 'prod', new_hash)
    doc.update(env_sync_status_only('dev', dev_status))
    doc.update(env_sync_status_only('prod', prod_status))

    col.update_one(
        {'rule_id': rule_id},
        {
            '$set': doc,
            '$setOnInsert': {
                'origin': 'app_created',
                'ruleset_type': 'custom',
            },
        },
        upsert=True,
    )
    record_rule_version(hist_col, doc, current_user.username, CHANGE_SOURCE_ROLLBACK, commit_message=commit_message)

    # [Phase C] "Perlu dipromosikan?" sekarang berarti "beda dari Prod"
    # secara spesifik (promote selalu menuju Prod) -- BUKAN dari Dev.
    # create_promotion_request() sendiri yang menolak (dengan pesan
    # jelas) kalau file ini ternyata belum pernah synced ke Dev sama
    # sekali; guard itu tidak diduplikasi di sini.
    promotion_result = _auto_promote_after_rollback(
        doc['filename'], is_rule=True, needs_promote=(prod_status != SYNC_STATUS_SYNCED),
    )

    return jsonify({
        'rolled_back': True,
        'rule_id': rule_id,
        'restored_from_version': version_number,
        'sync_status_dev': dev_status,
        'sync_status_prod': prod_status,
        'promotion_request': promotion_result,
    })


@builder_bp.route('/decoder/history', methods=['GET'])
def get_decoder_history():
    """
    All recorded versions for the decoder GROUP identified by
    (filename, name) — see history_utils.py module docstring for why
    decoder history is tracked per group rather than per sibling.
    Query params: ?filename=...&name=...
    """
    filename = (request.args.get('filename') or '').strip()
    name = (request.args.get('name') or '').strip()
    if not filename or not name:
        return jsonify({'error': 'Parameter "filename" dan "name" wajib diisi.'}), 400

    hist_col = get_decoder_history_collection()
    if hist_col is None:
        return _db_unavailable()
    entries = list(hist_col.find({'filename': filename, 'name': name}).sort('version_number', -1))
    return jsonify([_serialise_history(e) for e in entries])


@builder_bp.route('/decoder/rollback', methods=['POST'])
def rollback_decoder():
    """
    Restore the decoder group (filename, name) to exactly what it was at
    version_number — i.e. replace ALL of its current sibling documents
    with the siblings recorded in that version's snapshot.

    Body: { "filename": "...", "name": "...", "version_number": N }

    Implemented as a full delete-then-reinsert of the group's live
    documents, same pattern as pull_selected's decoder handling (see
    wazuh_api.py) and for the same reason: individual sibling documents
    have no stable identity to reconcile against across time, so a full
    swap is the only unambiguous way to reach an exact prior state. This
    itself records a new version (change_source='rollback') via
    record_decoder_group_version — nothing between now and
    version_number is erased from history.

    Phase A "Opsi Tengah" (22 Agustus 2026): setelah restore, otomatis
    ajukan promotion request untuk filename ini — decoder rollback SELALU
    dianggap "perlu dipromosikan" (lihat komentar di bawah), jadi promotion
    request selalu diajukan di sini kalau ada sibling yang di-restore.
    """
    payload = request.get_json(silent=True) or {}
    filename = (payload.get('filename') or '').strip()
    name = (payload.get('name') or '').strip()
    version_number = payload.get('version_number')
    if not filename or not name or version_number is None:
        return jsonify({'error': 'Field "filename", "name", dan "version_number" wajib diisi.'}), 400
    commit_message = (payload.get('commit_message') or '').strip() or f'Rollback ke versi {version_number}'

    hist_col = get_decoder_history_collection()
    col = get_decoders_collection()
    if hist_col is None or col is None:
        return _db_unavailable()

    entry = hist_col.find_one({'filename': filename, 'name': name, 'version_number': version_number})
    if entry is None:
        return jsonify({'error': f'Versi {version_number} untuk decoder "{name}" di "{filename}" tidak ditemukan.'}), 404

    col.delete_many({'filename': filename, 'name': name})

    snapshot = entry.get('snapshot') or []
    promotion_result = None
    if snapshot:
        new_docs = []
        for seq, sibling in enumerate(snapshot):
            d = dict(sibling)
            d['filename'] = filename
            d['_seq'] = seq
            d['origin'] = 'app_created'
            d['ruleset_type'] = 'custom'
            content_hash = decoder_content_hash(d)
            d['content_hash'] = content_hash
            # [Phase C, 24 Agustus 2026] TIDAK set sync_state sama sekali
            # di sini -- field yang absen otomatis berarti
            # SYNC_STATUS_NEW untuk KEDUA environment (lihat
            # get_env_sync_state()'s default), yang memang status yang
            # jujur untuk decoder hasil delete-then-reinsert: hubungannya
            # dengan Dev maupun Prod genuinely tidak diketahui sampai
            # pull/push berikutnya (bukan 'synced' karena belum benar-benar
            # disinkron, bukan juga 'modified_local' karena tidak ada
            # snapshot "terakhir synced" untuk dibandingkan). insert_many()
            # di bawah TIDAK lewat $set -- kalau MEMANG perlu diisi
            # eksplisit, harus pakai env_sync_state_nested(), BUKAN
            # dot-path (lihat catatan di sync_utils.py) -- tapi di sini
            # sengaja tidak diisi sama sekali karena defaultnya sudah benar.
            d['last_modified_by'] = current_user.username
            new_docs.append(d)
        col.insert_many(new_docs)

        # sync_state absen di atas -> selalu dianggap "perlu dipromosikan"
        # (needs_promote=True) -- konsisten dengan alasan yang sama:
        # delete-then-reinsert menghilangkan kemampuan membandingkan ke
        # snapshot Prod yang lama, jadi selalu aman (dan perlu) dicoba
        # ajukan promote, biar create_promotion_request() yang putuskan
        # boleh/tidaknya berdasarkan status Dev/conflict yang sebenarnya.
        promotion_result = _auto_promote_after_rollback(filename, is_rule=False, needs_promote=True)

    record_decoder_group_version(hist_col, col, filename, name, current_user.username, CHANGE_SOURCE_ROLLBACK, commit_message=commit_message)

    return jsonify({
        'rolled_back': True,
        'filename': filename,
        'name': name,
        'restored_from_version': version_number,
        'promotion_request': promotion_result,
    })