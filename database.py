"""
database.py — MongoDB connection and collection helper.

Collections:
  - rules     : stores Wazuh rule documents
  - decoders  : stores Wazuh decoder documents

Sync-tracking fields (added for the pull/push feature) present on
documents in both collections — see services/sync_utils.py for how
they're computed and used:

  filename            str          canonical target/source file, e.g.
                                    "local_rules.xml". Set on pull (to the
                                    actual remote filename) and on first
                                    save from the builder UI (to the
                                    user-chosen or default filename).
                                    This is the ONE field pull/push/diff
                                    group and filter by — do not
                                    reintroduce a separate "source_file"
                                    field, the two used to drift out of
                                    sync with each other.
  origin               'app_created' | 'pulled'
  ruleset_type        'custom' | 'default'   (default ruleset is read-only)
  content_hash        str          sha256 of the document's structural content
  last_synced_hash    str | None   content_hash as of the last successful sync
  last_synced_at      datetime | None
  sync_status         'new' | 'synced' | 'modified_local' | 'conflict'
"""

from __future__ import annotations

import logging
from pymongo import MongoClient, ASCENDING, errors
from config import Config

logger = logging.getLogger(__name__)

# Module-level client and db references (initialised lazily via init_db)
_client: MongoClient | None = None
_db = None


def get_db():
    """Return the active MongoDB database instance."""
    global _client, _db
    if _db is None:
        init_db()
    return _db


def get_client() -> MongoClient | None:
    """
    Return the raw MongoClient instance, or None if unavailable.

    Needed by app.py to hand off to Flask-Session's MongoDB backend
    (SESSION_MONGODB expects an actual MongoClient object, not a URI
    string) so sessions share the same connection instead of opening a
    second one to the same server.
    """
    global _client
    if _client is None:
        init_db()
    return _client


def init_db():
    """
    Create the MongoClient, connect to the configured database, and
    ensure all required indexes exist.

    Called once during Flask app initialisation (see app.py).
    """
    global _client, _db

    try:
        _client = MongoClient(Config.MONGO_URI, serverSelectionTimeoutMS=5000)
        # Force connection attempt to raise early on misconfiguration
        _client.server_info()
        _db = _client[Config.MONGO_DB_NAME]
        _ensure_indexes(_db)
        logger.info(
            '[MongoDB] Connected to %s / %s',
            Config.MONGO_URI,
            Config.MONGO_DB_NAME,
        )
    except errors.ServerSelectionTimeoutError as exc:
        logger.warning(
            '[MongoDB] Could not connect to %s: %s. '
            'The application will start without MongoDB support.',
            Config.MONGO_URI,
            exc,
        )
        _db = None
        _client = None  # a client that can't reach the server is as useless
        # as no client at all — callers of get_client() (e.g. app.py's
        # Flask-Session wiring) need a reliable "Mongo really is
        # reachable" signal, not just a MongoClient object that happens
        # to exist but will raise on first real use.


def _ensure_indexes(db) -> None:
    """Create unique and search indexes for `rules` and `decoders`."""
    # One-time cleanup: earlier versions indexed a `source_file` field that
    # was never actually written by any save/pull/push code path (the real
    # field has always been `filename`). Drop the dead index if present so
    # it doesn't linger and confuse future readers of the index list.
    for coll_name, idx_name in (('rules', 'idx_rule_source_file'),
                                 ('decoders', 'idx_decoder_source_file')):
        try:
            db[coll_name].drop_index(idx_name)
            logger.info('[MongoDB] Dropped deprecated index %s.%s', coll_name, idx_name)
        except errors.OperationFailure:
            pass  # index didn't exist — nothing to clean up

    try:
        # ── rules ──────────────────────────────────────────────────────
        db.rules.create_index(
            [('rule_id', ASCENDING)],
            unique=True,
            name='idx_rule_id_unique',
        )
        db.rules.create_index(
            [('description', ASCENDING)],
            name='idx_rule_description',
        )
        db.rules.create_index(
            [('groups', ASCENDING)],
            name='idx_rule_groups',
        )
        db.rules.create_index(
            [('level', ASCENDING)],
            name='idx_rule_level',
        )
        db.rules.create_index(
            [('filename', ASCENDING)],
            name='idx_rule_filename',
        )
        db.rules.create_index(
            [('sync_status', ASCENDING)],
            name='idx_rule_sync_status',
        )
        # [Phase C, 24 Agustus 2026] Index lama di atas DIPERTAHANKAN
        # (bukan dihapus) -- dokumen yang belum dimigrasi (lihat
        # migrate_sync_fields_to_env_state) masih punya field flat itu
        # sebagai arsip. Index baru untuk query yang sekarang jadi
        # jalur utama: promotion_utils's conflict-check
        # (sync_state.prod.sync_status) dan dev-synced guard
        # (sync_state.dev.sync_status), serta get_sync_overview's
        # aggregation per environment.
        db.rules.create_index(
            [('sync_state.dev.sync_status', ASCENDING)],
            name='idx_rule_sync_state_dev_status',
        )
        db.rules.create_index(
            [('sync_state.prod.sync_status', ASCENDING)],
            name='idx_rule_sync_state_prod_status',
        )

        # ── decoders ───────────────────────────────────────────────────
        db.decoders.create_index(
            [('name', ASCENDING)],
            # unique=True,
            name='idx_decoder_name_unique',
        )
        db.decoders.create_index(
            [('parent', ASCENDING)],
            name='idx_decoder_parent',
        )
        db.decoders.create_index(
            [('filename', ASCENDING)],
            name='idx_decoder_filename',
        )
        db.decoders.create_index(
            [('sync_status', ASCENDING)],
            name='idx_decoder_sync_status',
        )
        # [Phase C] Sama seperti rules di atas.
        db.decoders.create_index(
            [('sync_state.dev.sync_status', ASCENDING)],
            name='idx_decoder_sync_state_dev_status',
        )
        db.decoders.create_index(
            [('sync_state.prod.sync_status', ASCENDING)],
            name='idx_decoder_sync_state_prod_status',
        )

        # ── users ──────────────────────────────────────────────────────
        db.users.create_index(
            [('username', ASCENDING)],
            unique=True,
            name='idx_user_username_unique',
        )

        # ── rule_history / decoder_history (Phase 3 versioning) ─────────
        # Compound unique index on (identity, version_number) is a
        # storage-layer safety net against a race producing two entries
        # with the same version number for the same rule/decoder group
        # (e.g. two near-simultaneous saves both reading the same
        # "latest version" before either insert lands) — should be rare
        # given this is a small internal-tool user base, but cheap
        # insurance since history is meant to be a trustworthy audit
        # trail, not just a best-effort log.
        db.rule_history.create_index(
            [('rule_id', ASCENDING), ('version_number', ASCENDING)],
            unique=True,
            name='idx_rule_history_rule_version_unique',
        )
        db.rule_history.create_index(
            [('rule_id', ASCENDING), ('changed_at', ASCENDING)],
            name='idx_rule_history_rule_changed_at',
        )
        db.decoder_history.create_index(
            [('filename', ASCENDING), ('name', ASCENDING), ('version_number', ASCENDING)],
            unique=True,
            name='idx_decoder_history_group_version_unique',
        )
        db.decoder_history.create_index(
            [('filename', ASCENDING), ('name', ASCENDING), ('changed_at', ASCENDING)],
            name='idx_decoder_history_group_changed_at',
        )

        # ── manager_actions (restart audit log) ──────────────────────────
        db.manager_actions.create_index(
            [('triggered_at', ASCENDING)],
            name='idx_manager_actions_triggered_at',
        )

        # ── tech_stack (Phase E: inventaris infrastruktur) ───────────────
        # Query utama di masa depan: cari semua item yang cocok dengan
        # product/vendor CVE (filter relevansi sebelum LLM) -- index di
        # (vendor, product) supaya pencarian itu tidak full-scan.
        db.tech_stack.create_index(
            [('vendor', ASCENDING), ('product', ASCENDING)],
            name='idx_tech_stack_vendor_product',
        )

        # ── kev_catalog (Phase F: katalog vendor/product dari feed KEV) ──
        # Sumber dropdown di form Tech Stack. Unik per (vendor, product) --
        # sync berikutnya tinggal coba insert dan yang duplikat gagal
        # ordered=False (idempotent, tidak pernah menghapus entri lama).
        db.kev_catalog.create_index(
            [('vendor', ASCENDING), ('product', ASCENDING)],
            unique=True,
            name='idx_kev_catalog_vendor_product_unique',
        )

        # ── ai_proposals (Phase F: usulan draft rule dari AI) ────────────
        # Append-only secara praktik: status berubah pending -> dismissed,
        # tapi dokumennya tidak pernah dihapus (jejak audit keputusan).
        # Index untuk listing (terbaru dulu) + dedup per CVE.
        db.ai_proposals.create_index(
            [('created_at', ASCENDING)],
            name='idx_ai_proposals_created_at',
        )
        # UNIQUE per cve_id TAPI HANYA untuk status 'pending' (partial index).
        # Satu CVE = satu usulan yang menunggu review. Jaring pengaman di
        # storage layer terhadap dua run scheduler yang berjalan bersamaan
        # (mis. multi-worker) -- dedup aplikasi (baca-lalu-insert) rentan race.
        #
        # Kenapa PARTIAL, bukan unique penuh: fix dedup (29 Sep) sengaja
        # mengizinkan CVE yang sudah 'dismissed' diusulkan ULANG. Unique penuh
        # akan menolak insert itu, sehingga CVE yang pernah di-dismiss tetap
        # terkunci selamanya -- bertentangan dengan dedup aplikasi. Dengan
        # partial filter, dokumen dismissed tetap tersimpan (jejak audit) dan
        # usulan pending baru untuk CVE yang sama tetap boleh.
        db.ai_proposals.create_index(
            [('cve_id', ASCENDING)],
            unique=True,
            partialFilterExpression={'status': 'pending'},
            name='idx_ai_proposals_pending_cve_unique',
        )
        # Migrasi dari versi sebelumnya: unique penuh per cve_id tidak lagi
        # dipakai (lihat alasan di atas). Drop kalau masih ada, kalau tidak
        # index lama akan menolak usulan ulang.
        try:
            existing_names = set(db.ai_proposals.index_information().keys())
            if 'idx_ai_proposals_cve_id_unique' in existing_names:
                db.ai_proposals.drop_index('idx_ai_proposals_cve_id_unique')
                logger.info('[MongoDB] Dropped superseded index ai_proposals.idx_ai_proposals_cve_id_unique')
        except Exception as exc:  # noqa: BLE001 -- migrasi best-effort
            logger.warning('[MongoDB] Gagal drop index ai_proposals lama: %s', exc)

        logger.info('[MongoDB] Indexes verified.')
    except errors.OperationFailure as exc:
        logger.warning('[MongoDB] Index creation warning: %s', exc)


# ── Collection helpers ─────────────────────────────────────────────────

class AppendOnlyCollection:
    """
    Proxy pymongo Collection dengan jaminan STORAGE-LAYER bahwa isi
    koleksi tidak bisa diedit/dihapus lewat aplikasi ini.

    Latar belakang (Phase 5 hardening, 4 September 2026): semua jalur
    tulis ke `rule_history`/`decoder_history`/`manager_actions` saat ini
    murni `insert_one` (lihat services/history_utils.py dan api.py's
    _log_manager_action). Guard ini mengunci kenyataan itu DI TINGKAT
    KOLEKSI: operasi mutasi (update/delete/replace/find_one_and_*/
    drop/rename/bulk_write) melempar RuntimeError, sementara baca dan
    `insert_one` tetap jalan normal. Dengan begitu, route baru di masa
    depan yang (sengaja atau tidak) mencoba update/delete langsung ke
    koleksi audit log akan GAGAL TERANG-TERANGAN, bukan diam-diam
    menambal sejarah.

    TIDAK berpengaruh ke operasi internal pymongo yang sah:
    `_ensure_indexes()` membuat index lewat object db mentah (bukan
    getter ini), dan `insert_one` memang diizinkan.
    """

    _BLOCKED_MUTATORS = frozenset({
        'update_one', 'update_many', 'replace_one',
        'delete_one', 'delete_many',
        'find_one_and_update', 'find_one_and_delete', 'find_one_and_replace',
        'drop', 'rename', 'bulk_write',
    })

    def __init__(self, collection):
        self._collection = collection

    def __getattr__(self, name):
        if name in self._BLOCKED_MUTATORS:
            def _blocked(*args, **kwargs):
                raise RuntimeError(
                    f"Koleksi '{self._collection.name}' bersifat append-only — "
                    f"operasi '{name}' diblokir oleh Phase 5 hardening."
                )
            return _blocked
        return getattr(self._collection, name)


class NoDeleteCollection:
    """
    Seperti AppendOnlyCollection, TAPI mengizinkan `update_one`/`update_many`
    (transisi status workflow yang sah) sambil tetap memblokir SEMUA operasi
    delete (delete_one/delete_many/find_one_and_delete/drop/rename).

    Dipakai untuk `promotion_requests`: approve/reject WAZIB bisa
    meng-update status (pending → approved/rejected, dicatat siapa/kapan),
    tapi request yang sudah dibuat tidak boleh pernah DIHAPUS — histori
    keputusan 4-eyes adalah bagian dari audit trail.
    """

    _BLOCKED_MUTATORS = frozenset({
        'delete_one', 'delete_many', 'find_one_and_delete',
        'drop', 'rename', 'bulk_write',
    })

    def __init__(self, collection):
        self._collection = collection

    def __getattr__(self, name):
        if name in self._BLOCKED_MUTATORS:
            def _blocked(*args, **kwargs):
                raise RuntimeError(
                    f"Koleksi '{self._collection.name}' tidak boleh dihapus — "
                    f"operasi '{name}' diblokir oleh Phase 5 hardening."
                )
            return _blocked
        return getattr(self._collection, name)


def get_rules_collection():
    """Return the `rules` collection, or None if DB is unavailable."""
    db = get_db()
    return db.rules if db is not None else None


def get_decoders_collection():
    """Return the `decoders` collection, or None if DB is unavailable."""
    db = get_db()
    return db.decoders if db is not None else None


def get_users_collection():
    """Return the `users` collection, or None if DB is unavailable."""
    db = get_db()
    return db.users if db is not None else None


def get_rule_history_collection():
    """Return the append-only `rule_history` collection, or None if DB
    is unavailable. See services/history_utils.py. Dibungkus
    AppendOnlyCollection — update/delete apa pun terhadap koleksi ini
    melempar RuntimeError (Phase 5 hardening)."""
    db = get_db()
    return AppendOnlyCollection(db.rule_history) if db is not None else None


def get_decoder_history_collection():
    """Return the append-only `decoder_history` collection, or None if
    DB is unavailable. See services/history_utils.py. Dibungkus
    AppendOnlyCollection — update/delete apa pun melempar RuntimeError
    (Phase 5 hardening)."""
    db = get_db()
    return AppendOnlyCollection(db.decoder_history) if db is not None else None


def get_manager_actions_collection():
    """Return the append-only `manager_actions` audit-log collection
    (Wazuh Manager operations that aren't rule/decoder content changes,
    e.g. restart), or None if DB is unavailable. See blueprints/api.py's
    _log_manager_action(). Dibungkus AppendOnlyCollection — update/delete
    apa pun melempar RuntimeError (Phase 5 hardening)."""
    db = get_db()
    return AppendOnlyCollection(db.manager_actions) if db is not None else None


def get_promotion_requests_collection():
    """Return the `promotion_requests` collection (Phase B: 4-eyes
    approval workflow), or None if DB is unavailable. See
    services/promotion_utils.py. Dibungkus NoDeleteCollection — update
    status (approve/reject) sah, tapi delete apa pun melempar
    RuntimeError (Phase 5 hardening)."""
    db = get_db()
    return NoDeleteCollection(db.promotion_requests) if db is not None else None


def get_tech_stack_collection():
    """Return the `tech_stack` collection (Phase E: tech/infrastructure
    inventory for CVE/KEV filtering and rule context), or None if DB is
    unavailable. See services/tech_stack_utils.py."""
    db = get_db()
    return db.tech_stack if db is not None else None


def get_kev_catalog_collection():
    """Return the `kev_catalog` collection (Phase F: unique vendor/product
    pairs synced from the external KEV feed; powers the Tech Stack
    dropdowns), or None if DB is unavailable. See services/kev_utils.py."""
    db = get_db()
    return db.kev_catalog if db is not None else None


def get_ai_proposals_collection():
    """Return the `ai_proposals` collection (Phase F: AI-generated rule
    drafts awaiting human review), or None if DB is unavailable. See
    services/ai_utils.py. Dibungkus NoDeleteCollection -- status berubah
    (pending -> dismissed) sah, tapi usulan tidak pernah dihapus supaya
    jejak keputusan tetap utuh."""
    db = get_db()
    return NoDeleteCollection(db.ai_proposals) if db is not None else None


# ── Phase C migration: single-manager sync fields -> per-env sync_state ──

def migrate_sync_fields_to_env_state(target_env: str = 'prod') -> dict:
    """
    Migrasi SATU KALI, non-destruktif: salin field flat lama
    (sync_status/last_synced_hash/last_synced_at) di setiap dokumen
    `rules`/`decoders` ke `sync_state.<target_env>.*` (lihat
    services/sync_utils.py's env_sync_state_set_fields).

    target_env default 'prod' karena manager tunggal yang sudah ada
    SEBELUM Phase C secara fungsional berlaku sebagai Prod (di situ gate
    4-eyes Phase B dipasang) -- lihat LARAS_ROADMAP.md Phase C. Dokumen
    yang sudah punya sync_state[target_env] DILEWATI (idempotent, aman
    dijalankan berkali-kali tanpa menimpa data yang sudah dimigrasi).

    TIDAK menghapus field flat lama -- scaffold Phase C sengaja
    menjalankan struktur baru PARALEL dengan yang lama (lihat komentar di
    sync_utils.py) sampai semua endpoint/frontend selesai dipindah ke
    sync_state sepenuhnya. `sync_state.dev` TIDAK diisi oleh migrasi ini
    sama sekali -- itu memang belum pernah ada sebelum Phase C, jadi
    default kosong (SYNC_STATUS_NEW) dari get_env_sync_state() sudah
    benar untuk semua rule/decoder yang belum pernah di-push ke Dev.

    Dipanggil manual (bukan otomatis saat startup) -- migrasi data,
    sekecil apapun, sebaiknya dijalankan sadar oleh operator, bukan
    diam-diam setiap kali app start. Contoh pemakaian dari shell Python:

        from database import migrate_sync_fields_to_env_state
        migrate_sync_fields_to_env_state('prod')

    Return: {'rules_migrated': int, 'decoders_migrated': int, 'skipped': int}
    """
    from datetime import datetime, timezone  # local import: dipakai hanya di sini

    if target_env not in ('dev', 'prod'):
        raise ValueError(f"target_env harus 'dev' atau 'prod', diterima: {target_env!r}")

    db = get_db()
    if db is None:
        return {'error': 'MongoDB tidak tersedia.'}

    result = {'rules_migrated': 0, 'decoders_migrated': 0, 'skipped': 0}

    for col_name, counter_key in (('rules', 'rules_migrated'), ('decoders', 'decoders_migrated')):
        col = db[col_name]
        cursor = col.find(
            {f'sync_state.{target_env}': {'$exists': False}},
            {'sync_status': 1, 'last_synced_hash': 1, 'last_synced_at': 1},
        )
        for doc in cursor:
            # Dokumen yang belum pernah disentuh fitur sync sama sekali
            # (mis. rule baru yang belum pernah di-save lewat wizard,
            # kalau ada) tidak punya sync_status flat sama sekali --
            # skip, biarkan default SYNC_STATUS_NEW dari
            # get_env_sync_state() yang berlaku, tidak perlu ditulis
            # eksplisit.
            if 'sync_status' not in doc:
                result['skipped'] += 1
                continue

            col.update_one(
                {'_id': doc['_id']},
                {'$set': {
                    f'sync_state.{target_env}.sync_status': doc.get('sync_status'),
                    f'sync_state.{target_env}.last_synced_hash': doc.get('last_synced_hash'),
                    f'sync_state.{target_env}.last_synced_at': doc.get('last_synced_at'),
                }},
            )
            result[counter_key] += 1

    logger.info(
        '[Migration] sync_state.%s: %d rules, %d decoders dimigrasi, %d dilewati (belum pernah sync).',
        target_env, result['rules_migrated'], result['decoders_migrated'], result['skipped'],
    )
    return result