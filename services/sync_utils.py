"""
services/sync_utils.py
Helpers for tracking sync state between MongoDB rule/decoder documents
and the actual rule/decoder files on the Wazuh Manager.

Because rules and decoders are stored in a *structured* (parsed) form
rather than as raw XML, drift/conflict detection is based on a hash of
the structural fields the parser understands — not on the generated
XML text, which can vary cosmetically (attribute order, indentation)
between runs without any semantic change.

  rule_content_hash(doc)     -> str   (sha256 hex digest)
  decoder_content_hash(doc)  -> str   (sha256 hex digest)
  resolve_sync_status(...)   -> str   (one of SYNC_STATUS_*)
"""

from __future__ import annotations

import hashlib
import json

# ── Sync status values ──────────────────────────────────────────────────

SYNC_STATUS_NEW = 'new'                    # created in-app, never synced
SYNC_STATUS_SYNCED = 'synced'              # matches the last known server state
SYNC_STATUS_MODIFIED_LOCAL = 'modified_local'  # edited in-app since last sync, not yet pushed
SYNC_STATUS_CONFLICT = 'conflict'          # both local and server changed since last sync

# ── Which fields count as "content" for hashing ─────────────────────────
#
# Deliberately EXCLUDES bookkeeping fields (_id, filename, origin,
# ruleset_type, content_hash, last_synced_hash, last_synced_at,
# sync_status, updated_at) so that syncing itself never changes the hash.
# Also EXCLUDES `_wrapper_group` (the enclosing <group name="..."> a rule
# was found under) — that's file-layout metadata for XML reconstruction,
# not rule content; including it would flag a rule as "modified" purely
# because it got moved into a differently-named wrapper file.
# `_unparsed_tags` IS included: if an XML element the parser doesn't
# understand appears/disappears/changes, that's a real content change
# even though we can't fully represent it.

_RULE_CONTENT_FIELDS = [
    'rule_id', 'level', 'frequency', 'timeframe', 'ignore', 'overwrite',
    'noalert', 'maxsize', 'description', 'info', 'info_type', 'decoded_as',
    'if_sid', 'if_group', 'if_level', 'if_matched_sid', 'if_matched_group',
    'match', 'match_type', 'match_negate', 'regex', 'regex_type',
    'fields', 'urls', 'static_fields', 'lists', 'time', 'same_srcip',
    'different_srcip', 'same_url', 'same_fields', 'group', 'mitre_ids',
    'options', '_unparsed_tags',
]

_DECODER_CONTENT_FIELDS = [
    'name', 'parent', 'type', 'program_name', 'program_name_type',
    'prematch', 'prematch_type', 'prematch_offset',
    'regex', 'regex_type', 'regex_offset',
    'order', 'fts', 'ftscomment', 'accumulate', 'use_own_name',
    '_unparsed_tags',
]

# Public aliases — services/history_utils.py snapshots exactly these same
# fields so "what counts as rule/decoder content" has one single
# definition, not two that could silently drift apart.
RULE_CONTENT_FIELDS = _RULE_CONTENT_FIELDS
DECODER_CONTENT_FIELDS = _DECODER_CONTENT_FIELDS


def _canonical(doc: dict, fields: list[str]) -> str:
    """
    Serialise only the given fields, in a deterministic (sorted-key)
    form, so semantically identical documents always hash the same way
    regardless of key insertion order or missing-vs-empty differences.
    """
    subset = {k: doc.get(k) for k in fields}
    return json.dumps(subset, sort_keys=True, default=str, ensure_ascii=False)


def rule_content_hash(doc: dict) -> str:
    """SHA-256 hex digest of a rule document's structural content."""
    return hashlib.sha256(_canonical(doc, _RULE_CONTENT_FIELDS).encode('utf-8')).hexdigest()


def decoder_content_hash(doc: dict) -> str:
    """SHA-256 hex digest of a decoder document's structural content."""
    return hashlib.sha256(_canonical(doc, _DECODER_CONTENT_FIELDS).encode('utf-8')).hexdigest()


# ── Sync status resolution ──────────────────────────────────────────────

def resolve_sync_status(
    current_hash: str,
    last_synced_hash: str | None,
    remote_hash: str | None = None,
) -> str:
    """
    Decide the sync_status for a document.

    Args:
      current_hash:      content hash of the document's current state in MongoDB.
      last_synced_hash:  content hash recorded at the last successful sync
                          (pull or push). None if this document has never
                          been synced with the server.
      remote_hash:        content hash of a *freshly pulled* server copy,
                          only pass this when actively re-pulling to check
                          for drift. Leave as None for a plain "did I edit
                          this since last sync?" check (e.g. right after
                          Save, with no pull involved).

    Returns one of SYNC_STATUS_NEW / SYNC_STATUS_SYNCED /
    SYNC_STATUS_MODIFIED_LOCAL / SYNC_STATUS_CONFLICT.

    Note: this function only *classifies* state — it never mutates
    documents or decides whether to auto-adopt the remote version.
    Callers should auto-adopt only when this returns SYNCED after a
    remote_hash changed (i.e. no local edits existed), and must NOT
    auto-overwrite on CONFLICT.
    """
    if last_synced_hash is None:
        return SYNC_STATUS_NEW

    local_dirty = current_hash != last_synced_hash

    if remote_hash is None:
        # No fresh pull to compare against — just report local edit state.
        return SYNC_STATUS_MODIFIED_LOCAL if local_dirty else SYNC_STATUS_SYNCED

    remote_changed = remote_hash != last_synced_hash

    if not remote_changed:
        # Server hasn't moved; local edit state alone decides.
        return SYNC_STATUS_MODIFIED_LOCAL if local_dirty else SYNC_STATUS_SYNCED

    # Server DID change since last sync.
    if not local_dirty:
        # Only the server changed -> safe to auto-adopt. Caller is
        # responsible for actually copying the remote fields into the
        # document and updating last_synced_hash/last_synced_at.
        return SYNC_STATUS_SYNCED

    # Both sides changed independently -> needs manual resolution.
    return SYNC_STATUS_CONFLICT


# ── Phase C: per-environment sync state (Dev/Prod) ──────────────────────
#
# [Tambahan 24 Agustus 2026] Dokumen rule/decoder sebelum Phase C punya
# SATU set field flat (content_hash/sync_status/last_synced_hash/
# last_synced_at) karena cuma ada SATU Wazuh Manager. Dengan Dev+Prod
# terpisah, status sync harus dilacak PER ENVIRONMENT -- satu rule bisa
# saja sudah synced ke Dev tapi belum pernah di-push ke Prod sama sekali.
#
# `content_hash` TETAP flat (bukan per-environment) -- itu properti
# konten lokal itu sendiri, tidak tergantung ke server mana dia
# dibandingkan.
#
# Struktur baru pada dokumen:
#   sync_state: {
#       "dev":  {"last_synced_hash": str|None, "last_synced_at": datetime|None, "sync_status": str},
#       "prod": {"last_synced_hash": str|None, "last_synced_at": datetime|None, "sync_status": str},
#   }
#
# SENGAJA additive, bukan pengganti: field flat lama (sync_status,
# last_synced_hash, last_synced_at) TIDAK dihapus dari kode manapun di
# scaffold ini -- itu "jalankan paralel dengan yang lama" sesuai
# kesepakatan sebelum migrasi penuh (lihat LARAS_ROADMAP.md Phase C).
# Endpoint yang membaca/menulis sync_state (pull/push/diff/promote)
# menyusul di pesan berikutnya, bukan di scaffold ini.

ENVIRONMENTS = ('dev', 'prod')


def _validate_env(env: str) -> str:
    env = (env or '').lower()
    if env not in ENVIRONMENTS:
        raise ValueError(f"env harus salah satu dari {ENVIRONMENTS}, diterima: {env!r}")
    return env


def get_env_sync_state(doc: dict, env: str) -> dict:
    """
    Ambil sub-dict sync_state milik satu environment dari dokumen
    rule/decoder, dengan default yang aman kalau dokumen belum pernah
    disentuh fitur sync sama sekali untuk environment itu (dokumen dari
    sebelum Phase C, atau rule/decoder baru yang belum pernah di-push ke
    environment ini).
    """
    env = _validate_env(env)
    sync_state = doc.get('sync_state') or {}
    env_state = sync_state.get(env)
    if not env_state:
        return {'last_synced_hash': None, 'last_synced_at': None, 'sync_status': SYNC_STATUS_NEW}
    return env_state


def resolve_env_sync_status(doc: dict, env: str, current_hash: str, remote_hash: str | None = None) -> str:
    """
    Sama seperti resolve_sync_status(), tapi last_synced_hash diambil dari
    sync_state[env] milik dokumen -- pemanggil tidak perlu tahu struktur
    sync_state secara langsung, cukup kasih dokumen + environment mana
    yang dicek.
    """
    env_state = get_env_sync_state(doc, env)
    return resolve_sync_status(current_hash, env_state.get('last_synced_hash'), remote_hash)


def env_sync_status_only(env: str, sync_status: str) -> dict:
    """
    Bikin dict `$set` yang HANYA mengubah sync_state[env].sync_status,
    TANPA menyentuh last_synced_hash/last_synced_at milik environment
    itu. Dipakai saat status berubah TANPA ada sinkronisasi nyata yang
    terjadi -- mis. saat SAVE/EDIT konten (bikin status jadi
    'modified_local' relatif ke snapshot terakhir yang synced, tapi
    "terakhir synced"-nya sendiri tidak berubah) -- beda dari
    env_sync_state_set_fields()/env_sync_state_nested() yang dipakai
    saat pull/push BENAR-BENAR terjadi (ketiga field berubah sekaligus).
    """
    env = _validate_env(env)
    return {f'sync_state.{env}.sync_status': sync_status}


def env_sync_state_set_fields(env: str, last_synced_hash: str | None, last_synced_at, sync_status: str) -> dict:
    """
    Bikin dict siap pakai untuk MongoDB `$set` yang meng-update HANYA
    sync_state[env] milik SATU environment, tanpa menyentuh environment
    lain di dokumen yang sama.

    PENTING kenapa ini pakai dot-notation per-field (bukan langsung
    `{'sync_state': {...}}`): `$set: {'sync_state': {...}}` MENGGANTI
    SELURUH sub-dokumen sync_state, termasuk data environment LAIN yang
    tidak dimaksud untuk diubah (mis. meng-update status Dev tidak
    boleh menghapus data status Prod yang sudah ada di dokumen yang
    sama). Dot-path (`sync_state.dev.sync_status`, dst) meng-update
    field itu saja, field lain di sync_state dibiarkan utuh -- ini
    berlaku bahkan untuk dokumen yang belum punya `sync_state` sama
    sekali (MongoDB otomatis membuat sub-dokumen yang diperlukan).

    ⚠️ HANYA aman dipakai di dalam operator `$set` pada update_one/
    update_many/find_one_and_update (termasuk saat upsert=True membuat
    dokumen baru lewat $set). JANGAN pernah pakai ini untuk insert_one/
    insert_many MENTAH (tanpa $set) -- di situ MongoDB TIDAK
    menginterpretasikan titik dalam nama field sebagai path nested,
    hasilnya field literal bernama "sync_state.dev.sync_status" (rusak,
    bukan struktur nested yang benar). Untuk insert mentah, pakai
    env_sync_state_nested() di bawah.
    """
    env = _validate_env(env)
    prefix = f'sync_state.{env}'
    return {
        f'{prefix}.last_synced_hash': last_synced_hash,
        f'{prefix}.last_synced_at': last_synced_at,
        f'{prefix}.sync_status': sync_status,
    }


def env_sync_state_nested(env: str, last_synced_hash: str | None, last_synced_at, sync_status: str) -> dict:
    """
    Versi NESTED (bukan dot-path) dari env_sync_state_set_fields() --
    untuk dipakai di insert_one/insert_many MENTAH (mis. decoder
    delete-then-reinsert di pull_selected/rollback_decoder/import), di
    mana MongoDB TIDAK menginterpretasikan titik di nama field secara
    spesial. Hasilnya: {'sync_state': {'<env>': {...}}}.

    Aman dipakai untuk dokumen BARU (fresh insert) yang memang belum
    punya environment lain terisi -- get_env_sync_state() di sync_utils
    sudah menangani environment yang belum ada sebagai SYNC_STATUS_NEW
    secara default, jadi tidak perlu isi placeholder untuk environment
    yang tidak sedang diproses saat insert ini.
    """
    env = _validate_env(env)
    return {
        'sync_state': {
            env: {
                'last_synced_hash': last_synced_hash,
                'last_synced_at': last_synced_at,
                'sync_status': sync_status,
            }
        }
    }