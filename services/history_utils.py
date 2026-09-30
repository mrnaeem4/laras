"""
services/history_utils.py
Append-only version history for rules and decoders (Phase 3 of the
versioning roadmap).

Design:
  - rule_history:    one entry per rule_id per actual content change.
    rule_id is stable (Wazuh's own numeric id), so this is a direct
    1:1 identity match — no ambiguity.
  - decoder_history: one entry per (filename, name) GROUP per actual
    content change. Wazuh's "sibling decoders" (see
    xml_parser.parse_decoder_xml) let several <decoder> elements share
    one `name`; per explicit decision, decoder version history is
    tracked at the (filename, name) level, not per individual sibling
    document — a version snapshot is the full ordered list of sibling
    decoders under that name at that point in time. This also sidesteps
    individual decoder `_id` being unstable across pulls (pull_selected
    does a full delete+reinsert per file), which would otherwise make
    per-document history impossible to keep contiguous.

Both collections are pure inserts from this module's perspective —
records are appended, never updated or deleted here — so a document's
live row in `rules`/`decoders` can be edited, overwritten, or removed
entirely without losing its past states. Deleting a rule/decoder group
does not delete its history; see record_rule_deletion and the
change_source='deleted' path for decoders below.

A new version is only appended when content actually changed (compared
by content_hash against the latest recorded version) — a no-op save
(e.g. clicking Save without editing anything) does not create a
version entry.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from services.sync_utils import RULE_CONTENT_FIELDS, DECODER_CONTENT_FIELDS

CHANGE_SOURCE_APP_EDIT = 'app_edit'
CHANGE_SOURCE_PULL = 'pull'
CHANGE_SOURCE_DELETED = 'deleted'
CHANGE_SOURCE_ROLLBACK = 'rollback'
# [Tambahan 24 Agustus 2026] Terpisah dari CHANGE_SOURCE_PULL secara
# sengaja — pull berasal dari Wazuh Manager yang otoritatif (makanya pull
# menandai sync_status='synced'), sedangkan import berasal dari file XML
# yang diupload user (bisa dari mana saja — backup lama, share dari orang
# lain, dsb) yang BELUM tentu cocok dengan apa yang live di Wazuh Manager
# saat ini. Membedakan change_source di sini penting untuk audit trail:
# analyst yang lihat history harus bisa bedakan "ini datang dari server
# yang terverifikasi" vs "ini datang dari file yang diupload seseorang".
CHANGE_SOURCE_IMPORT = 'import'


def _snapshot(doc: dict, fields: list[str]) -> dict:
    return {k: doc.get(k) for k in fields}


def _hash_snapshot(snapshot) -> str:
    return hashlib.sha256(
        json.dumps(snapshot, sort_keys=True, default=str, ensure_ascii=False).encode('utf-8')
    ).hexdigest()


# ── Rules ────────────────────────────────────────────────────────────

def record_rule_version(history_col, rule_doc: dict, changed_by: str, change_source: str,
                         commit_message: str | None = None) -> dict | None:
    """
    Append a new rule_history entry for rule_doc['rule_id'] IF its
    content differs from the latest recorded version. Returns the
    inserted entry, or None if nothing changed or history_col/rule_id
    is unavailable (never raises for a missing history collection —
    versioning is additive, its absence should never block a save).

    commit_message is a free-text note the person typed when saving
    (e.g. "Add SSH brute force detection") — distinct from
    change_source, which is the mechanical origin of the change
    (app_edit/pull/rollback/deleted). change_source answers "how did
    this change happen"; commit_message answers "why", same distinction
    a git commit's metadata vs its message makes. None/empty is stored
    as None, not '' — callers rendering history fall back to
    change_source's label when there's no message.
    """
    if history_col is None:
        return None
    rule_id = rule_doc.get('rule_id')
    if rule_id is None:
        return None

    snapshot = _snapshot(rule_doc, RULE_CONTENT_FIELDS)
    content_hash = _hash_snapshot(snapshot)

    latest = history_col.find_one({'rule_id': rule_id}, sort=[('version_number', -1)])
    if latest is not None and latest.get('content_hash') == content_hash:
        return None  # no real change — don't pollute history with a no-op save

    entry = {
        'rule_id': rule_id,
        # Bookkeeping, NOT part of the content-hash snapshot (filename is
        # excluded from RULE_CONTENT_FIELDS by design — see sync_utils.py).
        # Tracked here anyway so Phase 4's rollback can still know which
        # file to restore a rule into after it's been fully deleted from
        # `rules` (at which point the live document — the only other
        # place filename lived — is gone).
        'filename': rule_doc.get('filename'),
        'version_number': (latest['version_number'] + 1) if latest else 1,
        'snapshot': snapshot,
        'content_hash': content_hash,
        'change_source': change_source,
        'commit_message': (commit_message or '').strip() or None,
        'changed_by': changed_by,
        'changed_at': datetime.now(timezone.utc),
    }
    history_col.insert_one(entry)
    return entry


def record_rule_deletion(history_col, rule_id: int, changed_by: str, commit_message: str | None = None) -> dict | None:
    """
    Append a tombstone entry marking rule_id as deleted, so its history
    stays queryable (GET /rule/<id>/history) even after the live
    document is gone from `rules`. Safe to call even if this rule_id
    never had any prior history (e.g. deleted right after creation
    without a version ever being recorded some other way — shouldn't
    normally happen since save_rule always records one, but this
    doesn't assume it did).
    """
    if history_col is None:
        return None
    latest = history_col.find_one({'rule_id': rule_id}, sort=[('version_number', -1)])
    entry = {
        'rule_id': rule_id,
        'filename': latest.get('filename') if latest else None,
        'version_number': (latest['version_number'] + 1) if latest else 1,
        'snapshot': latest.get('snapshot') if latest else None,
        'content_hash': latest.get('content_hash') if latest else None,
        'change_source': CHANGE_SOURCE_DELETED,
        'commit_message': (commit_message or '').strip() or None,
        'changed_by': changed_by,
        'changed_at': datetime.now(timezone.utc),
    }
    history_col.insert_one(entry)
    return entry


# ── Decoders ─────────────────────────────────────────────────────────

def record_decoder_group_version(history_col, decoders_col, filename: str, name: str,
                                  changed_by: str, change_source: str,
                                  commit_message: str | None = None) -> dict | None:
    """
    Re-read the CURRENT full sibling group for (filename, name) from the
    live `decoders` collection and append a new decoder_history entry IF
    it differs from the latest recorded version for that group.

    Always re-reads the live group rather than snapshotting just the one
    document that triggered the call — a version here represents "the
    decoder(s) called `name` in `filename`" as a whole (see module
    docstring). This naturally handles every case with one code path:
      - editing one sibling -> group re-read, snapshot changes
      - deleting one sibling out of several -> group re-read, snapshot
        shrinks by one entry
      - deleting the LAST sibling -> group re-read finds none, snapshot
        becomes [] -> acts as the "deleted" tombstone automatically, no
        separate deletion function needed (unlike rules, which have no
        natural "empty list" state to fall back to).
    Ordered by `_seq` (position in the last-pulled file) when present,
    so the snapshot's sibling order is deterministic and matches how
    the file would actually be rebuilt — see xml_parser.parse_decoder_xml.

    commit_message: see record_rule_version's docstring — same free-text
    "why" note, stored alongside this group version if provided. Since
    one save only ever touches ONE sibling but this records the whole
    group's state, the message describes the save action that triggered
    this snapshot, not necessarily every sibling in it.
    """
    if history_col is None or decoders_col is None:
        return None

    siblings = list(decoders_col.find({'filename': filename, 'name': name}).sort('_seq', 1))
    snapshot = [_snapshot(d, DECODER_CONTENT_FIELDS) for d in siblings]
    content_hash = _hash_snapshot(snapshot)

    latest = history_col.find_one({'filename': filename, 'name': name}, sort=[('version_number', -1)])
    if latest is not None and latest.get('content_hash') == content_hash:
        return None

    entry = {
        'filename': filename,
        'name': name,
        'version_number': (latest['version_number'] + 1) if latest else 1,
        'snapshot': snapshot,
        'content_hash': content_hash,
        'change_source': change_source,
        'commit_message': (commit_message or '').strip() or None,
        'changed_by': changed_by,
        'changed_at': datetime.now(timezone.utc),
    }
    history_col.insert_one(entry)
    return entry