"""
blueprints/importer.py
File upload, XML-to-Mongo import, and XML export routes.

Routes:
  POST /importer/upload/rules     → upload rules XML file → parse → upsert to MongoDB
  POST /importer/upload/decoders  → upload decoders XML file → parse → upsert to MongoDB
  GET  /importer/export/rules     → export selected rules from MongoDB as XML file download
  GET  /importer/export/decoders  → export selected decoders from MongoDB as XML file download

Audit 24 Agustus 2026 — upload_rules()/upload_decoders() sebelumnya
menulis ke `rules`/`decoders` lewat bulk ReplaceOne yang:
  1. Tidak pernah memanggil record_rule_version/record_decoder_group_version
     ATAU set last_modified_by — import jadi satu-satunya write path yang
     sama sekali tidak tercatat di audit trail (bertentangan langsung
     dengan filosofi LARAS).
  2. ReplaceOne mengganti SELURUH dokumen (bukan $set sebagian) — karena
     parse_rule_xml/parse_decoder_xml tidak pernah mengisi content_hash/
     sync_status/last_synced_hash/origin, field-field itu HILANG setelah
     import, merusak fitur sync/push/promote untuk apapun yang pernah
     di-import.
  3. Decoder di-replace berdasarkan {'name': doc['name']} saja — persis
     anti-pattern yang sudah diketahui salah (lihat komentar di
     wazuh_api.py's pull_selected): sibling decoder yang berbagi `name`
     yang sama saling menimpa, cuma satu yang selamat.
  4. `filename` tidak pernah di-set sama sekali (parser tidak mengisinya —
     pemanggil yang wajib set, seperti pull_selected lakukan) — rule/
     decoder hasil import jadi tidak terlihat oleh fitur pull/push/diff
     yang mengelompokkan berdasarkan filename.

Diperbaiki dengan meniru pola yang SUDAH BENAR di wazuh_api.py's
pull_selected (rule: per-dokumen upsert dengan content_hash/sync_status
dihitung; decoder: delete-then-reinsert per file, karena sibling decoder
tidak punya identitas stabil untuk di-reconcile satu-satu) — TAPI pakai
change_source='import' (bukan 'pull') dan sync_status yang HONEST bahwa
konten ini belum tentu cocok dengan Wazuh Manager yang live (beda dari
pull yang datang dari server otoritatif).

Keputusan produk (24 Agustus 2026): kalau rule/decoder yang diimpor
sudah punya edit lokal yang belum di-push (sync_status modified_local
atau conflict) DAN kontennya beda dari yang mau diimpor, import untuk
item itu di-SKIP dan dilaporkan sebagai conflict — bukan ditimpa diam-
diam. Rule/decoder lain dalam file yang sama tetap diproses.
"""

from __future__ import annotations

import io
import logging

from flask import Blueprint, jsonify, request, send_file
from flask_login import current_user

from database import (
    get_decoders_collection, get_rules_collection,
    get_rule_history_collection, get_decoder_history_collection,
)
from services.xml_parser import (
    decoder_docs_to_xml_file,
    parse_decoder_xml,
    parse_rule_xml,
    rule_docs_to_xml_file,
)
from services.sync_utils import (
    rule_content_hash,
    decoder_content_hash,
    resolve_env_sync_status,
    env_sync_status_only,
    get_env_sync_state,
    SYNC_STATUS_CONFLICT,
    SYNC_STATUS_MODIFIED_LOCAL,
)
from services.history_utils import (
    record_rule_version,
    record_decoder_group_version,
    CHANGE_SOURCE_IMPORT,
)

logger = logging.getLogger(__name__)

importer_bp = Blueprint('importer', __name__)

# Max upload size — 4 MB
MAX_CONTENT_LENGTH = 4 * 1024 * 1024
ALLOWED_EXTENSIONS = {'xml'}


def _allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def _db_unavailable():
    return jsonify({'error': 'MongoDB is not available. Check your MONGO_URI.'}), 503


# ══════════════════════════════════════════════════════════════════════
# IMPORT routes
# ══════════════════════════════════════════════════════════════════════

@importer_bp.route('/upload/rules', methods=['POST'])
def upload_rules():
    """
    Accept multiple Wazuh rules XML files upload.
    Parse all <rule> elements from all files and upsert them into the
    `rules` collection — one document at a time (NOT a bulk ReplaceOne,
    see module docstring for why), computing content_hash/sync_status
    and recording history exactly like a wizard Save would.
    """
    col = get_rules_collection()
    hist_col = get_rule_history_collection()
    if col is None:
        return _db_unavailable()

    files = request.files.getlist('files')
    if not files or all(f.filename == '' for f in files):
        return jsonify({'error': 'No file provided.'}), 400

    imported = 0
    skipped = 0
    total_parsed = 0
    parse_errors: list[str] = []
    conflicts: list[dict] = []

    for file in files:
        if not file or not file.filename:
            continue

        if not _allowed_file(file.filename):
            parse_errors.append(f'{file.filename}: Only .xml files are accepted.')
            continue

        xml_bytes = file.read()
        if len(xml_bytes) > MAX_CONTENT_LENGTH:
            parse_errors.append(f'{file.filename}: File too large (max 4 MB).')
            continue

        try:
            docs = parse_rule_xml(xml_bytes.decode('utf-8', errors='replace'))
        except ValueError as exc:
            parse_errors.append(f'{file.filename}: XML parse error ({exc})')
            continue

        if not docs:
            parse_errors.append(f'{file.filename}: No valid <rule> elements found.')
            continue

        total_parsed += len(docs)

        for doc in docs:
            rule_id = doc.get('rule_id')
            try:
                if rule_id is None:
                    raise ValueError('rule_id tidak ditemukan di elemen <rule>.')

                # parse_rule_xml tidak mengisi `filename` — pemanggil yang
                # wajib set, sama seperti pull_selected lakukan. Nama file
                # yang diupload dipakai sebagai target, konsisten dengan
                # bagaimana pull_selected memakai nama file dari Wazuh
                # Manager sebagai `filename`.
                doc['filename'] = file.filename

                new_hash = rule_content_hash(doc)
                existing = col.find_one({'rule_id': rule_id}, {'content_hash': 1, 'sync_state': 1})

                # [Phase C, 24 Agustus 2026] Cek conflict terhadap KEDUA
                # environment -- ada edit lokal yang belum di-push ke
                # SALAH SATU (Dev atau Prod) sudah cukup alasan untuk
                # skip, supaya import tidak menimpa pekerjaan yang belum
                # disimpan ke manapun, terlepas environment mana yang
                # dituju edit itu.
                if existing is not None and existing.get('content_hash') != new_hash:
                    dev_status = get_env_sync_state(existing, 'dev').get('sync_status')
                    prod_status = get_env_sync_state(existing, 'prod').get('sync_status')
                    conflicting_envs = [
                        env for env, status in (('dev', dev_status), ('prod', prod_status))
                        if status in (SYNC_STATUS_MODIFIED_LOCAL, SYNC_STATUS_CONFLICT)
                    ]
                    if conflicting_envs:
                        conflicts.append({
                            'rule_id': rule_id,
                            'file': file.filename,
                            'reason': (
                                f'Rule {rule_id} punya edit lokal yang belum di-push ke '
                                f'{"/".join(conflicting_envs)}; import dilewati.'
                            ),
                        })
                        skipped += 1
                        continue

                existing_for_status = existing or {}
                doc['content_hash'] = new_hash
                doc['last_modified_by'] = current_user.username
                doc.update(env_sync_status_only('dev', resolve_env_sync_status(existing_for_status, 'dev', new_hash)))
                doc.update(env_sync_status_only('prod', resolve_env_sync_status(existing_for_status, 'prod', new_hash)))

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
                record_rule_version(
                    hist_col, doc, current_user.username, CHANGE_SOURCE_IMPORT,
                    commit_message=f'Import dari file {file.filename}',
                )
                imported += 1
            except Exception as exc:  # noqa: BLE001
                skipped += 1
                parse_errors.append(f'{file.filename} (Rule {rule_id if rule_id is not None else "?"}): {exc}')

    return jsonify({
        'imported': imported,
        'skipped': skipped,
        'total_parsed': total_parsed,
        'conflicts': conflicts,
        'errors': parse_errors,
    })


@importer_bp.route('/upload/decoders', methods=['POST'])
def upload_decoders():
    """
    Accept multiple Wazuh decoders XML files upload.

    Each uploaded file is treated as a full reset for its OWN filename
    target (delete-then-reinsert of every decoder currently stored under
    that filename) — same pattern pull_selected uses for decoders, and
    for the exact same reason: sibling decoders sharing a `name` have no
    stable per-document identity to reconcile one-by-one across an
    import, so a full swap is the only unambiguous way to land on the
    uploaded file's exact content. sync_status is 'new' (not 'synced')
    since — unlike a pull — there's no confirmation this matches what's
    actually live on the Wazuh Manager.

    Conflict handling: if any EXISTING decoder under a name in this file
    currently has unpushed local edits, importing anyway would silently
    discard those edits with no way to detect it after the fact (delete-
    then-reinsert has no per-sibling diff). So: if ANY name in this
    file is found in modified_local/conflict state, the WHOLE FILE's
    import is skipped and reported as a conflict — partial writes here
    would leave the group in a state that doesn't match either the old
    local edits or the new import, which is worse than skipping cleanly.
    """
    col = get_decoders_collection()
    hist_col = get_decoder_history_collection()
    if col is None:
        return _db_unavailable()

    files = request.files.getlist('files')
    if not files or all(f.filename == '' for f in files):
        return jsonify({'error': 'No file provided.'}), 400

    imported = 0
    skipped = 0
    total_parsed = 0
    parse_errors: list[str] = []
    conflicts: list[dict] = []

    for file in files:
        if not file or not file.filename:
            continue

        if not _allowed_file(file.filename):
            parse_errors.append(f'{file.filename}: Only .xml files are accepted.')
            continue

        xml_bytes = file.read()
        if len(xml_bytes) > MAX_CONTENT_LENGTH:
            parse_errors.append(f'{file.filename}: File too large (max 4 MB).')
            continue

        try:
            docs = parse_decoder_xml(xml_bytes.decode('utf-8', errors='replace'))
        except ValueError as exc:
            parse_errors.append(f'{file.filename}: XML parse error ({exc})')
            continue

        if not docs:
            parse_errors.append(f'{file.filename}: No valid <decoder> elements found.')
            continue

        total_parsed += len(docs)
        target_filename = file.filename

        try:
            names_in_upload = {d['name'] for d in docs if d.get('name')}

            # Conflict check BEFORE touching anything — see docstring for
            # why this is whole-file, not per-sibling. [Phase C] Cek
            # KEDUA environment -- sibling yang modified_local/conflict
            # di Dev ATAU Prod sudah cukup alasan untuk skip seluruh file.
            conflicted_names = []
            for name in names_in_upload:
                siblings = list(col.find({'filename': target_filename, 'name': name},
                                          {'sync_state': 1}))
                for sib in siblings:
                    dev_status = get_env_sync_state(sib, 'dev').get('sync_status')
                    prod_status = get_env_sync_state(sib, 'prod').get('sync_status')
                    if dev_status in (SYNC_STATUS_MODIFIED_LOCAL, SYNC_STATUS_CONFLICT) or \
                       prod_status in (SYNC_STATUS_MODIFIED_LOCAL, SYNC_STATUS_CONFLICT):
                        conflicted_names.append(name)
                        break

            if conflicted_names:
                conflicts.append({
                    'file': file.filename,
                    'names': sorted(set(conflicted_names)),
                    'reason': (
                        f'File "{file.filename}" berisi decoder dengan edit lokal yang belum '
                        f'di-push ({", ".join(sorted(set(conflicted_names)))}); import untuk seluruh '
                        f'file ini dilewati.'
                    ),
                })
                skipped += len(docs)
                continue

            names_before = set(col.distinct('name', {'filename': target_filename}))
            col.delete_many({'filename': target_filename})

            names_in_file = set()
            for seq, d in enumerate(docs):
                d['filename'] = target_filename
                d['_seq'] = seq
                d['origin'] = 'app_created'
                d['ruleset_type'] = 'custom'
                d['content_hash'] = decoder_content_hash(d)
                # [Phase C, 24 Agustus 2026] TIDAK set sync_state sama
                # sekali -- field absen otomatis berarti SYNC_STATUS_NEW
                # untuk KEDUA environment (lihat get_env_sync_state()'s
                # default), status yang jujur untuk decoder hasil
                # delete-then-reinsert (sama alasannya dengan
                # rollback_decoder di builder.py). insert_many() di bawah
                # TIDAK lewat $set -- kalau perlu diisi eksplisit, WAJIB
                # env_sync_state_nested(), bukan dot-path.
                d['last_modified_by'] = current_user.username
                names_in_file.add(d.get('name'))
            col.insert_many(docs)
            imported += len(docs)

            for name in names_before | names_in_file:
                if not name:
                    continue
                record_decoder_group_version(
                    hist_col, col, target_filename, name, current_user.username,
                    CHANGE_SOURCE_IMPORT, commit_message=f'Import dari file {file.filename}',
                )
        except Exception as exc:  # noqa: BLE001
            skipped += len(docs)
            parse_errors.append(f'{file.filename}: {exc}')

    return jsonify({
        'imported': imported,
        'skipped': skipped,
        'total_parsed': total_parsed,
        'conflicts': conflicts,
        'errors': parse_errors,
    })


# ══════════════════════════════════════════════════════════════════════
# EXPORT routes
# ══════════════════════════════════════════════════════════════════════

@importer_bp.route('/export/rules', methods=['GET'])
def export_rules():
    """
    Export rules from MongoDB as a downloadable XML file.

    Query params:
      ids   : comma-separated list of rule_id integers to export (optional).
              If omitted, all rules are exported.
      group : group name to use as the <group name="..."> wrapper attribute
              (default: "custom,").
    """
    col = get_rules_collection()
    if col is None:
        return _db_unavailable()

    ids_param = request.args.get('ids', '').strip()
    group_name = request.args.get('group', 'custom').strip()

    query: dict = {}
    if ids_param:
        try:
            id_list = [int(i.strip()) for i in ids_param.split(',') if i.strip()]
            query = {'rule_id': {'$in': id_list}}
        except ValueError:
            return jsonify({'error': 'ids must be comma-separated integers.'}), 400

    docs = list(col.find(query, {'_id': 0}))
    if not docs:
        return jsonify({'error': 'No rules found for the given criteria.'}), 404

    try:
        xml_content = rule_docs_to_xml_file(group_name, docs)
    except Exception as exc:  # noqa: BLE001
        logger.exception('Export rules error')
        return jsonify({'error': str(exc)}), 500

    buffer = io.BytesIO(xml_content.encode('utf-8'))
    return send_file(
        buffer,
        mimetype='application/xml',
        as_attachment=True,
        download_name='wazuh_rules_export.xml',
    )


@importer_bp.route('/export/decoders', methods=['GET'])
def export_decoders():
    """
    Export decoders from MongoDB as a downloadable XML file.

    Query params:
      names : comma-separated decoder names to export (optional).
              If omitted, all decoders are exported.
    """
    col = get_decoders_collection()
    if col is None:
        return _db_unavailable()

    names_param = request.args.get('names', '').strip()

    query: dict = {}
    if names_param:
        name_list = [n.strip() for n in names_param.split(',') if n.strip()]
        query = {'name': {'$in': name_list}}

    docs = list(col.find(query, {'_id': 0}))
    if not docs:
        return jsonify({'error': 'No decoders found for the given criteria.'}), 404

    try:
        xml_content = decoder_docs_to_xml_file(docs)
    except Exception as exc:  # noqa: BLE001
        logger.exception('Export decoders error')
        return jsonify({'error': str(exc)}), 500

    buffer = io.BytesIO(xml_content.encode('utf-8'))
    return send_file(
        buffer,
        mimetype='application/xml',
        as_attachment=True,
        download_name='wazuh_decoders_export.xml',
    )