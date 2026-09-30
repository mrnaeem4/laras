"""
services/promotion_utils.py
4-eyes approval workflow untuk push rule/decoder ke Wazuh Manager
(single manager untuk saat ini — lihat LARAS_ROADMAP.md Phase B).

Desain:
  - Promotion request adalah koleksi TERPISAH (`promotion_requests`),
    BUKAN field yang ditempel ke tiap dokumen rule/decoder — satu
    request mencakup satu BATCH filename (sama seperti push_selected
    beroperasi), dan approve/reject harus atomik untuk seluruh batch,
    bukan diselesaikan per-dokumen.
  - Tidak ada User model terpisah di app ini (lihat database.py) —
    aktor dicatat sebagai username string biasa, pola yang sama dengan
    `changed_by` (history_utils.py) dan `last_modified_by`
    (wazuh_api.py).
  - Guard `approved_by != proposed_by` ditegakkan DI SINI (bukan cuma
    di level route) supaya tidak bisa terlewat oleh pemanggil lain di
    masa depan yang lupa cek — lihat approve_promotion_request().
  - Reject/cancel TIDAK punya restriksi != — proposer boleh membatalkan
    pengajuannya sendiri, user lain juga boleh reject. rejected_by
    selalu dicatat sehingga UI bisa membedakan "dibatalkan sendiri"
    (rejected_by == proposed_by) dari "ditolak reviewer lain" kalau mau.
  - Conflict-aware TAPI TIDAK block mutlak: request yang mencakup file
    dengan sync_status 'conflict' ditolak PADA PERCOBAAN PERTAMA (tanpa
    force) — pemohon harus secara eksplisit mengulang dengan
    force=True untuk tetap mengajukan. force dicatat di request dan
    ditampilkan ke approver (lihat conflicted_rule_files/
    conflicted_decoder_files yang disnapshot di sini), lalu diteruskan
    apa adanya ke push_selected(force=...) saat di-approve. Ini
    menggantikan tombol "Push Paksa" versi lama yang bisa dipencet
    siapa saja tanpa approval kedua — sekarang override conflict pun
    tetap harus lewat 4-eyes.
"""

from __future__ import annotations

from datetime import datetime, timezone

from services.sync_utils import SYNC_STATUS_CONFLICT, SYNC_STATUS_SYNCED, get_env_sync_state
from services.notification import notify

STATUS_PENDING = 'pending'
STATUS_APPROVED = 'approved'
STATUS_REJECTED = 'rejected'


def _fmt_filenames(rule_filenames, decoder_filenames) -> str:
    """Human-friendly ringkasan cakupan batch untuk pesan notifikasi."""
    parts = []
    if rule_filenames is None:
        parts.append('semua file rule')
    elif rule_filenames:
        parts.append(f"{len(rule_filenames)} file rule ({', '.join(rule_filenames[:3])}{'...' if len(rule_filenames) > 3 else ''})")
    if decoder_filenames is None:
        parts.append('semua file decoder')
    elif decoder_filenames:
        parts.append(f"{len(decoder_filenames)} file decoder ({', '.join(decoder_filenames[:3])}{'...' if len(decoder_filenames) > 3 else ''})")
    return ' + '.join(parts) if parts else '(tidak ada file)'


def _conflicted_filenames(col, filenames: list[str] | None) -> list[str]:
    """
    Subset dari `filenames` (atau SEMUA filename lokal koleksi ini, kalau
    filenames None) yang punya minimal satu dokumen dengan
    sync_status == 'conflict'.

    Mengikuti semantik None/[]/[...] yang sama dengan
    pull_selected/push_selected di wazuh_api.py: None = "semua file
    jenis ini", [] = "tidak ada", [...] = "hanya file ini".

    [Phase C, 24 Agustus 2026] Cek sync_state.prod.sync_status, BUKAN
    field flat lagi -- promote SELALU menuju Prod, jadi conflict yang
    relevan di sini spesifik status terhadap Prod, bukan Dev. Rule/
    decoder yang conflict di Dev tapi bersih di Prod TIDAK menghalangi
    promote (itu urusan push-ke-Dev, gate berbeda).
    """
    if col is None or filenames == []:
        return []
    query: dict = {'sync_state.prod.sync_status': SYNC_STATUS_CONFLICT}
    if filenames is not None:
        query['filename'] = {'$in': filenames}
    return sorted(col.distinct('filename', query))


def _not_dev_synced_filenames(col, filenames: list[str] | None) -> list[str]:
    """
    [Phase C, 24 Agustus 2026] Guard promote-ke-Prod: "minimal pernah
    di-push ke Dev" (keputusan 24 Agustus 2026 -- versi sederhana dari
    "harus lulus test di Dev" di roadmap Phase C; kriteria "lulus test"
    penuh menyusul di Phase D begitu logtest-gate ada).

    Return nama file yang GAGAL syarat ini -- yaitu punya minimal satu
    dokumen yang sync_state.dev.sync_status BUKAN 'synced' (termasuk
    dokumen yang belum py punya sync_state.dev sama sekali, dihitung
    sebagai belum pernah di-push ke Dev). TIDAK ada override `force`
    untuk guard ini (beda dari conflict) -- "belum pernah dites di Dev"
    bukan sesuatu yang boleh dipaksa lewat, itu justru inti jaminan
    LARAS yang paling utama.
    """
    if col is None or filenames == []:
        return []
    query: dict = {'filename': {'$ne': None}}
    if filenames is not None:
        query['filename'] = {'$in': filenames}
    bad_filenames = set()
    for doc in col.find(query, {'filename': 1, 'sync_state': 1}):
        env_state = get_env_sync_state(doc, 'dev')
        if env_state.get('sync_status') != SYNC_STATUS_SYNCED:
            bad_filenames.add(doc.get('filename'))
    return sorted(bad_filenames)


def create_promotion_request(
    requests_col, rules_col, decoders_col,
    rule_filenames: list[str] | None, decoder_filenames: list[str] | None,
    proposed_by: str, force: bool = False,
) -> dict:
    """
    Buat promotion request baru berstatus pending untuk pilihan filename
    yang diberikan (semantik None/[]/[...] sama seperti push_selected).

    Kalau ada file target berstatus conflict DAN force=False: request
    DITOLAK, return {'success': False, 'error': str,
    'conflicted_rule_files': [...], 'conflicted_decoder_files': [...],
    'requires_force': True} — caller (UI) menampilkan ini sebagai
    peringatan dan menawarkan opsi "ajukan tetap dengan force".

    Kalau force=True: request tetap DIBUAT meski ada conflict, dengan
    'force': True disimpan di dokumennya, dan daftar file yang
    conflict di-snapshot ke 'conflicted_rule_files'/
    'conflicted_decoder_files' pada request itu sendiri — supaya
    approver bisa lihat APA yang akan ditimpa sebelum approve, tanpa
    perlu query ulang status sync saat itu (yang bisa saja sudah
    berubah antara proposal dan approval).
    """
    if requests_col is None:
        return {'success': False, 'error': 'Koleksi promotion_requests tidak tersedia (MongoDB down?).'}

    # [Phase C] Guard: minimal pernah synced ke Dev. Dicek SEBELUM
    # conflict check -- kalau file belum pernah dites di Dev sama sekali,
    # tidak relevan lagi bicara soal conflict di Prod (belum ada urusan
    # dengan Prod sama sekali).
    not_dev_rules = _not_dev_synced_filenames(rules_col, rule_filenames)
    not_dev_decoders = _not_dev_synced_filenames(decoders_col, decoder_filenames)
    if not_dev_rules or not_dev_decoders:
        return {
            'success': False,
            'error': (
                'Tidak bisa mengajukan promote: ada file yang belum pernah di-push ke Dev '
                '(sync_status=synced). Push ke Dev dan pastikan tersinkron dulu sebelum promote ke Prod.'
            ),
            'not_dev_synced_rule_files': not_dev_rules,
            'not_dev_synced_decoder_files': not_dev_decoders,
        }

    conflicted_rules = _conflicted_filenames(rules_col, rule_filenames)
    conflicted_decoders = _conflicted_filenames(decoders_col, decoder_filenames)

    if (conflicted_rules or conflicted_decoders) and not force:
        return {
            'success': False,
            'error': (
                'Ada file berstatus conflict yang belum diselesaikan. Ajukan ulang dengan '
                'force=True kalau tetap ingin menimpa versi server (approver akan melihat '
                'peringatan ini juga sebelum approve).'
            ),
            'conflicted_rule_files': conflicted_rules,
            'conflicted_decoder_files': conflicted_decoders,
            'requires_force': True,
        }

    now = datetime.now(timezone.utc)
    entry = {
        'rule_filenames': rule_filenames,
        'decoder_filenames': decoder_filenames,
        'force': force,
        'conflicted_rule_files': conflicted_rules,
        'conflicted_decoder_files': conflicted_decoders,
        'status': STATUS_PENDING,
        'proposed_by': proposed_by,
        'proposed_at': now,
        'approved_by': None,
        'approved_at': None,
        'rejected_by': None,
        'rejected_at': None,
        'push_result': None,
    }
    result = requests_col.insert_one(entry)
    entry['_id'] = result.inserted_id

    notify(
        'Promotion request diajukan',
        f"Oleh: {proposed_by}\nCakupan: {_fmt_filenames(rule_filenames, decoder_filenames)}\n"
        f"Force: {'ya' if force else 'tidak'}\nMenunggu approve reviewer lain.",
        level='info',
    )
    return {'success': True, 'request': entry}


def list_promotion_requests(requests_col, status: str | None = None) -> list[dict]:
    """List promotion request, terbaru dulu. status=None mengembalikan semua."""
    if requests_col is None:
        return []
    query = {'status': status} if status else {}
    return list(requests_col.find(query).sort('proposed_at', -1))


def approve_promotion_request(requests_col, users_col, push_fn, request_id, approved_by: str) -> dict:
    """
    Approve dan LANGSUNG eksekusi promotion request yang masih pending.

    push_fn: callable(rule_filenames, decoder_filenames, force) -> dict,
    mengikuti signature WazuhAPI.push_selected — di-inject (bukan
    diimpor langsung) supaya modul ini tidak punya dependency keras ke
    WazuhAPI (lebih mudah ditest, menghindari potensi circular import).
    `force` yang tersimpan di request (dari saat proposal) diteruskan
    apa adanya ke push_fn — bukan diputuskan ulang di sini.

    users_col: koleksi `users` — dipakai untuk cek role reviewer.
    SENGAJA fail-closed kalau users_col None (mis. MongoDB down): untuk
    guard yang menyangkut keamanan, "tidak bisa diverifikasi" harus
    berarti DITOLAK, bukan diloloskan begitu saja. Ini beda dari pola
    fail-open yang dipakai di tempat lain di app ini (mis. autocomplete
    yang balikin [] kalau koleksi kosong) — di sana kegagalan cuma
    bikin fitur kurang nyaman, bukan bikin gate keamanan bolong.

    Dua guard ditegakkan DI SINI (bukan cuma oleh pemanggil), supaya
    tidak bisa terlewat oleh route di masa depan yang lupa cek:
      1. approved_by harus punya flag is_reviewer=True di `users`
         ("tata kelola" — role reviewer, BUKAN role SOC analyst biasa).
      2. approved_by != proposed_by tetap berlaku SEKALIPUN keduanya
         reviewer — 4-eyes artinya proposer dan approver tidak boleh
         orang yang sama, terlepas dari role.
    """
    if requests_col is None:
        return {'success': False, 'error': 'Koleksi promotion_requests tidak tersedia.'}
    if users_col is None:
        return {'success': False, 'error': 'Tidak bisa memverifikasi role reviewer (koleksi users tidak tersedia).'}

    approver_doc = users_col.find_one({'username': approved_by})
    if approver_doc is None or not approver_doc.get('is_reviewer'):
        return {'success': False, 'error': 'Hanya user dengan role reviewer yang bisa approve promote ke Prod.'}

    req = requests_col.find_one({'_id': request_id})
    if req is None:
        return {'success': False, 'error': 'Promotion request tidak ditemukan.'}
    if req.get('status') != STATUS_PENDING:
        return {'success': False, 'error': f"Request sudah berstatus '{req.get('status')}', tidak bisa diproses lagi."}
    if req.get('proposed_by') == approved_by:
        return {'success': False, 'error': 'Tidak bisa approve pengajuan promote milik sendiri (4-eyes).'}

    now = datetime.now(timezone.utc)
    push_result = push_fn(req.get('rule_filenames'), req.get('decoder_filenames'), req.get('force', False))

    # Status 'approved' mencatat KEPUTUSAN approve-nya berhasil dilakukan;
    # berhasil/gagalnya push itu sendiri ada di dalam push_result — bukan
    # hal yang sama. Caller (route) yang tampilkan pesan sesuai isi
    # push_result ke user, bukan modul ini yang menyembunyikannya di
    # balik status 'failed' terpisah.
    requests_col.update_one(
        {'_id': request_id},
        {'$set': {
            'status': STATUS_APPROVED,
            'approved_by': approved_by,
            'approved_at': now,
            'push_result': push_result,
        }},
    )

    push_ok = bool(push_result.get('success'))
    detail_parts = []
    if not push_ok:
        detail_parts.append(f"Error: {push_result.get('error')}")
    detail_parts.extend(
        f"{k}: {len(v)}" for k, v in (
            ('skipped_conflicts', push_result.get('skipped_conflicts')),
            ('errors', push_result.get('errors')),
        ) if v
    )
    notify(
        'Promotion request DI-APPROVE',
        f"Approved by: {approved_by}\nCakupan: {_fmt_filenames(req.get('rule_filenames'), req.get('decoder_filenames'))}\n"
        f"Push ke Prod: {'berhasil' if push_ok else 'GAGAL'}"
        + (f"\n{' | '.join(detail_parts)}" if detail_parts else ''),
        level='success' if push_ok else 'error',
    )
    return {'success': True, 'push_result': push_result}


def reject_promotion_request(requests_col, request_id, rejected_by: str) -> dict:
    """
    Reject (atau self-cancel) promotion request yang masih pending.
    Beda dari approve, TIDAK ADA restriksi proposed_by != rejected_by —
    proposer boleh membatalkan pengajuannya sendiri, dan user lain juga
    boleh reject punya orang lain. `rejected_by` selalu dicatat supaya
    UI bisa membedakan "dibatalkan sendiri" (rejected_by == proposed_by)
    dari "ditolak reviewer lain" kalau perlu.

    Reject/cancel TIDAK menyentuh dokumen rule/decoder sama sekali —
    sync_status mereka dibiarkan apa adanya (biasanya 'modified_local').
    Untuk coba lagi, harus diajukan promotion request baru.
    """
    if requests_col is None:
        return {'success': False, 'error': 'Koleksi promotion_requests tidak tersedia.'}

    req = requests_col.find_one({'_id': request_id})
    if req is None:
        return {'success': False, 'error': 'Promotion request tidak ditemukan.'}
    if req.get('status') != STATUS_PENDING:
        return {'success': False, 'error': f"Request sudah berstatus '{req.get('status')}', tidak bisa diproses lagi."}

    now = datetime.now(timezone.utc)
    requests_col.update_one(
        {'_id': request_id},
        {'$set': {
            'status': STATUS_REJECTED,
            'rejected_by': rejected_by,
            'rejected_at': now,
        }},
    )

    is_self_cancel = rejected_by == req.get('proposed_by')
    notify(
        'Promotion request dibatalkan' if is_self_cancel else 'Promotion request DITOLAK',
        f"{'Dibatalkan oleh proposer' if is_self_cancel else 'Ditolak oleh'}: {rejected_by}\n"
        f"Cakupan: {_fmt_filenames(req.get('rule_filenames'), req.get('decoder_filenames'))}",
        level='warning' if is_self_cancel else 'error',
    )
    return {'success': True}