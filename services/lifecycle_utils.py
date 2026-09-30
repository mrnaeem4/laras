"""
services/lifecycle_utils.py
Phase D: status lifecycle rule -- DIHITUNG on-the-fly dari sinyal yang
sudah ada (sync_state, test_results), TIDAK PERNAH disimpan sebagai
field independen yang di-transisi manual di berbagai tempat.

Ini keputusan sengaja (27 Agustus 2026): field status yang di-$set di
banyak call site punya risiko nyata jadi basi/bohong kalau satu jalur
kode lupa meng-update-nya -- kelas bug yang sudah dikenal luas. Setiap
sinyal yang dibutuhkan sudah ada di tempat lain di dokumen yang sama,
jadi menghitungnya ulang setiap kali dibaca itu murah dan TIDAK BISA
berbohong.

5 state (bukan 6 seperti sketsa awal roadmap) -- "validated" (PCRE2
syntax check) SENGAJA digabung ke "draft" (keputusan eksplisit,
27 Agustus 2026): Test Samples sudah memvalidasi jauh lebih ketat
(logtest sungguhan lewat Wazuh Dev asli) daripada sekadar cek syntax
PCRE2, jadi "validated" sebagai state terpisah tidak menambah informasi
yang berarti.

  draft          -> belum di-push ke Dev (sync_state.dev != 'synced')
  deployed_dev   -> sudah di-push ke Dev, tapi belum (kembali) diuji
                    sejak konten terakhir berubah
  tested         -> sudah diuji terhadap konten SAAT INI, tapi ADA yang
                    gagal (test_results.all_passed == False)
  passed         -> sudah diuji terhadap konten SAAT INI, SEMUA sample
                    lolos
  promoted_prod  -> sudah di-push ke Prod (sync_state.prod == 'synced')

"Diuji terhadap konten saat ini" berarti test_results.content_hash
SAMA dengan content_hash dokumen sekarang -- kalau rule diedit lagi
setelah test dijalankan, test_results otomatis jadi basi (rule turun
balik ke deployed_dev) sampai diuji ulang, persis seperti sync_state
turun balik ke modified_local setelah diedit.
"""

from __future__ import annotations

from services.sync_utils import get_env_sync_state, SYNC_STATUS_SYNCED

LIFECYCLE_DRAFT = 'draft'
LIFECYCLE_DEPLOYED_DEV = 'deployed_dev'
LIFECYCLE_TESTED = 'tested'
LIFECYCLE_PASSED = 'passed'
LIFECYCLE_PROMOTED_PROD = 'promoted_prod'

# Urutan garis waktu untuk UI stepper -- "tested" dan "passed" sengaja
# ditaruh di INDEX yang sama secara konseptual (dua-duanya "sudah diuji
# terhadap konten saat ini, belum dipromosikan") tapi tetap dua nilai
# enum berbeda supaya warna stepper (kuning vs hijau) bisa membedakan
# "sudah diuji, ada yang gagal" dari "sudah diuji, semua lolos" tanpa
# perlu 6 titik untuk 5 tahap konsep. Lihat static/js/common.js's
# renderLifecycleStepper() untuk bagaimana ini divisualisasikan.
LIFECYCLE_ORDER = [
    LIFECYCLE_DRAFT,
    LIFECYCLE_DEPLOYED_DEV,
    LIFECYCLE_TESTED,  # alias visual "passed" tapi index sama
    LIFECYCLE_PASSED,
    LIFECYCLE_PROMOTED_PROD,
]

LIFECYCLE_LABELS = {
    LIFECYCLE_DRAFT: 'Draft',
    LIFECYCLE_DEPLOYED_DEV: 'Deployed to Dev',
    LIFECYCLE_TESTED: 'Tested (ada yang gagal)',
    LIFECYCLE_PASSED: 'Passed',
    LIFECYCLE_PROMOTED_PROD: 'Promoted to Prod',
}


def compute_rule_lifecycle_status(rule_doc: dict) -> str:
    """
    Hitung lifecycle_status SATU rule dari sinyal yang sudah ada di
    dokumennya -- tidak pernah membaca ATAU menulis field
    lifecycle_status independen di MongoDB (field itu memang sengaja
    tidak pernah dibuat).
    """
    prod_status = get_env_sync_state(rule_doc, 'prod').get('sync_status')
    if prod_status == SYNC_STATUS_SYNCED:
        return LIFECYCLE_PROMOTED_PROD

    dev_status = get_env_sync_state(rule_doc, 'dev').get('sync_status')
    if dev_status != SYNC_STATUS_SYNCED:
        return LIFECYCLE_DRAFT

    test_results = rule_doc.get('test_results')
    current_hash = rule_doc.get('content_hash')
    if not test_results or test_results.get('content_hash') != current_hash:
        return LIFECYCLE_DEPLOYED_DEV

    return LIFECYCLE_PASSED if test_results.get('all_passed') else LIFECYCLE_TESTED