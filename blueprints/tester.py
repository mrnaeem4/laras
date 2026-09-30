from flask import Blueprint, request, jsonify
from services.wazuh_api import WazuhAPI
from services.pcre2_service import PCRE2Service

tester_bp = Blueprint('tester', __name__)
# [Phase C, 24 Agustus 2026] Logtest WAJIB ke Dev, bukan Prod -- alur
# LARAS: Draft -> Validate -> Deploy Dev -> Reload Dev -> Logtest ->
# Passed? -> Promote Prod. Menguji pola/rule terhadap Prod sebelum lolos
# gate promote bertentangan langsung dengan urutan itu (nge-tes sesuatu
# yang belum tentu boleh ada di Prod, DI Prod). Tanpa env='dev' eksplisit
# di sini, WazuhAPI() default ke 'prod' (lihat services/wazuh_api.py).
wazuh_api = WazuhAPI(env='dev')
pcre2_service = PCRE2Service()


@tester_bp.route('/logtest', methods=['POST'])
def logtest():
    """
    Send log to wazuh-logtest endpoint.

    [FIX 24 Agustus 2026] Sebelumnya endpoint ini ambil token dari
    Authorization header atau body JSON dan meneruskannya manual ke
    run_logtest() — satu-satunya tempat di codebase yang masih pakai
    pola ini. Semua endpoint Wazuh lain (push/pull/restart di api.py,
    sudah dikonfirmasi berfungsi) TIDAK PERNAH kirim token dari client
    sama sekali — WazuhAPI self-authenticate pakai kredensial dari
    Config (.env) secara otomatis lewat _make_request()'s
    "if not active_token: active_token = self.authenticate()".

    Kalau client kirim token yang salah/basi (non-None, jadi truthy),
    baris self-authenticate itu KELEWAT di percobaan pertama -- itulah
    yang menyebabkan respons "Invalid token" dari Wazuh diteruskan
    mentah-mentah ke frontend. Solusinya: jangan ambil/kirim token dari
    client sama sekali, biarkan WazuhAPI urus sendiri seperti endpoint
    lain yang sudah terbukti jalan.
    """
    data = request.get_json() or {}
    log = data.get('log', '').strip()

    if not log:
        return jsonify({'error': 'Log message is required'}), 400

    result = wazuh_api.run_logtest(log=log)

    # Wazuh's own 401 body has {'detail': ..., 'title': 'Unauthorized'},
    # bukan {'error': ...} -- cek dua-duanya supaya kegagalan auth (baik
    # dari respons kita sendiri maupun diteruskan mentah dari Wazuh)
    # sama-sama dilaporkan sebagai 401 yang jelas, bukan lolos sebagai
    # 200 OK berisi pesan error.
    if isinstance(result, dict):
        if 'error' in result:
            error_msg = str(result['error'])
            if ('Not authenticated' in error_msg or error_msg == '401'
                    or 'Tidak bisa mendapatkan token' in error_msg):
                return jsonify({'error': error_msg if 'Tidak bisa mendapatkan token' in error_msg
                                 else 'Not authenticated with Wazuh API'}), 401
        if result.get('title') == 'Unauthorized':
            return jsonify({'error': f"Wazuh API menolak autentikasi: {result.get('detail', 'Unauthorized')}"}), 401

    return jsonify(result)

@tester_bp.route('/pcre2/test', methods=['POST'])
def test_pcre2():
    """Test PCRE2 pattern against a log string"""
    data = request.get_json() or {}
    pattern = data.get('pattern', '')
    log = data.get('log', '')

    if not pattern:
        return jsonify({'error': 'Pattern is required'}), 400

    match_found, matches, extracted = pcre2_service.test_pattern(pattern, log)
    return jsonify({
        'match_found': match_found,
        'matches': matches,
        'extracted': extracted,
        'pattern_info': pcre2_service.get_pattern_info(pattern)
    })


@tester_bp.route('/pcre2/validate', methods=['POST'])
def validate_pcre2():
    """Validate PCRE2 pattern syntax"""
    data = request.get_json() or {}
    pattern = data.get('pattern', '')

    valid, error = pcre2_service.validate_pattern(pattern)
    return jsonify({'valid': valid, 'error': error})