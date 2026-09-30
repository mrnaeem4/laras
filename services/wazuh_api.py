from datetime import datetime, timezone
import logging

import requests
import urllib3
from flask_login import current_user
from config import Config
from database import (
    get_rules_collection, get_decoders_collection,
    get_rule_history_collection, get_decoder_history_collection,
)
from services.xml_parser import (
    parse_rule_xml,
    parse_decoder_xml,
    decoder_docs_to_xml_file,
    build_rule_file_xml,
)
from services.wazuh_compat import scan_rule_docs
from services.sync_utils import (
    rule_content_hash,
    decoder_content_hash,
    resolve_sync_status,
    resolve_env_sync_status,
    env_sync_state_set_fields,
    env_sync_state_nested,
    SYNC_STATUS_NEW,
    SYNC_STATUS_SYNCED,
    SYNC_STATUS_MODIFIED_LOCAL,
    SYNC_STATUS_CONFLICT,
)
from services.history_utils import (
    record_rule_version, record_decoder_group_version, CHANGE_SOURCE_PULL,
)

# Suppress InsecureRequestWarning when verify_cert=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# [7 September 2026] Relative dirname yang dianggap Wazuh sebagai USER
# ruleset (writable via PUT /rules/files & /decoders/files). File yang
# lokasinya di luar dir ini di manager (mis. 'ruleset/rules') adalah
# bagian dari ruleset BAWAAN — read-only, dan mem-push-nya ke user
# ruleset (etc/rules) akan membuat DUPLIKAT rule bawaan sebagai custom.
# Dipakai di get_sync_overview() (menandai is_builtin untuk UI) dan
# push_selected() (guard backend). Nilai diverifikasi live oleh user
# (7 September 2026): ruleset/rules = bawaan, etc/rules = custom.
WAZUH_USER_RULESET_DIRS = ('etc/rules', 'etc/decoders')

logger = logging.getLogger(__name__)


def _current_username() -> str:
    """
    Best-effort username for history's `changed_by`. pull_selected/
    push_selected are plain service methods (not Flask view functions),
    always invoked from within an HTTP request in practice — but this
    guards against a RuntimeError if that's ever not true (e.g. a future
    CLI/scheduled pull) rather than crashing the whole pull over a
    missing request context. 'system' should never show up in normal
    browser-triggered usage; if it does, that's a signal something is
    calling this code path outside a request.
    """
    try:
        if current_user and current_user.is_authenticated:
            return current_user.username
    except RuntimeError:
        pass
    return 'system'


class WazuhAPI:
    """
    Client for Wazuh Manager REST API v4.x.
    Handles JWT authentication, rule/decoder file operations, sync with MongoDB, and wazuh-logtest endpoint.

    [Phase C, 24 Agustus 2026] Sekarang env-aware -- satu instance HANYA
    bicara ke SATU environment (Dev ATAU Prod), ditentukan saat konstruksi:

        wazuh_api_dev = WazuhAPI(env='dev')
        wazuh_api_prod = WazuhAPI(env='prod')

    Sengaja instance TERPISAH per environment (bukan satu instance dengan
    parameter env di tiap panggilan method) supaya `self.token` (cache JWT)
    milik Dev tidak pernah tertukar/dipakai untuk request ke Prod atau
    sebaliknya -- dua environment ini secara sengaja diperlakukan sebagai
    dua server yang sepenuhnya independen, termasuk soal token.

    TIDAK ada fallback ke WAZUH_API_* (config single-manager lama) --
    keputusan eksplisit (lihat config.py) supaya deployment tidak diam-diam
    jalan di atas config lama tanpa sadar. Kalau WAZUH_{ENV}_API_URL/USER/
    PASSWORD belum diisi di .env, constructor TIDAK crash (supaya start-up
    app tidak mati total hanya gara-gara satu environment belum
    dikonfigurasi -- konsisten dengan pola non-fatal-degradation yang
    sudah ada di database.py/app.py), tapi authenticate()/_make_request()
    akan gagal dengan pesan jelas begitu benar-benar dipakai.
    """

    def __init__(self, env: str = 'prod'):
        env = (env or '').lower()
        if env not in ('dev', 'prod'):
            raise ValueError(f"env harus 'dev' atau 'prod', diterima: {env!r}")
        self.env = env

        prefix = f'WAZUH_{env.upper()}_API_'
        raw_base_url = getattr(Config, f'{prefix}URL', None)
        self.base_url = raw_base_url.rstrip('/') if raw_base_url else ''
        self.user = getattr(Config, f'{prefix}USER', None)
        self.password = getattr(Config, f'{prefix}PASSWORD', None)
        self.verify_cert = getattr(Config, f'{prefix}VERIFY_CERT', False)
        self.token = None

        if not self.base_url or not self.user or not self.password:
            logger.warning(
                '[WazuhAPI] Konfigurasi %s belum lengkap -- isi WAZUH_%s_API_URL, '
                'WAZUH_%s_API_USER, dan WAZUH_%s_API_PASSWORD di .env sebelum '
                'fitur yang menyentuh Wazuh %s bisa dipakai.',
                env.upper(), env.upper(), env.upper(), env.upper(), env.upper(),
            )

    def authenticate(self, username: str = "", password: str = "") -> str | None:
        """Obtain a JWT token from the Wazuh Manager API."""
        if not self.base_url:
            logger.error(
                '[WazuhAPI] Tidak bisa autentikasi ke %s -- WAZUH_%s_API_URL belum diisi di .env.',
                self.env.upper(), self.env.upper(),
            )
            return None

        user = username or self.user
        pwd = password or self.password
        if not user or not pwd:
            logger.error(
                '[WazuhAPI] Tidak bisa autentikasi ke %s -- WAZUH_%s_API_USER/PASSWORD belum diisi di .env.',
                self.env.upper(), self.env.upper(),
            )
            return None

        try:
            response = requests.post(
                f'{self.base_url}/security/user/authenticate',
                auth=(user, pwd),
                verify=self.verify_cert,
                timeout=10
            )
            if response.status_code == 200:
                self.token = response.json().get('data', {}).get('token')
                if not self.token:
                    # [FIX 24 Agustus 2026] 200 OK tapi body tidak punya
                    # data.token -- kemungkinan bentuk response Wazuh
                    # beda dari yang diharapkan (versi API berbeda?).
                    # Sebelumnya ini lolos diam-diam sebagai None, lalu
                    # menyebabkan "Authorization: Bearer None" terkirim
                    # ke request berikutnya dan Wazuh balikin "Invalid
                    # token" yang menyesatkan (kelihatan seperti masalah
                    # token, padahal sebenarnya autentikasi gagal dari
                    # awal). Sekarang alasan aslinya di-log.
                    logger.error(
                        '[WazuhAPI] Login 200 OK tapi respons tidak berisi data.token (env=%s). '
                        'Body: %s', self.env, response.text[:500],
                    )
                return self.token
            # [FIX 24 Agustus 2026] Sebelumnya status non-200 cuma
            # `return None` tanpa jejak apapun kenapa gagal -- log
            # status code + body Wazuh supaya kredensial salah vs
            # endpoint salah vs Wazuh Manager tidak reachable bisa
            # dibedakan dari log, bukan cuma tebak-tebak dari gejala di
            # endpoint lain (mis. "Invalid token" yang sebenarnya bukan
            # soal token sama sekali).
            logger.error(
                '[WazuhAPI] Autentikasi ke %s (%s) gagal -- HTTP %s. Body: %s',
                self.env, self.base_url, response.status_code, response.text[:500],
            )
            return None
        except requests.exceptions.RequestException as e:
            logger.error('[WazuhAPI] Authentication error (%s tidak bisa dihubungi?): %s', self.base_url, e)
            print(f'[WazuhAPI] Authentication error: {e}')
            return None

    def _get_headers(self, token: str = "", custom_content_type: str = 'application/json') -> dict:
        """Use passed token if available, otherwise fallback to instance token."""
        active_token = token or self.token
        return {
            'Authorization': f'Bearer {active_token}',
            'Content-Type': custom_content_type
        }

    def _make_request(self, method: str, endpoint: str, token: str = "", **kwargs) -> requests.Response:
        """Centralized request handler with 401 auto-retry."""
        active_token = token or self.token
        if not active_token:
            active_token = self.authenticate()

        # [FIX 24 Agustus 2026] Sebelumnya kalau authenticate() gagal
        # (return None), kode ini tetap lanjut kirim request dengan
        # active_token=None -> _get_headers menghasilkan literal
        # "Authorization: Bearer None" -> Wazuh balikin "Invalid token"
        # yang MENYESATKAN (kelihatan seperti masalah token padahal
        # sebenarnya autentikasi gagal total dari awal, sebelum request
        # apapun terkirim). Sekarang gagal cepat dengan pesan yang jujur
        # tentang apa yang sebenarnya terjadi -- detail lengkapnya sudah
        # di-log oleh authenticate() sendiri (lihat log level ERROR).
        if not active_token:
            raise requests.exceptions.RequestException(
                f'Tidak bisa mendapatkan token dari Wazuh Manager {self.env.upper()} ({self.base_url or "URL belum diisi"}). '
                f'Cek WAZUH_{self.env.upper()}_API_URL/USER/PASSWORD di .env, dan '
                'pastikan Wazuh Manager reachable -- lihat log server untuk detail.'
            )

        headers = kwargs.pop('headers', self._get_headers(active_token))
        url = f'{self.base_url}/{endpoint.lstrip("/")}'
        timeout = kwargs.pop('timeout', 15)

        response = requests.request(method, url, headers=headers, verify=self.verify_cert, timeout=timeout, **kwargs)

        if response.status_code == 401:
            print("[WazuhAPI] Token expired or invalid, attempting re-authentication...")
            new_token = self.authenticate()
            if new_token:
                headers['Authorization'] = f'Bearer {new_token}'
                response = requests.request(method, url, headers=headers, verify=self.verify_cert, timeout=timeout, **kwargs)
            else:
                # [FIX 24 Agustus 2026] Re-authenticate gagal juga --
                # sebelumnya diam-diam mengembalikan response 401 yang
                # ASLI (dari token lama) tanpa penjelasan tambahan.
                # Alasan kegagalan re-auth sudah di-log oleh
                # authenticate() sendiri di atas.
                logger.error('[WazuhAPI] Re-autentikasi setelah 401 juga gagal untuk %s %s.', method, endpoint)

        return response

    # ══════════════════════════════════════════════════════════════════════
    # RULE FILE OPERATIONS
    # ══════════════════════════════════════════════════════════════════════

    def get_rule_files_list(self, limit: int = 500) -> dict:
        """GET /rules/files"""
        try:
            resp = self._make_request('GET', '/rules/files', params={'limit': limit})
            if resp.status_code == 200:
                return resp.json()
            return {'success': False, 'error': resp.text, 'status_code': resp.status_code}
        except requests.exceptions.RequestException as e:
            return {'success': False, 'error': str(e)}

    def get_rule_file(self, filename: str) -> dict:
        """GET /rules/files/{filename}?raw=true"""
        try:
            resp = self._make_request('GET', f'/rules/files/{filename}', params={'raw': 'true'})
            if resp.status_code == 200:
                return {'success': True, 'content': resp.text}
            return {'success': False, 'error': resp.text, 'status_code': resp.status_code}
        except requests.exceptions.RequestException as e:
            return {'success': False, 'error': str(e)}

    def _parse_upload_response(self, resp: requests.Response) -> dict:
        """
        Normalize a Wazuh Manager file-upload response into a consistent
        {'success': bool, 'error': str|None, ...} shape.

        A PUT to /rules/files or /decoders/files can fail in ways that
        DON'T produce an obvious top-level 'error' key: a non-200 HTTP
        status with a plain-text or differently-shaped JSON error body
        (e.g. {"title": "Bad Request", "detail": "..."} on a 400), or a
        200 whose envelope reports per-item failure via `error` / a
        non-empty `data.failed_items` (malformed XML, duplicate rule id,
        a filename colliding with a protected default-ruleset path,
        etc.). The previous implementation only ever returned the raw
        parsed body, so callers checking for an 'error' key silently
        treated all of the above as success — a push could show a
        "berhasil" toast while nothing actually reached the manager.
        """
        try:
            body = resp.json()
        except ValueError:
            body = None

        if resp.status_code != 200:
            message = None
            if isinstance(body, dict):
                message = body.get('detail') or body.get('message') or body.get('title')
            return {
                'success': False,
                'error': message or (resp.text or f'HTTP {resp.status_code}'),
                'status_code': resp.status_code,
                'raw': body,
            }

        if isinstance(body, dict):
            failed_items = ((body.get('data') or {}).get('failed_items')) or []
            if body.get('error') or failed_items:
                messages = []
                for item in failed_items:
                    err = item.get('error') if isinstance(item, dict) else None
                    messages.append(str(err.get('message')) if isinstance(err, dict) and err.get('message') else str(item))
                message = '; '.join(messages) or body.get('message') or 'Wazuh Manager melaporkan kegagalan tanpa detail.'
                return {'success': False, 'error': message, 'status_code': resp.status_code, 'raw': body}
            return {'success': True, 'error': None, 'status_code': resp.status_code, 'raw': body}

        # 200 with a non-JSON body — treat as success but keep the raw text
        # around in case a caller wants to log/inspect it.
        return {'success': True, 'error': None, 'status_code': resp.status_code, 'raw': resp.text}

    def upload_rule_file(self, filename: str, content: str, overwrite: bool = True) -> dict:
        """PUT /rules/files/{filename}"""
        try:
            # NOTE: Wazuh's file-upload endpoints require the raw-bytes
            # content type, NOT application/xml — the API rejects the
            # latter. This was the actual reason pushes silently failed:
            # the wrong Content-Type triggered an error response that the
            # old (unchecked-status-code) parsing then treated as success.
            headers = self._get_headers(custom_content_type='application/octet-stream')
            resp = self._make_request('PUT', f'/rules/files/{filename}',
                                      params={'overwrite': str(overwrite).lower()},
                                      data=content.encode('utf-8'),
                                      headers=headers)
            return self._parse_upload_response(resp)
        except requests.exceptions.RequestException as e:
            return {'success': False, 'error': str(e)}

    def delete_rule_file(self, filename: str) -> dict:
        """DELETE /rules/files/{filename}"""
        try:
            resp = self._make_request('DELETE', f'/rules/files/{filename}')
            return resp.json()
        except requests.exceptions.RequestException as e:
            return {'error': str(e)}

    # ══════════════════════════════════════════════════════════════════════
    # DECODER FILE OPERATIONS
    # ══════════════════════════════════════════════════════════════════════

    def get_decoder_files_list(self, limit: int = 500) -> dict:
        """GET /decoders/files"""
        try:
            resp = self._make_request('GET', '/decoders/files', params={'limit': limit})
            if resp.status_code == 200:
                return resp.json()
            return {'success': False, 'error': resp.text, 'status_code': resp.status_code}
        except requests.exceptions.RequestException as e:
            return {'success': False, 'error': str(e)}

    def get_decoder_file(self, filename: str) -> dict:
        """GET /decoders/files/{filename}?raw=true"""
        try:
            resp = self._make_request('GET', f'/decoders/files/{filename}', params={'raw': 'true'})
            if resp.status_code == 200:
                return {'success': True, 'content': resp.text}
            return {'success': False, 'error': resp.text, 'status_code': resp.status_code}
        except requests.exceptions.RequestException as e:
            return {'success': False, 'error': str(e)}

    def upload_decoder_file(self, filename: str, content: str, overwrite: bool = True) -> dict:
        """PUT /decoders/files/{filename}"""
        try:
            headers = self._get_headers(custom_content_type='application/octet-stream')
            resp = self._make_request('PUT', f'/decoders/files/{filename}', 
                                      params={'overwrite': str(overwrite).lower()},
                                      data=content.encode('utf-8'), 
                                      headers=headers)
            return self._parse_upload_response(resp)
        except requests.exceptions.RequestException as e:
            return {'success': False, 'error': str(e)}

    def delete_decoder_file(self, filename: str) -> dict:
        """DELETE /decoders/files/{filename}"""
        try:
            resp = self._make_request('DELETE', f'/decoders/files/{filename}')
            return resp.json()
        except requests.exceptions.RequestException as e:
            return {'error': str(e)}

    # ══════════════════════════════════════════════════════════════════════
    # HIGH-LEVEL SYNC OPERATIONS (PULL & PUSH)
    # ══════════════════════════════════════════════════════════════════════

    def get_sync_overview(self) -> dict:
        """
        Combine local (MongoDB, grouped by `filename`) and remote (Wazuh
        Manager) file listings for both rules and decoders, so the frontend
        can render per-file checkboxes for selective pull/push with a
        sync-status badge, instead of an all-or-nothing action.

        [Phase C, 24 Agustus 2026] sync_status yang dikembalikan sekarang
        milik environment INSTANCE INI (self.env) -- dibaca dari
        sync_state.<env>.sync_status per dokumen, BUKAN field flat lama.
        Instance Dev dan Prod akan melihat status yang BEDA untuk
        dokumen yang sama, sesuai riwayat sync masing-masing. Dokumen
        yang belum pernah sync ke environment ini (termasuk semua
        dokumen lama sebelum Phase C yang belum dimigrasi -- lihat
        database.migrate_sync_fields_to_env_state) dianggap
        SYNC_STATUS_NEW, konsisten dengan default get_env_sync_state().

        Response shape:
          {
            "env": "dev" | "prod",
            "rules":    [ {filename, on_manager, in_mongo, local_count,
                            statuses, has_conflict, relative_dirname, is_builtin}, ... ],
            "decoders": [ ... same shape ... ]
          }

        [7 September 2026] `relative_dirname` + `is_builtin` ditambahkan:
        Wazuh mengembalikan lokasi tiap file relatif ke instalasinya
        (RulesetFile schema, diverifikasi live oleh user: ruleset/rules =
        rule BAWAAN, etc/rules = custom). File yang lokasinya di luar
        user ruleset (WAZUH_USER_RULESET_DIRS) adalah ruleset bawaan
        yang read-only — TIDAK boleh di-push (push menulis ke user
        ruleset dan akan membuat DUPLIKAT rule bawaan sebagai custom).
        Frontend memakai is_builtin untuk menyembunyikan file tersebut
        dari list push; push_selected() juga menolaknya sebagai jaring
        pengaman backend.
        """
        rules_col = get_rules_collection()
        decoders_col = get_decoders_collection()

        def _remote_files(list_fn) -> dict:
            res = list_fn()
            items = res.get('data', {}).get('affected_items', []) if isinstance(res, dict) else []
            out = {}
            for f in items:
                if f.get('filename'):
                    out[f['filename']] = (f.get('relative_dirname') or '').strip()
            return out

        remote_rule_files = _remote_files(self.get_rule_files_list)
        remote_decoder_files = _remote_files(self.get_decoder_files_list)

        status_field = f'$sync_state.{self.env}.sync_status'

        def _local_summary(col) -> dict:
            if col is None:
                return {}
            pipeline = [
                {'$match': {'filename': {'$ne': None}}},
                {'$group': {
                    '_id': '$filename',
                    'count': {'$sum': 1},
                    # $ifNull menangani dokumen yang belum punya
                    # sync_state[env] sama sekali (field path yang hilang
                    # total, bukan cuma null) -- jatuh ke SYNC_STATUS_NEW,
                    # konsisten dengan default get_env_sync_state() di
                    # sync_utils.py supaya badge di UI tidak kosong untuk
                    # dokumen yang belum pernah disentuh environment ini.
                    'statuses': {'$addToSet': {'$ifNull': [status_field, SYNC_STATUS_NEW]}},
                }},
            ]
            return {row['_id']: row for row in col.aggregate(pipeline)}

        local_rule_summary = _local_summary(rules_col)
        local_decoder_summary = _local_summary(decoders_col)

        def _is_builtin(remote_dirname: str) -> bool:
            # File yang ADA di manager dan berada di luar user ruleset =
            # ruleset bawaan (read-only). Tanpa relative_dirname (API lama
            # yang tidak mengembalikan field ini) tidak bisa diklasifikasi
            # -> dianggap custom (fail-open), konsisten dengan perilaku
            # sebelum fitur ini ada.
            return bool(remote_dirname) and remote_dirname not in WAZUH_USER_RULESET_DIRS

        def _merge(remote_files: dict, local_summary: dict) -> list:
            out = []
            for fn in sorted(set(remote_files.keys()) | set(local_summary.keys())):
                local = local_summary.get(fn)
                statuses = local['statuses'] if local else []
                remote_dirname = remote_files.get(fn, '')
                out.append({
                    'filename': fn,
                    'on_manager': fn in remote_files,
                    'in_mongo': local is not None,
                    'local_count': local['count'] if local else 0,
                    'statuses': statuses,
                    'has_conflict': SYNC_STATUS_CONFLICT in statuses,
                    'relative_dirname': remote_dirname or None,
                    'is_builtin': _is_builtin(remote_dirname),
                })
            return out

        return {
            'env': self.env,
            'rules': _merge(remote_rule_files, local_rule_summary),
            'decoders': _merge(remote_decoder_files, local_decoder_summary),
        }

    def _ruleset_type_for(self, relative_dirname: str | None) -> str:
        """
        [7 September 2026] Tentukan `ruleset_type` sebuah file dari lokasinya
        di manager (diverifikasi live: ruleset/rules = bawaan, etc/rules =
        custom). File di luar user ruleset = ruleset bawaan (read-only);
        tanpa/empty relative_dirname (API lama) = custom (perilaku historis,
        fail-open).
        """
        if relative_dirname and relative_dirname not in WAZUH_USER_RULESET_DIRS:
            return 'default'
        return 'custom'

    def pull_selected(self, rule_filenames: list | None = None,
                       decoder_filenames: list | None = None) -> dict:
        """
        Pull specific rule/decoder files from Wazuh into MongoDB.

        rule_filenames / decoder_filenames:
          None -> pull every file of that type currently on the manager
          []   -> pull none of that type
          [..] -> pull only the named files

        Conflict-aware: a document that was edited locally since its last
        sync (TO THIS ENVIRONMENT -- see below) is never silently
        overwritten by an incoming pull. It is instead flagged
        sync_state.<env>.sync_status='conflict' for the user to resolve
        via the diff view (see get_file_diff), and its content is left
        as-is.

        [Phase C, 24 Agustus 2026] Menulis ke sync_state.<env>.* (env =
        self.env milik instance ini), BUKAN field flat sync_status/
        last_synced_hash/last_synced_at lagi. Field flat itu DIBIARKAN
        APA ADANYA (tidak diupdate) mulai dari sini -- kalau tetap
        dimutakhirkan dari kedua instance (Dev dan Prod), keduanya akan
        SALING MENIMPA status masing-masing lewat field yang sama,
        persis masalah yang sync_state dirancang untuk dihindari.
        Dokumen lama yang belum dimigrasi (lihat
        database.migrate_sync_fields_to_env_state) tetap punya field
        flat sebagai arsip beku, tidak lagi jadi sumber kebenaran.
        `content_hash` TETAP flat -- itu properti konten lokal, bukan
        milik satu environment tertentu.
        """
        rules_col = get_rules_collection()
        decoders_col = get_decoders_collection()
        rule_history_col = get_rule_history_collection()
        decoder_history_col = get_decoder_history_collection()
        now = datetime.now(timezone.utc)
        username = _current_username()
        env = self.env

        result = {
            'success': True,
            'env': env,
            'pulled_rules': 0, 'pulled_decoders': 0,
            'conflicts': [], 'errors': [],
        }

        # ── Rules ────────────────────────────────────────────────────
        if rule_filenames != [] and rules_col is not None:
            files_res = self.get_rule_files_list()
            # [7 September 2026] Simpan relative_dirname per file, bukan
            # cuma nama -- dipakai untuk menandai ruleset_type dokumen
            # ('default' kalau file dari ruleset bawaan, 'custom' kalau
            # dari user ruleset) sesuai lokasi aslinya di manager.
            available = {}
            for f in files_res.get('data', {}).get('affected_items', []) if isinstance(files_res, dict) else []:
                if f.get('filename'):
                    available[f['filename']] = (f.get('relative_dirname') or '').strip()
            targets = available if rule_filenames is None else (set(rule_filenames) & set(available))

            for filename in sorted(targets):
                relative_dirname = available.get(filename, '')
                ruleset_type = self._ruleset_type_for(relative_dirname)
                content_res = self.get_rule_file(filename)
                if not content_res.get('success'):
                    result['errors'].append({'file': filename, 'error': content_res.get('error')})
                    continue
                try:
                    parsed_rules = parse_rule_xml(content_res.get('content', ''))
                except ValueError as exc:
                    result['errors'].append({'file': filename, 'error': str(exc)})
                    continue

                for rule_doc in parsed_rules:
                    rule_doc['filename'] = filename
                    rule_doc['ruleset_type'] = ruleset_type
                    remote_hash = rule_content_hash(rule_doc)
                    existing = rules_col.find_one({'rule_id': rule_doc['rule_id']})

                    if existing is None:
                        rule_doc.update({
                            'origin': 'pulled',
                            'content_hash': remote_hash,
                            'last_modified_by': username,
                            # update_one(..., {'$set': rule_doc}, upsert=True)
                            # di bawah lewat operator $set -- dot-path dari
                            # env_sync_state_set_fields() AMAN di sini
                            # (beda dari insert_many mentah di bagian
                            # decoder, lihat env_sync_state_nested()).
                            **env_sync_state_set_fields(env, remote_hash, now, SYNC_STATUS_SYNCED),
                        })
                        rules_col.update_one({'rule_id': rule_doc['rule_id']}, {'$set': rule_doc}, upsert=True)
                        record_rule_version(rule_history_col, rule_doc, username, CHANGE_SOURCE_PULL)
                        result['pulled_rules'] += 1
                        continue

                    status = resolve_env_sync_status(existing, env, existing.get('content_hash'), remote_hash)

                    if status == SYNC_STATUS_CONFLICT:
                        # ruleset_type ikut dikoreksi (metadata asal file,
                        # bukan konten) supaya dokumen yang sudah terlanjur
                        # salah-tandai dari pull sebelum 7 September 2026
                        # tetap bisa diperbaiki saat pull ulang walau
                        # kontennya conflict (tidak ditimpa).
                        rules_col.update_one(
                            {'rule_id': rule_doc['rule_id']},
                            {'$set': {
                                'ruleset_type': ruleset_type,
                                f'sync_state.{env}.sync_status': status,
                            }},
                        )
                        result['conflicts'].append({'type': 'rule', 'rule_id': rule_doc['rule_id'], 'filename': filename})
                        continue

                    if status == SYNC_STATUS_MODIFIED_LOCAL:
                        # Server unchanged, local has unpushed edits — leave local content alone.
                        continue

                    # SYNCED: nothing changed, or only the server changed -> adopt remote content.
                    rule_doc.update({
                        'ruleset_type': ruleset_type,
                        'content_hash': remote_hash,
                        'last_modified_by': username,
                        **env_sync_state_set_fields(env, remote_hash, now, SYNC_STATUS_SYNCED),
                    })
                    rules_col.update_one({'rule_id': rule_doc['rule_id']}, {'$set': rule_doc})
                    record_rule_version(rule_history_col, rule_doc, username, CHANGE_SOURCE_PULL)
                    result['pulled_rules'] += 1

        # ── Decoders ─────────────────────────────────────────────────
        if decoder_filenames != [] and decoders_col is not None:
            files_res = self.get_decoder_files_list()
            # [7 September 2026] Sama seperti rules: simpan
            # relative_dirname per file untuk menandai ruleset_type.
            available = {}
            for f in files_res.get('data', {}).get('affected_items', []) if isinstance(files_res, dict) else []:
                if f.get('filename'):
                    available[f['filename']] = (f.get('relative_dirname') or '').strip()
            targets = available if decoder_filenames is None else (set(decoder_filenames) & set(available))

            for filename in sorted(targets):
                relative_dirname = available.get(filename, '')
                ruleset_type = self._ruleset_type_for(relative_dirname)
                content_res = self.get_decoder_file(filename)
                if not content_res.get('success'):
                    result['errors'].append({'file': filename, 'error': content_res.get('error')})
                    continue
                try:
                    parsed_decoders = parse_decoder_xml(content_res.get('content', ''))
                except ValueError as exc:
                    result['errors'].append({'file': filename, 'error': str(exc)})
                    continue

                # Wazuh allows multiple decoders sharing the same `name`
                # ("sibling decoders" — see parse_decoder_xml docstring),
                # and decoders have no stable ID from Wazuh to match
                # against across pulls the way rules have `rule_id`. Per
                # explicit decision: pull is a full reset for this file —
                # every local decoder document belonging to `filename` is
                # deleted first (regardless of sync_status, including
                # modified_local/conflict — those are NOT preserved), then
                # replaced wholesale with what was just parsed from the
                # server. No per-decoder conflict detection for decoders.
                names_before = set(decoders_col.distinct('name', {'filename': filename}))

                decoders_col.delete_many({'filename': filename})

                names_in_file = set()
                if parsed_decoders:
                    for decoder_doc in parsed_decoders:
                        decoder_doc['filename'] = filename
                        decoder_doc['ruleset_type'] = ruleset_type
                        remote_hash = decoder_content_hash(decoder_doc)
                        decoder_doc.update({
                            'origin': 'pulled',
                            'content_hash': remote_hash,
                            'last_modified_by': username,
                            # insert_many() di bawah TIDAK lewat $set --
                            # WAJIB pakai versi nested (bukan dot-path),
                            # lihat docstring env_sync_state_nested().
                            **env_sync_state_nested(env, remote_hash, now, SYNC_STATUS_SYNCED),
                        })
                        names_in_file.add(decoder_doc['name'])
                    decoders_col.insert_many(parsed_decoders)
                    result['pulled_decoders'] += len(parsed_decoders)

                # One history version per distinct decoder name touched by
                # this pull — both names still present (edited or
                # unchanged, record_decoder_group_version no-ops if
                # unchanged) AND names that existed before but vanished
                # from this pull (re-read finds an empty group, recording
                # that removal). Re-reads decoders_col, so must run AFTER
                # insert_many above.
                for name in names_before | names_in_file:
                    record_decoder_group_version(
                        decoder_history_col, decoders_col, filename, name,
                        username, CHANGE_SOURCE_PULL,
                    )


        msg = f"Pull dari {env.upper()} selesai. {result['pulled_rules']} rule & {result['pulled_decoders']} decoder diperbarui."
        if result['conflicts']:
            msg += f" {len(result['conflicts'])} item berstatus conflict (tidak ditimpa, perlu diselesaikan manual)."
        if result['errors']:
            msg += f" {len(result['errors'])} file gagal diproses."
        result['message'] = msg
        return result

    def push_selected(self, rule_filenames: list | None = None,
                       decoder_filenames: list | None = None,
                       force: bool = False) -> dict:
        """
        Push specific rule/decoder files from MongoDB to the Wazuh Manager.

        rule_filenames / decoder_filenames:
          None -> push every file of that type that exists locally
          []   -> push none of that type
          [..] -> push only the named files

        By default, a file containing any document with sync_status
        'conflict' is skipped entirely (listed under skipped_conflicts)
        rather than silently overwriting server-side changes. Pass
        force=True to push anyway (the user has reviewed the diff and
        chosen to overwrite the server copy).

        NOTE on multiple <group name="..."> wrappers per file: an
        earlier version of this method refused to push such files,
        reasoning that concatenating several top-level <group> blocks
        isn't well-formed XML per generic parsers (verified with lxml).
        That reasoning was WRONG as a predictor of what the Wazuh
        Manager REST API actually accepts — empirically confirmed by
        successfully pushing a small multi-group file through this same
        code path. A separate, larger (75-rule, 5-group) file DID fail
        with "XML syntax error" from Wazuh, so something about that
        specific push does fail — but it is not simply "this file has
        more than one wrapper". The real cause is still unconfirmed
        (possibly size-related, possibly a specific rule's content); do
        not reintroduce a blanket multi-group block based on the old
        theory. See `raw` on failed upload results for Wazuh's full
        response when diagnosing a real failure.
        [Phase C, 24 Agustus 2026] Conflict check dan update status setelah
        push sekarang pakai sync_state.<env>.sync_status (env = self.env
        milik instance ini), BUKAN field flat lagi -- lihat pull_selected's
        docstring untuk alasan yang sama persis (Dev dan Prod tidak boleh
        saling menimpa status lewat field yang sama).
        """
        rules_col = get_rules_collection()
        decoders_col = get_decoders_collection()
        now = datetime.now(timezone.utc)
        env = self.env

        result = {
            'success': True,
            'env': env,
            'pushed_rules': 0, 'pushed_decoders': 0,
            'skipped_conflicts': [], 'skipped_builtin': [], 'errors': [],
        }

        # ── Rules ────────────────────────────────────────────────────
        if rule_filenames != [] and rules_col is not None:
            query = {'filename': {'$in': rule_filenames}} if rule_filenames is not None else {'filename': {'$ne': None}}
            docs_by_file: dict = {}
            for r in rules_col.find(query):
                docs_by_file.setdefault(r.get('filename'), []).append(r)

            # [7 September 2026] Ruleset BAWAAN (file yang di manager
            # berada di luar user ruleset, mis. ruleset/rules) TIDAK boleh
            # di-push: PUT /rules/files menulis ke user ruleset (etc/rules),
            # jadi mem-push file bawaan akan membuat DUPLIKAT rule bawaan
            # sebagai custom. Daftar diambil dari manager (bukan hanya
            # nama lokal) supaya nama file yang bentrok dengan ruleset
            # bawaan ikut terblokir walau belum ada di MongoDB.
            builtin_rule_files: set[str] = set()
            try:
                files_res = self.get_rule_files_list()
                for f in (files_res.get('data', {}).get('affected_items', []) if isinstance(files_res, dict) else []):
                    fn = f.get('filename')
                    relative_dirname = (f.get('relative_dirname') or '').strip()
                    if fn and relative_dirname and relative_dirname not in WAZUH_USER_RULESET_DIRS:
                        builtin_rule_files.add(fn)
            except requests.exceptions.RequestException as exc:
                logger.warning('[push] Gagal mengambil daftar rule files utk deteksi ruleset bawaan: %s', exc)

            for filename, docs in docs_by_file.items():
                if filename in builtin_rule_files:
                    result['skipped_builtin'].append({
                        'file': filename, 'type': 'rule',
                        'reason': 'File adalah bagian dari ruleset bawaan Wazuh (read-only). Push akan membuat duplikat di user ruleset.',
                    })
                    continue

                # [7 September 2026] Lapisan kedua: dokumen yang
                # ruleset_type-nya 'default' (ditandai pull dari ruleset
                # bawaan) TIDAK boleh di-push, TANPA bergantung pada
                # relative_dirname dari API manager (API lama bisa tidak
                # mengembalikan field itu, tapi metadata lokal tetap
                # menyimpan kebenaran yang sudah di-set saat pull).
                if any(d.get('ruleset_type') == 'default' for d in docs):
                    result['skipped_builtin'].append({
                        'file': filename, 'type': 'rule',
                        'reason': 'Dokumen ditandai sebagai bagian dari ruleset bawaan Wazuh (ruleset_type=default, read-only).',
                    })
                    continue

                conflicted = [
                    d['rule_id'] for d in docs
                    if d.get('sync_state', {}).get(env, {}).get('sync_status') == SYNC_STATUS_CONFLICT
                ]
                if conflicted and not force:
                    result['skipped_conflicts'].append({'file': filename, 'type': 'rule', 'rule_ids': conflicted})
                    continue

                xml_content = build_rule_file_xml(docs)
                res = self.upload_rule_file(filename, xml_content, overwrite=True)

                if not res.get('success'):
                    # Diagnose WHICH rule(s) actually caused the failure so the
                    # person doesn't have to bisect by hand (see the earlier
                    # 101006 atomic-group case). Two tiers, cheapest first:
                    #   1. Instant local pattern match against known Wazuh
                    #      parser quirks (services/wazuh_compat.py).
                    #   2. If that finds nothing (an unknown new quirk), fall
                    #      back to actually bisecting against the manager via
                    #      a disposable scratch file — slower (O(log n) extra
                    #      uploads) but works for causes we haven't seen yet.
                    suspect_rules = scan_rule_docs(docs)
                    diagnosis_method = 'heuristic' if suspect_rules else None

                    if not suspect_rules:
                        failing = self._bisect_failing_rules(docs)
                        if failing:
                            suspect_rules = {
                                d['rule_id']: [f"Rule ini gagal diupload sendirian ke Wazuh (deskripsi: {d.get('description') or '-'})."]
                                for d in failing
                            }
                            diagnosis_method = 'bisection'
                        else:
                            diagnosis_method = 'inconclusive'

                    result['errors'].append({
                        'file': filename,
                        'error': res.get('error') or 'Upload gagal tanpa detail.',
                        'status_code': res.get('status_code'),
                        'raw': res.get('raw'),
                        'suspect_rules': suspect_rules,
                        'diagnosis_method': diagnosis_method,
                    })
                    continue

                for d in docs:
                    new_hash = d.get('content_hash') or rule_content_hash(d)
                    rules_col.update_one(
                        {'rule_id': d['rule_id']},
                        {'$set': {
                            'content_hash': new_hash,
                            **env_sync_state_set_fields(env, new_hash, now, SYNC_STATUS_SYNCED),
                        }},
                    )
                result['pushed_rules'] += len(docs)

        # ── Decoders ─────────────────────────────────────────────────
        if decoder_filenames != [] and decoders_col is not None:
            query = {'filename': {'$in': decoder_filenames}} if decoder_filenames is not None else {'filename': {'$ne': None}}
            docs_by_file = {}
            for d in decoders_col.find(query):
                docs_by_file.setdefault(d.get('filename'), []).append(d)

            # [7 September 2026] Sama seperti rules: file decoder dari
            # ruleset bawaan (mis. ruleset/decoders) tidak boleh di-push
            # ke user ruleset (etc/decoders) supaya tidak duplikat.
            builtin_decoder_files: set[str] = set()
            try:
                files_res = self.get_decoder_files_list()
                for f in (files_res.get('data', {}).get('affected_items', []) if isinstance(files_res, dict) else []):
                    fn = f.get('filename')
                    relative_dirname = (f.get('relative_dirname') or '').strip()
                    if fn and relative_dirname and relative_dirname not in WAZUH_USER_RULESET_DIRS:
                        builtin_decoder_files.add(fn)
            except requests.exceptions.RequestException as exc:
                logger.warning('[push] Gagal mengambil daftar decoder files utk deteksi ruleset bawaan: %s', exc)

            for filename, docs in docs_by_file.items():
                if filename in builtin_decoder_files:
                    result['skipped_builtin'].append({
                        'file': filename, 'type': 'decoder',
                        'reason': 'File adalah bagian dari ruleset bawaan Wazuh (read-only). Push akan membuat duplikat di user ruleset.',
                    })
                    continue

                # [7 September 2026] Lapisan kedua: dokumen dengan
                # ruleset_type='default' tidak boleh di-push (fallback
                # untuk API manager yang tidak mengembalikan
                # relative_dirname).
                if any(d.get('ruleset_type') == 'default' for d in docs):
                    result['skipped_builtin'].append({
                        'file': filename, 'type': 'decoder',
                        'reason': 'Dokumen ditandai sebagai bagian dari ruleset bawaan Wazuh (ruleset_type=default, read-only).',
                    })
                    continue

                conflicted = [
                    d['name'] for d in docs
                    if d.get('sync_state', {}).get(env, {}).get('sync_status') == SYNC_STATUS_CONFLICT
                ]
                if conflicted and not force:
                    result['skipped_conflicts'].append({'file': filename, 'type': 'decoder', 'names': conflicted})
                    continue

                xml_content = decoder_docs_to_xml_file(docs)
                res = self.upload_decoder_file(filename, xml_content, overwrite=True)

                if not res.get('success'):
                    result['errors'].append({
                        'file': filename,
                        'error': res.get('error') or 'Upload gagal tanpa detail.',
                        'status_code': res.get('status_code'),
                        'raw': res.get('raw'),
                    })
                    continue

                for d in docs:
                    new_hash = d.get('content_hash') or decoder_content_hash(d)
                    decoders_col.update_one(
                        {'_id': d['_id']},
                        {'$set': {
                            'content_hash': new_hash,
                            **env_sync_state_set_fields(env, new_hash, now, SYNC_STATUS_SYNCED),
                        }},
                    )
                result['pushed_decoders'] += len(docs)

        msg = f"Push ke {env.upper()} selesai. {result['pushed_rules']} rule & {result['pushed_decoders']} decoder dikirim ke Wazuh Manager."
        if result['skipped_builtin']:
            msg += f" {len(result['skipped_builtin'])} file dilewati karena bagian dari ruleset bawaan Wazuh (read-only)."
        if result['skipped_conflicts']:
            msg += f" {len(result['skipped_conflicts'])} file dilewati karena ada conflict yang belum diselesaikan."
        if result['errors']:
            msg += f" {len(result['errors'])} file gagal dikirim."
        result['message'] = msg
        return result

    _VALIDATION_SCRATCH_FILENAME = '__ruleforge_validate_scratch__.xml'

    def _bisect_failing_rules(self, docs: list[dict]) -> list[dict]:
        """
        Binary-search which individual rule(s) within `docs` cause Wazuh
        to reject the upload, by repeatedly test-uploading shrinking
        subsets to a disposable SCRATCH filename (never the real target
        file) and narrowing down on failure — O(log n) upload calls for
        a single bad rule. Only called after a real push already failed;
        never run speculatively on every push.

        Existing-server-file safety: the scratch filename is a fixed,
        clearly-marked throwaway name distinct from anything a real
        ruleset would use, and is deleted (best-effort) when done. If a
        file with that exact name already exists on the manager for some
        other reason, this WILL overwrite and then delete it — acceptable
        for a name this deliberately unusual, but worth knowing.

        Returns a list of {rule_id, description} for every rule that
        still fails when uploaded alone. An empty list despite the full
        set failing suggests the failure comes from an INTERACTION
        between rules (e.g. duplicate content) rather than any single
        one — callers should say so rather than claim "no cause found".
        """
        def _try_upload(subset: list[dict]) -> bool:
            if not subset:
                return True
            ids = [d.get('rule_id') for d in subset]
            xml_content = build_rule_file_xml(subset)
            res = self.upload_rule_file(self._VALIDATION_SCRATCH_FILENAME, xml_content, overwrite=True)
            ok = bool(res.get('success'))
            logger.info(
                '[bisect] tested %d rule(s) %s -> %s%s',
                len(subset), ids, 'OK' if ok else 'FAIL',
                '' if ok else f" ({res.get('error')})",
            )
            return ok

        def _bisect(subset: list[dict]) -> list[dict]:
            if len(subset) <= 1:
                logger.info('[bisect] isolated failing rule: %s', [d.get('rule_id') for d in subset])
                return list(subset)
            mid = len(subset) // 2
            left, right = subset[:mid], subset[mid:]
            bad: list[dict] = []
            if not _try_upload(left):
                bad.extend(_bisect(left))
            if not _try_upload(right):
                bad.extend(_bisect(right))
            if not bad:
                # Both halves independently succeeded even though the
                # combined subset that led here was known to fail — the
                # failure only reproduces when this exact combination is
                # present together (an interaction, not a single culprit).
                logger.warning(
                    '[bisect] batch of %d failed as a whole but BOTH halves '
                    'succeeded independently (ids=%s) — likely an '
                    'interaction between rules, not a single bad one',
                    len(subset), [d.get('rule_id') for d in subset],
                )
            return bad

        logger.info('[bisect] starting: %d rule(s) total, filename=%s', len(docs), self._VALIDATION_SCRATCH_FILENAME)
        whole_ok = _try_upload(docs)
        failing_docs = _bisect(docs) if not whole_ok else []
        logger.info('[bisect] finished: %d rule(s) identified as failing: %s',
                    len(failing_docs), [d.get('rule_id') for d in failing_docs])

        try:
            self.delete_rule_file(self._VALIDATION_SCRATCH_FILENAME)
        except Exception:
            pass  # best-effort cleanup — don't let this mask the real result

        return [{'rule_id': d.get('rule_id'), 'description': d.get('description', '')} for d in failing_docs]

    def get_file_diff(self, file_type: str, filename: str) -> dict:
        """
        Build a side-by-side diff payload: the XML rebuilt from the current
        MongoDB documents for `filename` vs. the XML currently deployed on
        the Wazuh Manager.

        Both sides are rendered through the SAME builder
        (build_rule_file_xml / decoder_docs_to_xml_file) before being
        compared. The remote XML is parsed and re-serialised rather than
        diffed as raw text — otherwise every diff would be dominated by
        cosmetic differences (tag order, attribute order, indentation)
        between however the file was originally hand-authored and our
        canonical output, drowning out genuine content changes. If the
        remote XML fails to parse, we fall back to showing it raw and
        flag that in `warnings`.

        file_type: 'rule' | 'decoder'
        """
        if file_type not in ('rule', 'decoder'):
            return {'success': False, 'error': "file_type must be 'rule' or 'decoder'"}

        warnings = []

        if file_type == 'rule':
            col = get_rules_collection()
            remote_res = self.get_rule_file(filename)
            local_docs = list(col.find({'filename': filename})) if col is not None else []
            local_xml = build_rule_file_xml(local_docs) if local_docs else ''

            remote_exists = bool(remote_res.get('success'))
            remote_raw = remote_res.get('content', '') if remote_exists else ''
            remote_xml = ''
            if remote_exists:
                try:
                    remote_docs = parse_rule_xml(remote_raw)
                    remote_xml = build_rule_file_xml(remote_docs)
                except ValueError as exc:
                    remote_xml = remote_raw
                    warnings.append(
                        f'Gagal mem-parsing XML dari Wazuh Manager untuk normalisasi diff ({exc}). '
                        'Menampilkan XML mentah — sebagian perbedaan yang tampil mungkin hanya format, bukan isi.'
                    )
            doc_count = len(local_docs)
        else:
            col = get_decoders_collection()
            remote_res = self.get_decoder_file(filename)
            local_docs = list(col.find({'filename': filename})) if col is not None else []
            local_xml = decoder_docs_to_xml_file(local_docs) if local_docs else ''

            remote_exists = bool(remote_res.get('success'))
            remote_raw = remote_res.get('content', '') if remote_exists else ''
            remote_xml = ''
            if remote_exists:
                try:
                    remote_docs = parse_decoder_xml(remote_raw)
                    remote_xml = decoder_docs_to_xml_file(remote_docs)
                except ValueError as exc:
                    remote_xml = remote_raw
                    warnings.append(
                        f'Gagal mem-parsing XML dari Wazuh Manager untuk normalisasi diff ({exc}). '
                        'Menampilkan XML mentah — sebagian perbedaan yang tampil mungkin hanya format, bukan isi.'
                    )
            doc_count = len(local_docs)

        if not remote_exists and remote_res.get('status_code') not in (None, 404):
            return {'success': False, 'error': remote_res.get('error', 'Gagal mengambil file dari Wazuh Manager.')}

        return {
            'success': True,
            'filename': filename,
            'file_type': file_type,
            'local_xml': local_xml,
            'remote_xml': remote_xml,
            'remote_exists': remote_exists,
            'local_doc_count': doc_count,
            'warnings': warnings,
        }

    # ══════════════════════════════════════════════════════════════════════
    # MANAGER OPERATIONS & LOGTEST
    # ══════════════════════════════════════════════════════════════════════

    def restart_manager(self) -> dict:
        """PUT /manager/analysisd/reload"""
        try:
            resp = self._make_request('PUT', '/manager/analysisd/reload')
            try:
                body = resp.json()
            except ValueError:
                body = None

            if resp.status_code not in (200, 202):
                message = None
                if isinstance(body, dict):
                    message = body.get('detail') or body.get('message') or body.get('title')
                return {'success': False, 'error': message or (resp.text or f'HTTP {resp.status_code}')}

            if isinstance(body, dict) and body.get('error'):
                return {'success': False, 'error': body.get('message') or 'Wazuh Manager menolak perintah restart.'}

            return {'success': True, 'data': body}
        except requests.exceptions.RequestException as e:
            return {'success': False, 'error': str(e)}

    def run_logtest(self, log: str, rule_xml: str = '', decoder_xml: str = '', token: str = "") -> dict:
        """Send a log line to the wazuh-logtest endpoint."""
        payload = {
            'log_format': 'syslog',
            'location': 'wz_rule_management',
            'event': log
        }
        try:
            resp = self._make_request('PUT', '/logtest', token=token, json=payload, timeout=15)
            return resp.json()
        except requests.exceptions.RequestException as e:
            return {'error': str(e)}