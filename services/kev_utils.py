"""
services/kev_utils.py
KEV feed integration (Phase F, Opsi C).

Sumber: CSIRT Tangerang Kota advisories API (lihat Config.KEV_ADVISORIES_URL).
Endpoint mengembalikan JSON:

    {
      "success": true,
      "filters": {...},
      "meta": {"total": N, "count": N},
      "data": [
        {
          "cve_id": "CVE-2026-88772",
          "vendor": "Citrix", "product": "NetScaler",
          "title": "...", "description": "...",
          "required_action": "...", "cwes": ["CWE-119"],
          "cvss_score": 9.5, "cvss_severity": "critical",
          "exploitation": "active", "ransomware_use": "Known",
          "published_at": "2026-09-27", "date_updated": "...",
          ...
        }, ...
      ]
    }

Yang dilakukan modul ini:

  1. `fetch_advisories()` -- ambil seluruh advisory (server-side; feed tidak
     mengirim header CORS, jadi HARUS dipanggil dari backend, bukan browser).
  2. `sync_vendor_catalog()` -- ekstrak pasangan unik (vendor, product) dan
     simpan ke koleksi `kev_catalog`. **Hanya menyisipkan pasangan yang
     belum ada** (lihat catatan dedup di bawah) -- tidak pernah menghapus
     atau mengubah entri lama.

Dedup (permintaan eksplisit, 29 September 2026): "abaikan vendor/product
yang sudah ada di database". Dedup dilakukan terhadap `kev_catalog` DAN
terhadap `tech_stack` -- pasangan yang sudah dipakai di tech_stack tidak
perlu dibuatkan lagi di katalog, supaya dropdown tidak menampilkan duplikat
dari apa yang sudah user tambahkan sendiri.

Modul ini TIDAK menyentuh koleksi `rules`/`decoders` dan tidak menyimpan
advisory mentah (itu scope pipeline AI di services/ai_utils.py, yang
mengambil advisory langsung dari feed saat dibutuhkan).
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone

import requests

from config import Config

logger = logging.getLogger(__name__)


class KevError(Exception):
    """Kesalahan yang bisa ditampilkan ke user (bukan stack trace)."""


def _advisories_url() -> str:
    return (Config.KEV_ADVISORIES_URL or '').strip()


def fetch_advisories(params: dict | None = None) -> list[dict]:
    """
    Ambil daftar advisory dari feed KEV.

    `params` opsional, mis. {'vendor': 'Citrix'} atau {'dateFrom': '...'}.
    Feed tidak mendukung pagination -- tanpa filter, satu panggilan
    mengembalikan seluruh katalog (ribuan entri).

    Raise KevError kalau URL kosong, koneksi gagal, atau response bukan
    bentuk yang diharapkan.
    """
    url = _advisories_url()
    if not url:
        raise KevError('KEV_ADVISORIES_URL belum dikonfigurasi.')

    try:
        resp = requests.get(
            url,
            params=params or {},
            timeout=Config.KEV_HTTP_TIMEOUT,
            verify=Config.KEV_VERIFY_CERT,
            headers={'Accept': 'application/json', 'User-Agent': 'laras-kev-sync'},
        )
    except requests.exceptions.RequestException as exc:
        raise KevError(f'Gagal menghubungi feed KEV: {exc}') from exc

    if resp.status_code != 200:
        raise KevError(f'Feed KEV mengembalikan HTTP {resp.status_code}.')

    try:
        payload = resp.json()
    except ValueError as exc:
        raise KevError('Response feed KEV bukan JSON yang valid.') from exc

    if not isinstance(payload, dict) or not payload.get('success'):
        raise KevError('Response feed KEV tidak berhasil (success=false).')

    data = payload.get('data')
    if not isinstance(data, list):
        raise KevError('Response feed KEV tidak punya array "data".')

    return data


def extract_pairs(advisories: list[dict]) -> set[tuple[str, str]]:
    """Ambil pasangan unik (vendor, product) dari daftar advisory."""
    pairs: set[tuple[str, str]] = set()
    for adv in advisories:
        vendor = (adv.get('vendor') or '').strip()
        product = (adv.get('product') or '').strip()
        if vendor and product:
            pairs.add((vendor, product))
    return pairs


def sync_vendor_catalog(catalog_col, tech_stack_col=None) -> dict:
    """
    Sinkronkan katalog vendor/product dari feed KEV ke `kev_catalog`.

    Hanya MENYISIPKAN pasangan yang belum ada -- entri lama tidak dihapus
    atau diubah. Pasangan yang sudah ada di `tech_stack` juga dianggap sudah
    ada (tidak perlu digandakan di katalog).

    Return ringkasan: {'success', 'total_pairs', 'inserted', 'skipped',
    'vendors', 'products', 'synced_at'} atau {'success': False, 'error'}.
    """
    if catalog_col is None:
        return {'success': False, 'error': 'MongoDB tidak tersedia.'}

    try:
        advisories = fetch_advisories()
    except KevError as exc:
        return {'success': False, 'error': str(exc)}

    pairs = extract_pairs(advisories)

    # Pasangan yang sudah ada di katalog. Dibandingkan case-insensitively
    # (casefold) supaya "Citrix/NetScaler" dari feed tidak dianggap berbeda
    # dari baris yang sudah tersimpan sebagai "citrix/netscaler" -- kalau
    # tidak, dropdown akan menampilkan duplikat beda kapitalisasi.
    existing: set[tuple[str, str]] = set()

    def _key(vendor: str, product: str) -> tuple[str, str]:
        return ((vendor or '').strip().casefold(), (product or '').strip().casefold())

    for doc in catalog_col.find({}, {'vendor': 1, 'product': 1}):
        existing.add(_key(doc.get('vendor'), doc.get('product')))

    # Pasangan yang sudah dipakai di tech_stack -- jangan digandakan ke
    # katalog (permintaan eksplisit: abaikan yang sudah ada di database).
    if tech_stack_col is not None:
        for doc in tech_stack_col.find({}, {'vendor': 1, 'product': 1}):
            existing.add(_key(doc.get('vendor'), doc.get('product')))

    now = datetime.now(timezone.utc)
    new_docs = []
    for vendor, product in sorted(pairs):
        if _key(vendor, product) in existing:
            continue
        new_docs.append({
            'vendor': vendor,
            'product': product,
            'source': 'kev',
            'created_at': now,
        })

    inserted = 0
    if new_docs:
        try:
            result = catalog_col.insert_many(new_docs, ordered=False)
            inserted = len(result.inserted_ids)
        except Exception as exc:  # noqa: BLE001 -- dilaporkan, bukan crash
            # ordered=False: sebagian mungkin berhasil, sebagian gagal
            # (duplikat race). Ambil jumlah yang BENAR-BENAR tersisip dari
            # exception; count_documents() tidak bisa dipakai karena
            # menghitung seluruh koleksi (termasuk baris lama).
            logger.warning('[KEV] Sebagian insert katalog gagal: %s', exc)
            details = getattr(exc, 'details', None) or {}
            inserted = int(details.get('nInserted') or 0)

    vendors = len({p[0] for p in pairs})
    products = len(pairs)

    summary = {
        'success': True,
        'total_pairs': len(pairs),
        'inserted': inserted,
        'skipped': max(0, len(pairs) - inserted),
        'vendors': vendors,
        'products': products,
        'synced_at': now.isoformat(),
    }
    logger.info(
        '[KEV] Sync katalog: %d pasangan unik (%d vendor), %d baru disisipkan.',
        len(pairs), vendors, inserted,
    )
    return summary


def list_vendors(catalog_col, search: str = '') -> list[str]:
    """Daftar vendor unik dari katalog (opsional difilter substring).

    Input user di-escape (re.escape) dan di-anchor sebelum masuk $regex --
    mencegah ReDoS dari pola yang diketik user sekaligus memungkinkan index
    dipakai untuk prefix match.
    """
    if catalog_col is None:
        return []
    q = (search or '').strip()
    query = {'vendor': {'$regex': '^' + re.escape(q), '$options': 'i'}} if q else {}
    vendors = catalog_col.distinct('vendor', query)
    return sorted(v for v in vendors if v)


def list_products(catalog_col, vendor: str = '', search: str = '') -> list[str]:
    """Daftar product unik dari katalog, opsional difilter per vendor."""
    if catalog_col is None:
        return []
    query: dict = {}
    vendor = (vendor or '').strip()
    if vendor:
        # Case-insensitive exact match supaya vendor dengan kapitalisasi
        # berbeda tetap menemukan product-nya.
        query['vendor'] = {'$regex': '^' + re.escape(vendor) + '$', '$options': 'i'}
    search = (search or '').strip()
    if search:
        query['product'] = {'$regex': '^' + re.escape(search), '$options': 'i'}
    products = catalog_col.distinct('product', query)
    return sorted(p for p in products if p)
