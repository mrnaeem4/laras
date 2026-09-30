from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from bson import ObjectId
from pymongo.collection import Collection

VALID_CATEGORIES = ('os', 'web', 'db', 'network', 'app', 'other')
VALID_ENVIRONMENTS = ('dev', 'prod', 'both')


def validate_item(data: dict) -> str | None:
    vendor = (data.get('vendor') or '').strip()
    product = (data.get('product') or '').strip()
    if not vendor or not product:
        return 'Fields "vendor" and "product" are required.'
    category = (data.get('category') or '').strip()
    if category and category not in VALID_CATEGORIES:
        return f'Category must be one of: {", ".join(VALID_CATEGORIES)}.'
    env = (data.get('environment') or '').strip()
    if env and env not in VALID_ENVIRONMENTS:
        return f'Environment must be one of: {", ".join(VALID_ENVIRONMENTS)}.'
    return None


def list_items(col: Collection) -> list[dict]:
    if col is None:
        return []
    docs = col.find({}).sort('vendor', 1).sort('product', 1)
    result = []
    for d in docs:
        d['_id'] = str(d['_id'])
        result.append(d)
    return result


def get_item(col: Collection, item_id: str) -> dict | None:
    try:
        oid = ObjectId(item_id)
    except Exception:
        return None
    d = col.find_one({'_id': oid})
    if d:
        d['_id'] = str(d['_id'])
    return d


def create_item(col: Collection, data: dict, username: str) -> dict:
    error = validate_item(data)
    if error:
        return {'success': False, 'error': error}

    doc = {
        'vendor': data.get('vendor', '').strip(),
        'product': data.get('product', '').strip(),
        'version': (data.get('version') or '').strip() or None,
        'category': (data.get('category') or '').strip() or None,
        'environment': (data.get('environment') or '').strip() or None,
        'note': (data.get('note') or '').strip() or None,
        'created_at': datetime.now(timezone.utc),
        'created_by': username,
        'updated_at': datetime.now(timezone.utc),
        'updated_by': username,
    }
    result = col.insert_one(doc)
    doc['_id'] = str(result.inserted_id)
    return {'success': True, 'item': doc}


def update_item(col: Collection, item_id: str, data: dict, username: str) -> dict:
    try:
        oid = ObjectId(item_id)
    except Exception:
        return {'success': False, 'error': 'Invalid ID.'}

    existing = col.find_one({'_id': oid})
    if not existing:
        return {'success': False, 'error': 'Item not found.'}

    patch = {}
    for field in ('vendor', 'product', 'version', 'category', 'environment', 'note'):
        if field in data:
            val = data[field]
            patch[field] = val.strip() if isinstance(val, str) else val

    error = validate_item({**existing, **patch})
    if error:
        return {'success': False, 'error': error}

    patch['updated_at'] = datetime.now(timezone.utc)
    patch['updated_by'] = username
    col.update_one({'_id': oid}, {'$set': patch})

    updated = col.find_one({'_id': oid})
    if not updated:
        return {'success': False, 'error': 'Item not found.'}
    updated['_id'] = str(updated['_id'])
    return {'success': True, 'item': updated}


def delete_item(col: Collection, item_id: str) -> dict:
    try:
        oid = ObjectId(item_id)
    except Exception:
        return {'success': False, 'error': 'Invalid ID.'}

    result = col.delete_one({'_id': oid})
    if result.deleted_count == 0:
        return {'success': False, 'error': 'Item not found.'}
    return {'success': True, 'deleted': True}