from __future__ import annotations

import gzip
import json
import logging
from datetime import datetime, timezone
from typing import Any

import boto3
import botocore
from bson import ObjectId
from pymongo.database import Database

from config import Config
from database import get_db

logger = logging.getLogger(__name__)


class ObjectIdEncoder(json.JSONEncoder):
    """Custom JSON encoder that handles ObjectId and datetime."""

    def default(self, o: Any) -> str:
        if isinstance(o, ObjectId):
            return str(o)
        if isinstance(o, datetime):
            return o.isoformat()
        return super().default(o)


def _get_s3_client():
    if not Config.S3_ENDPOINT_URL or not Config.S3_ACCESS_KEY or not Config.S3_SECRET_KEY:
        return None
    return boto3.client(
        's3',
        endpoint_url=Config.S3_ENDPOINT_URL,
        aws_access_key_id=Config.S3_ACCESS_KEY,
        aws_secret_access_key=Config.S3_SECRET_KEY,
        region_name=Config.S3_REGION or None,
        config=botocore.config.Config(signature_version='s3v4'),
    )


def _ensure_bucket(s3) -> bool:
    try:
        s3.head_bucket(Bucket=Config.S3_BUCKET)
        return True
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == '404':
            try:
                s3.create_bucket(Bucket=Config.S3_BUCKET)
                logger.info('[Backup] Bucket %s dibuat.', Config.S3_BUCKET)
                return True
            except Exception as create_err:
                logger.error('[Backup] Gagal membuat bucket %s: %s', Config.S3_BUCKET, create_err)
                return False
        logger.error('[Backup] Gagal mengakses bucket %s: %s', Config.S3_BUCKET, e)
        return False


def export_collections(db: Database) -> dict[str, list[dict]]:
    names = [n.strip() for n in Config.BACKUP_COLLECTIONS if n.strip()]
    result = {}
    for name in names:
        try:
            docs = list(db[name].find({}))
            for doc in docs:
                if '_id' in doc:
                    doc['_id'] = str(doc['_id'])
            result[name] = docs
            logger.info('[Backup] Diekspor: %s (%d dokumen)', name, len(docs))
        except Exception as exc:
            logger.warning('[Backup] Gagal mengekspor koleksi %s: %s', name, exc)
            result[name] = []
    return result


def create_backup(db: Database, triggered_by: str = 'system') -> dict:
    if not Config.BACKUP_ENABLED:
        return {'success': False, 'error': 'Backup tidak diaktifkan (BACKUP_ENABLED=False).'}

    s3 = _get_s3_client()
    if s3 is None:
        return {'success': False, 'error': 'Konfigurasi S3/MinIO belum lengkap (S3_ENDPOINT_URL, S3_ACCESS_KEY, S3_SECRET_KEY).'}

    if not _ensure_bucket(s3):
        return {'success': False, 'error': f'Tidak bisa mengakses bucket {Config.S3_BUCKET}.'}

    now = datetime.now(timezone.utc)
    timestamp = now.strftime('%Y%m%d_%H%M%S')
    backup_id = f'{timestamp}_{ObjectId()}'

    collections = export_collections(db)
    total_docs = sum(len(docs) for docs in collections.values())

    backup_data = {
        'metadata': {
            'backup_id': backup_id,
            'created_at': now.isoformat(),
            'triggered_by': triggered_by,
            'version': '1.0',
            'collections': {name: len(docs) for name, docs in collections.items()},
            'total_documents': total_docs,
        },
        'collections': collections,
    }

    json_bytes = json.dumps(backup_data, cls=ObjectIdEncoder, ensure_ascii=False).encode('utf-8')
    compressed = gzip.compress(json_bytes)
    s3_key = f'{Config.S3_PREFIX}/{backup_id}.json.gz'

    try:
        s3.put_object(
            Bucket=Config.S3_BUCKET,
            Key=s3_key,
            Body=compressed,
            ContentType='application/gzip',
            Metadata={
                'backup_id': backup_id,
                'triggered_by': triggered_by,
                'total_documents': str(total_docs),
            },
        )
        size_kb = len(compressed) / 1024
        logger.info(
            '[Backup] %s berhasil: %s (%d dokumen, %.1f KB)',
            backup_id, s3_key, total_docs, size_kb,
        )
        return {
            'success': True,
            'backup_id': backup_id,
            's3_key': s3_key,
            'size_bytes': len(compressed),
            'total_documents': total_docs,
            'collections': backup_data['metadata']['collections'],
            'created_at': backup_data['metadata']['created_at'],
        }
    except Exception as exc:
        logger.error('[Backup] Gagal mengupload %s ke S3: %s', s3_key, exc)
        return {'success': False, 'error': f'Gagal mengupload backup ke S3: {exc}'}


def list_backups(limit: int = 20) -> list[dict]:
    s3 = _get_s3_client()
    if s3 is None:
        return []

    if not _ensure_bucket(s3):
        return []

    prefix = f'{Config.S3_PREFIX}/'
    try:
        response = s3.list_objects_v2(Bucket=Config.S3_BUCKET, Prefix=prefix, MaxKeys=limit)
        contents = response.get('Contents', [])
        backups = []
        for obj in sorted(contents, key=lambda x: x['LastModified'], reverse=True)[:limit]:
            key = obj['Key']
            backup_id = key[len(prefix):].replace('.json.gz', '')
            try:
                meta = s3.head_object(Bucket=Config.S3_BUCKET, Key=key)
                m = meta.get('Metadata', {})
            except Exception:
                m = {}
            backups.append({
                'backup_id': backup_id,
                's3_key': key,
                'size_bytes': obj['Size'],
                'last_modified': obj['LastModified'].isoformat(),
                'triggered_by': m.get('triggered_by', 'unknown'),
                'total_documents': int(m.get('total_documents', 0)),
            })
        return backups
    except Exception as exc:
        logger.error('[Backup] Gagal mendaftar backup dari S3: %s', exc)
        return []


def download_backup(s3_key: str) -> dict | None:
    """
    Download + decompress + parse satu backup dari S3. Return dict backup
    mentah (dengan kunci 'metadata' dan 'collections') atau None kalau
    gagal (S3 unreachable, key tidak ada, format rusak).
    """
    s3 = _get_s3_client()
    if s3 is None:
        logger.error('[Restore] S3/MinIO belum dikonfigurasi.')
        return None
    try:
        response = s3.get_object(Bucket=Config.S3_BUCKET, Key=s3_key)
        raw = response['Body'].read()
        data = json.loads(gzip.decompress(raw))
        if not isinstance(data, dict) or 'collections' not in data:
            logger.error('[Restore] Format backup tidak valid: %s', s3_key)
            return None
        return data
    except Exception as exc:
        logger.error('[Restore] Gagal mengunduh/parse backup %s: %s', s3_key, exc)
        return None


def _restore_doc_id(doc: dict) -> dict:
    """Kembalikan _id string (dari backup) ke ObjectId kalau valid, supaya
    dokumen yang di-restore punya identitas aslinya (bukan _id baru)."""
    if '_id' in doc and isinstance(doc['_id'], str):
        try:
            doc['_id'] = ObjectId(doc['_id'])
        except Exception:
            pass
    return doc


_TIMESTAMP_FIELDS = frozenset({
    'created_at', 'updated_at', 'last_synced_at', 'changed_at', 'proposed_at',
    'approved_at', 'rejected_at', 'triggered_at', 'executed_at',
})


def _restore_datetimes(doc: dict) -> dict:
    """Best-effort: ubah field timestamp yang tersimpan sebagai ISO string
    (lihat ObjectIdEncoder, datetime jadi .isoformat()) kembali ke
    datetime supaya query rentang waktu tetap berfungsi setelah restore.
    Hanya field dengan nama yang dikenal yang disentuh — tidak menebak
    sembarang string."""
    for key in list(doc.keys()):
        val = doc[key]
        if key in _TIMESTAMP_FIELDS and isinstance(val, str):
            try:
                doc[key] = datetime.fromisoformat(val)
            except ValueError:
                pass
        elif isinstance(val, dict):
            doc[key] = _restore_datetimes(val)
        elif isinstance(val, list):
            for i, item in enumerate(val):
                if isinstance(item, dict):
                    val[i] = _restore_datetimes(item)
    return doc


def restore_backup(s3_key: str, collections: list[str] | None = None) -> dict:
    """
    Restore koleksi dari satu backup di S3.

    collection=None -> restore SEMUA koleksi yang ada di backup.
    DESTRUKTIF: tiap koleksi yang dipilih DI-DROP dulu lalu di-insert ulang
    dari isi backup. Dipanggil dari endpoint /api/backup/restore — panggilan
    dari UI sudah lewat konfirmasi ganda, tapi ini sendiri tidak melakukan
    konfirmasi (endpoint yang handle itu).

    Return dict ringkasan per koleksi: {collection: {dropped, restored}}.
    Koleksi yang tidak ada di backup dilewati (bukan error).
    """
    db = get_db()
    if db is None:
        return {'success': False, 'error': 'MongoDB tidak tersedia.'}
    if not Config.BACKUP_ENABLED:
        return {'success': False, 'error': 'Backup tidak diaktifkan (BACKUP_ENABLED=False).'}

    data = download_backup(s3_key)
    if data is None:
        return {'success': False, 'error': f'Gagal mengunduh/memparse backup: {s3_key}'}

    backup_collections = data.get('collections') or {}
    wanted = collections if collections else list(backup_collections.keys())

    summary = {}
    for name in wanted:
        docs = backup_collections.get(name)
        if docs is None:
            logger.warning('[Restore] Koleksi %s tidak ada di backup — dilewati.', name)
            continue
        try:
            col = db[name]
            dropped = col.estimated_document_count()
            col.drop()
            if docs:
                restored_docs = [_restore_datetimes(_restore_doc_id(dict(d))) for d in docs]
                col.insert_many(restored_docs)
            summary[name] = {'dropped': dropped, 'restored': len(docs)}
            logger.info('[Restore] %s: drop %d, restore %d', name, dropped, len(docs))
        except Exception as exc:
            logger.error('[Restore] Gagal restore %s: %s', name, exc)
            return {'success': False, 'error': f'Gagal restore koleksi {name}: {exc}', 'summary': summary}

    return {'success': True, 'summary': summary}