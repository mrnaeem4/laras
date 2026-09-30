/**
 * static/js/import_export.js
 * Page-specific logic for GET /import-export (templates/import_export.html).
 * Upload XML files for import, and trigger XML exports with optional filters.
 * The export buttons call triggerExportRules()/triggerExportDecoders(),
 * which read the filter inputs and navigate to the export endpoints.
 */

function _escOrRaw(str) {
    // common.js defines esc() globally (used by rule_list.js/
    // decoder_list.js) — use it when available; fall back to a manual
    // escape otherwise so this file does not hard-crash on script order.
    if (typeof esc === 'function') return esc(str);
    return (str ?? '').toString().replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

async function uploadXML(type) {
    const isRules = type === 'rules';
    const inputId = isRules ? 'importRulesFile' : 'importDecodersFile';
    const statusId = isRules ? 'importRulesStatus' : 'importDecodersStatus';
    const endpoint = isRules ? '/importer/upload/rules' : '/importer/upload/decoders';

    const fileInput = document.getElementById(inputId);
    const statusEl = document.getElementById(statusId);
    const files = fileInput.files;

    if (!files || files.length === 0) {
        statusEl.innerHTML = `<span class="text-danger">Select at least one XML file.</span>`;
        return;
    }

    // Build FormData with all files under the 'files' key
    const formData = new FormData();
    for (let i = 0; i < files.length; i++) {
        formData.append('files', files[i]);
    }

    statusEl.innerHTML = `<span class="text-info">Uploading and processing ${files.length} file(s)...</span>`;

    try {
        const res = await fetch(endpoint, {
            method: 'POST',
            body: formData,
        });

        const data = await res.json();

        if (res.ok) {
            let msg = `<span class="text-success"><i class="fa-solid fa-circle-check me-1"></i>Imported ${data.imported} of ${data.total_parsed} parsed items.</span>`;

            if (data.skipped > 0) {
                msg += `<div class="text-muted mt-1"><i class="fa-solid fa-forward me-1"></i>${data.skipped} item(s) skipped.</div>`;
            }

            if (data.conflicts && data.conflicts.length > 0) {
                const conflictLines = data.conflicts.map((c) => _escOrRaw(c.reason || JSON.stringify(c)));
                msg += `<div class="text-warning mt-1"><i class="fa-solid fa-triangle-exclamation me-1"></i>Conflict - has unpushed local edits (${data.conflicts.length}):<br>• ${conflictLines.join('<br>• ')}</div>`;
            }

            if (data.errors && data.errors.length > 0) {
                const errorLines = data.errors.map((e) => _escOrRaw(e));
                msg += `<div class="text-warning mt-1"><i class="fa-solid fa-triangle-exclamation me-1"></i>Error (${data.errors.length}):<br>• ${errorLines.join('<br>• ')}</div>`;
            }

            statusEl.innerHTML = msg;

            // Refresh table views & badges
            if (isRules && typeof loadRuleTable === 'function') loadRuleTable();
            if (!isRules && typeof loadDecoderTable === 'function') loadDecoderTable();
            if (typeof loadSidebarCounts === 'function') loadSidebarCounts();

            // Clear input
            fileInput.value = '';
        } else {
            statusEl.innerHTML = `<span class="text-danger"><i class="fa-solid fa-circle-exclamation me-1"></i>Error: ${data.error || 'Failed to import files.'}</span>`;
        }
    } catch (err) {
        console.error('Upload error:', err);
        statusEl.innerHTML = `<span class="text-danger"><i class="fa-solid fa-circle-exclamation me-1"></i>Request error: ${err.message}</span>`;
    }
}

// Export buttons call triggerExportRules()/triggerExportDecoders() below.
// The GET /importer/export/rules & .../decoders endpoints (blueprints/
// importer.py) accept filters via query string, not body.
function triggerExportRules() {
    const idsInput = document.getElementById('exportRuleIds');
    const groupInput = document.getElementById('exportRuleGroup');
    const params = new URLSearchParams();

    const ids = (idsInput?.value || '').trim();
    const group = (groupInput?.value || '').trim();
    if (ids) params.set('ids', ids);
    if (group) params.set('group', group);

    const qs = params.toString();
    window.location.href = `/importer/export/rules${qs ? '?' + qs : ''}`;
}

function triggerExportDecoders() {
    const namesInput = document.getElementById('exportDecoderNames');
    const params = new URLSearchParams();

    const names = (namesInput?.value || '').trim();
    if (names) params.set('names', names);

    const qs = params.toString();
    window.location.href = `/importer/export/decoders${qs ? '?' + qs : ''}`;
}

// ── Database Backup (Phase E) ──────────────────────────────────────────

let _restoreCandidate = null;

function setBackupControlsDisabled(disabled) {
    const ids = ['btnCreateBackup', 'btnConfirmRestore', 'btnCancelRestore'];
    for (const id of ids) {
        const el = document.getElementById(id);
        if (el) el.disabled = disabled;
    }
    document.querySelectorAll('#backupTableBody .btn-restore').forEach((b) => { b.disabled = disabled; });
}

function backupControlsDisabled() {
    const el = document.getElementById('btnCreateBackup');
    const confirmEl = document.getElementById('btnConfirmRestore');
    return (el && el.disabled) || (confirmEl && confirmEl.disabled);
}

async function loadBackupTable() {
    const tbody = document.getElementById('backupTableBody');
    const emptyEl = document.getElementById('backupTableEmpty');
    if (!tbody || !emptyEl) return;
    tableSkeleton(tbody, 6);
    emptyEl.classList.add('d-none');
    try {
        const res = await fetch('/api/backups');
        const backups = await res.json();
        if (!Array.isArray(backups)) throw new Error('Invalid response.');
        if (backups.length === 0) {
            tbody.innerHTML = '';
            emptyEl.classList.remove('d-none');
            return;
        }
        const controlsDisabled = backupControlsDisabled();
        tbody.innerHTML = backups.map((b) => `
            <tr>
                <td class="cell-mono wrap-col">${esc(b.backup_id)}</td>
                <td>${esc(b.triggered_by)}</td>
                <td>${b.total_documents ?? '-'}</td>
                <td class="cell-muted">${(b.size_bytes / 1024).toFixed(1)} KB</td>
                <td class="cell-muted">${fmtDate(b.last_modified)}</td>
                <td>
                    <button class="btn btn-sm btn-outline-danger btn-restore" onclick="openRestoreConfirm('${esc(b.s3_key)}')" ${controlsDisabled ? 'disabled' : ''}><i class="fa-solid fa-trash-restore me-1"></i>Restore</button>
                </td>
            </tr>`).join('');
    } catch (err) {
        console.error('Load backups error:', err);
        tbody.innerHTML = `<tr><td colspan="6" class="text-danger text-center py-4">Failed to load backups: ${esc(err.message)}</td></tr>`;
    }
}

async function createBackupNow() {
    if (backupControlsDisabled()) return;
    const btn = document.getElementById('btnCreateBackup');
    const statusEl = document.getElementById('backupStatus');
    setBackupControlsDisabled(true);
    const original = btn.innerHTML;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>';
    if (statusEl) statusEl.innerHTML = '<span class="text-info"><i class="fa-solid fa-spinner fa-spin me-1"></i>Creating backup...</span>';
    try {
        const res = await fetch('/api/backup', { method: 'POST' });
        const data = await res.json();
        if (data.success) {
            if (statusEl) statusEl.innerHTML = `<span class="text-success"><i class="fa-solid fa-circle-check me-1"></i>Backup created: ${esc(data.backup_id)} (${data.total_documents} documents).</span>`;
        } else {
            if (statusEl) statusEl.innerHTML = `<span class="text-danger"><i class="fa-solid fa-circle-exclamation me-1"></i>${esc(data.error || 'Failed to create backup.')}</span>`;
        }
        loadBackupTable();
    } catch (err) {
        console.error('Create backup error:', err);
        if (statusEl) statusEl.innerHTML = `<span class="text-danger"><i class="fa-solid fa-circle-exclamation me-1"></i>Request error: ${esc(err.message)}</span>`;
    } finally {
        setBackupControlsDisabled(false);
        btn.innerHTML = original;
    }
}

async function openRestoreConfirm(s3Key) {
    if (backupControlsDisabled()) return;
    _restoreCandidate = null;
    document.getElementById('restoreBackupId').textContent = s3Key;

    // The backup exports whatever BACKUP_COLLECTIONS is configured to
    // (same set used by create_backup). Show that list for confirmation.
    const collectionNames = [
        'rules', 'decoders', 'rule_history', 'decoder_history',
        'promotion_requests', 'users', 'manager_actions', 'tech_stack',
    ];
    const listEl = document.getElementById('restoreCollectionList');
    listEl.innerHTML = collectionNames.map((c) => `<code class="me-2">${esc(c)}</code>`).join('');

    _restoreCandidate = { s3_key: s3Key, collections: collectionNames };
    bootstrap.Modal.getOrCreateInstance(document.getElementById('restoreConfirmModal')).show();
}

async function confirmRestore() {
    if (!_restoreCandidate || backupControlsDisabled()) return;
    const btn = document.getElementById('btnConfirmRestore');
    const statusEl = document.getElementById('backupStatus');
    const original = btn.innerHTML;
    setBackupControlsDisabled(true);
    btn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>';
    try {
        const res = await fetch('/api/backup/restore', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(_restoreCandidate),
        });
        const data = await res.json();
        if (data.success) {
            if (statusEl) statusEl.innerHTML = `<span class="text-success"><i class="fa-solid fa-circle-check me-1"></i>Restore completed.</span>`;
            showToast('Restore completed.', 'success');
            bootstrap.Modal.getInstance(document.getElementById('restoreConfirmModal'))?.hide();
            if (typeof loadSidebarCounts === 'function') loadSidebarCounts();
            if (typeof loadRuleTable === 'function') loadRuleTable();
            if (typeof loadDecoderTable === 'function') loadDecoderTable();
        } else {
            if (statusEl) statusEl.innerHTML = `<span class="text-danger"><i class="fa-solid fa-circle-exclamation me-1"></i>${esc(data.error || 'Restore failed.')}</span>`;
        }
    } catch (err) {
        console.error('Restore error:', err);
        if (statusEl) statusEl.innerHTML = `<span class="text-danger"><i class="fa-solid fa-circle-exclamation me-1"></i>Request error: ${esc(err.message)}</span>`;
    } finally {
        btn.innerHTML = original;
        setBackupControlsDisabled(false);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('btnConfirmRestore')?.addEventListener('click', confirmRestore);
    loadBackupTable();
});