/**
 * static/js/sync_manager.js
 * Page-specific logic for GET /sync (templates/sync_manager.html).
 * Depends on common.js and sync_common.js (fetchSyncOverview,
 * renderSyncFileList, wireSelectAll, getCheckedFilenames — all loaded
 * first via base.html). The Pull/Push/Diff/Restart MODALS are shared
 * partials already included by base.html; this file only wires up the
 * buttons/handlers.
 *
 * The Push button submits a promotion request (4-eyes approval). The
 * actual push happens only when ANOTHER user (reviewer role) approves
 * via the Promotion Requests panel on this page.
 */

// ── Sync & Manager: file-level Pull / Push selection + Diff preview

const STATUS_LABELS = {
    synced: 'Synced',
    modified_local: 'Not pushed',
    conflict: 'Conflict',
    new: 'Never synced',
};

function _primaryStatus(statuses) {
    if (!statuses || statuses.length === 0) return null;
    if (statuses.includes('conflict')) return 'conflict';
    if (statuses.includes('modified_local')) return 'modified_local';
    if (statuses.includes('new')) return 'new';
    return 'synced';
}

function _syncBadgeHtml(status) {
    if (!status) return '';
    const label = STATUS_LABELS[status] || status;
    return `<span class="sync-badge ${status}">${label}</span>`;
}

async function fetchSyncOverview(env) {
    if (env !== 'dev' && env !== 'prod') throw new Error(`env must be 'dev' or 'prod', got: ${env}`);
    const response = await fetch(`/api/wazuh/files?env=${env}`);
    if (!response.ok) throw new Error(`Failed to fetch file list from server (${env}).`);
    return response.json();
}

/**
 * Render one file-list section (rules or decoders) into a container.
 * mode: 'pull' -> source items are remote-manager files (on_manager true prioritized)
 *       'push' -> source items are local (in_mongo true) files
 * env: environment being displayed ('dev'|'prod') — carried to the View Diff
 *      button so the diff modal knows which environment to compare against.
 *
 * [7 September 2026] File ruleset bawaan (is_builtin, relative_dirname di
 * luar user ruleset — mis. ruleset/rules) TIDAK dirender pada mode 'push':
 * push menulis ke user ruleset dan akan membuat DUPLIKAT rule bawaan sebagai
 * custom. File tersebut tetap tampil di mode 'pull' (membaca referensi itu
 * sah), hanya push yang dikecualikan.
 */
function renderSyncFileList(containerEl, items, fileType, mode, env) {
    const relevant = items.filter((it) => (mode === 'pull' ? it.on_manager : (it.in_mongo && !it.is_builtin)));

    if (relevant.length === 0) {
        containerEl.innerHTML = `<div class="text-muted small py-1">No ${fileType} files available.</div>`;
        return;
    }

    containerEl.innerHTML = relevant.map((it) => {
        const status = _primaryStatus(it.statuses);
        const badges = [];
        if (mode === 'pull' && !it.in_mongo) badges.push(_syncBadgeHtml('new'));
        else if (status) badges.push(_syncBadgeHtml(status));
        if (mode === 'pull' && !it.on_manager) badges.push('<span class="sync-badge remote_only">Local only</span>');

        const diffBtn = it.on_manager && it.in_mongo
            ? `<button type="button" class="btn-diff-link" data-diff-type="${fileType}" data-diff-file="${it.filename}" data-diff-env="${env}">View Diff</button>`
            : '';

        return `
            <div class="sync-file-row" data-filename="${it.filename}">
                <label class="file-label">
                    <input type="checkbox" class="sync-file-checkbox" value="${it.filename}" checked>
                    <span class="file-name" title="${it.filename}">${it.filename}</span>
                </label>
                <div class="d-flex align-items-center gap-2">
                    ${badges.join(' ')}
                    ${diffBtn}
                </div>
            </div>`;
    }).join('');
}

function wireSelectAll(selectAllId, containerId) {
    const selectAll = document.getElementById(selectAllId);
    const container = document.getElementById(containerId);
    if (!selectAll || !container) return;
    selectAll.checked = true;
    selectAll.onchange = () => {
        container.querySelectorAll('.sync-file-checkbox').forEach((cb) => { cb.checked = selectAll.checked; });
    };
}

function getCheckedFilenames(containerId) {
    return Array.from(document.querySelectorAll(`#${containerId} .sync-file-checkbox:checked`)).map((cb) => cb.value);
}

// Push always goes to Dev (the /wazuh/push endpoint takes no env param).
// Pull can target Dev or Prod; the env is set by the radio toggle inside
// the Pull modal and stored here so other handlers know which env is active.
let _currentPullEnv = 'dev';

async function loadSyncModal(mode) {
    const env = mode === 'push' ? 'dev' : _currentPullEnv;

    const loadingId = mode === 'pull' ? 'pullFileListLoading' : 'pushFileListLoading';
    const errorId = mode === 'pull' ? 'pullFileListError' : 'pushFileListError';
    const containerId = mode === 'pull' ? 'pullFileListContainer' : 'pushFileListContainer';
    const rulesListId = mode === 'pull' ? 'pullRulesFileList' : 'pushRulesFileList';
    const decodersListId = mode === 'pull' ? 'pullDecodersFileList' : 'pushDecodersFileList';
    const rulesSelectAllId = mode === 'pull' ? 'pullRulesSelectAll' : 'pushRulesSelectAll';
    const decodersSelectAllId = mode === 'pull' ? 'pullDecodersSelectAll' : 'pushDecodersSelectAll';

    const loadingEl = document.getElementById(loadingId);
    const errorEl = document.getElementById(errorId);
    const containerEl = document.getElementById(containerId);

    loadingEl.classList.remove('d-none');
    errorEl.classList.add('d-none');
    containerEl.classList.add('d-none');

    try {
        const overview = await fetchSyncOverview(env);
        renderSyncFileList(document.getElementById(rulesListId), overview.rules || [], 'rule', mode, env);
        renderSyncFileList(document.getElementById(decodersListId), overview.decoders || [], 'decoder', mode, env);
        wireSelectAll(rulesSelectAllId, rulesListId);
        wireSelectAll(decodersSelectAllId, decodersListId);

        loadingEl.classList.add('d-none');
        containerEl.classList.remove('d-none');

        // Wire diff buttons freshly rendered into this modal
        containerEl.querySelectorAll('.btn-diff-link').forEach((btn) => {
            btn.addEventListener('click', () => openDiffModal(btn.dataset.diffType, btn.dataset.diffFile, btn.dataset.diffEnv));
        });
    } catch (error) {
        console.error(`${mode} file list error:`, error);
        loadingEl.classList.add('d-none');
        errorEl.textContent = error.message || 'Failed to load file list.';
        errorEl.classList.remove('d-none');
    }
}

document.getElementById('pullModal')?.addEventListener('show.bs.modal', () => {
    _currentPullEnv = 'dev'; // reset to Dev each time the modal opens, so it does not stay stuck on Prod from a previous session
    const devRadio = document.getElementById('pullEnvDev');
    if (devRadio) devRadio.checked = true;
    loadSyncModal('pull');
});
document.getElementById('pushModal')?.addEventListener('show.bs.modal', () => loadSyncModal('push'));

// Toggle Dev/Prod inside the Pull modal -- see _pull_modal.html for the radio markup.
document.querySelectorAll('input[name="pullEnv"]').forEach((radio) => {
    radio.addEventListener('change', (e) => {
        _currentPullEnv = e.target.value;
        loadSyncModal('pull');
    });
});

/**
 * Fill the "Save to file" datalist inputs in the rule & decoder wizards
 * with every filename currently known (on the Wazuh Manager and/or already
 * in MongoDB), so the user can pick an existing file instead of guessing
 * the exact name, while still being free to type a brand-new one.
 *
 * Uses env='dev' as the filename source. This is only for autocomplete of
 * filenames, not sync status, so Dev vs Prod does not matter much here.
 */
async function populateFilenameOptions() {
    try {
        const overview = await fetchSyncOverview('dev');
        knownRuleFilenames = [...new Set((overview.rules || []).map((f) => f.filename))].sort();
        knownDecoderFilenames = [...new Set((overview.decoders || []).map((f) => f.filename))].sort();
    } catch (error) {
        console.warn('Failed to load filenames for the picker:', error);
    }
}
document.addEventListener('DOMContentLoaded', populateFilenameOptions);


// ── Restart Manager handlers (separate Dev/Prod buttons) ───────────────
async function _runRestart(env, btn) {
    const originalText = btn.innerHTML;
    const restartModalEl = document.getElementById('restartModal');
    const restartModal = bootstrap.Modal.getInstance(restartModalEl) || new bootstrap.Modal(restartModalEl);
    const statusEl = document.getElementById('restartModalStatus');

    const allRestartBtns = [document.getElementById('btnConfirmRestartDev'), document.getElementById('btnConfirmRestartProd')].filter(Boolean);

    try {
        allRestartBtns.forEach((b) => { b.disabled = true; });
        btn.innerHTML = `<span class="spinner-border spinner-border-sm me-1" role="status" aria-hidden="true"></span>Restarting ${env.toUpperCase()}...`;

        const response = await fetch('/api/wazuh/restart', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ env }),
        });
        const result = await response.json();

        if (response.ok && result.success) {
            restartModal.hide();
            if (typeof showToast === 'function') showToast('<i class="fa-solid fa-circle-check me-1"></i>' + (result.message || `Restart command sent to ${env.toUpperCase()}.`), 'success');
        } else {
            throw new Error(result.message || `Failed to restart Wazuh Manager ${env.toUpperCase()}.`);
        }
    } catch (error) {
        console.error(`Restart ${env} error:`, error);
        if (statusEl) {
            statusEl.textContent = error.message || 'Network error.';
            statusEl.classList.add('text-danger');
        }
        if (typeof showToast === 'function') {
            showToast('<i class="fa-solid fa-circle-exclamation me-1"></i>' + (error.message || 'Network error.'), 'danger');
        } else {
            alert('Failed: ' + error.message);
        }
    } finally {
        allRestartBtns.forEach((b) => { b.disabled = false; });
        btn.innerHTML = originalText;
    }
}

document.getElementById('restartModal')?.addEventListener('show.bs.modal', () => {
    const statusEl = document.getElementById('restartModalStatus');
    if (statusEl) {
        statusEl.textContent = '';
        statusEl.classList.remove('text-danger');
    }
});

document.getElementById('btnConfirmRestartDev')?.addEventListener('click', function () {
    _runRestart('dev', this);
});
document.getElementById('btnConfirmRestartProd')?.addEventListener('click', function () {
    _runRestart('prod', this);
});

// ── Handle Click Tombol Pull ──────────────────────────────────────────
document.getElementById('btnConfirmPull')?.addEventListener('click', async function () {
    const btn = this;
    const originalText = btn.innerHTML;
    const pullModalEl = document.getElementById('pullModal');
    const pullModal = bootstrap.Modal.getInstance(pullModalEl) || new bootstrap.Modal(pullModalEl);

    const rule_filenames = getCheckedFilenames('pullRulesFileList');
    const decoder_filenames = getCheckedFilenames('pullDecodersFileList');

    if (rule_filenames.length === 0 && decoder_filenames.length === 0) {
        if (typeof showToast === 'function') showToast('<i class="fa-solid fa-triangle-exclamation me-1"></i>Select at least one rule or decoder file to pull.', 'warning');
        return;
    }

    try {
        btn.disabled = true;
        btn.innerHTML = `<span class="spinner-border spinner-border-sm me-1" role="status" aria-hidden="true"></span>Processing...`;

        const response = await fetch('/api/wazuh/pull', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ env: _currentPullEnv, rule_filenames, decoder_filenames }),
        });

        const result = await response.json();

        if (response.ok && result.success) {
            const hasConflicts = (result.conflicts || []).length > 0;
            const hasErrors = (result.errors || []).length > 0;
            if (!hasErrors) pullModal.hide();
            if (typeof showToast === 'function') {
                if (hasErrors) {
                    const eList = result.errors.map((e) => `${e.file}: ${e.error}`).join('; ');
                    showToast(`<i class="fa-solid fa-circle-exclamation me-1"></i>Some files failed to pull: ${eList}`, 'danger');
                } else {
                    showToast(result.message || (hasConflicts ? '<i class="fa-solid fa-triangle-exclamation me-1"></i>Pull finished with conflicts.' : '<i class="fa-solid fa-circle-check me-1"></i>Pull succeeded.'), hasConflicts ? 'warning' : 'success');
                }
            }
            if (typeof loadDecoderTable === 'function') loadDecoderTable();
            if (typeof loadRuleTable === 'function') loadRuleTable();
            if (typeof loadSidebarCounts === 'function') loadSidebarCounts();
            if (typeof populateFilenameOptions === 'function') populateFilenameOptions();
        } else {
            throw new Error(result.message || 'Failed to pull data from the Wazuh Manager.');
        }
    } catch (error) {
        console.error('Pull Error:', error);
        if (typeof showToast === 'function') {
            showToast('<i class="fa-solid fa-circle-exclamation me-1"></i>' + (error.message || 'Network error.'), 'danger');
        } else {
            alert('Failed: ' + error.message);
        }
    } finally {
        btn.disabled = false;
        btn.innerHTML = originalText;
    }
});

// ── Push button -> now submits a promotion request, not a direct push.
//    The actual push happens only when ANOTHER user (reviewer role)
//    approves via the Promotion Requests panel below.
document.getElementById('btnConfirmPush')?.addEventListener('click', async function () {
    await proposePromotion(false);
});

async function proposePromotion(force) {
    const btn = document.getElementById('btnConfirmPush');
    const originalText = btn.innerHTML;
    const pushModalEl = document.getElementById('pushModal');
    const pushModal = bootstrap.Modal.getInstance(pushModalEl) || new bootstrap.Modal(pushModalEl);
    const warningEl = document.getElementById('pushConflictWarning');
    warningEl.classList.add('d-none');

    const rule_filenames = getCheckedFilenames('pushRulesFileList');
    const decoder_filenames = getCheckedFilenames('pushDecodersFileList');

    if (rule_filenames.length === 0 && decoder_filenames.length === 0) {
        if (typeof showToast === 'function') showToast('<i class="fa-solid fa-triangle-exclamation me-1"></i>Select at least one rule or decoder file to submit.', 'warning');
        return;
    }

    try {
        btn.disabled = true;
        btn.innerHTML = `<span class="spinner-border spinner-border-sm me-1" role="status" aria-hidden="true"></span>Submitting...`;

        const response = await fetch('/api/wazuh/promote/request', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ rule_filenames, decoder_filenames, force }),
        });
        const result = await response.json();

        if (response.ok && result.success) {
            pushModal.hide();
            document.getElementById('btnForcePush')?.remove();
            if (typeof showToast === 'function') {
                showToast('<i class="fa-solid fa-circle-check me-1"></i>Promote request submitted. Awaiting reviewer approval.', 'success');
            }
            loadPromotionQueue();
        } else if (result.requires_force) {
            // Conflicting files present: this click only SUBMITS with
            // force=true, it does not overwrite the server directly. The
            // reviewer still executes the push (via approve) and sees the
            // conflicting file list before approving.
            const rFiles = result.conflicted_rule_files || [];
            const dFiles = result.conflicted_decoder_files || [];
            const fileList = [...rFiles, ...dFiles].join(', ');
            warningEl.innerHTML = `${escapeHtml(result.error || '')} Conflicting files: <code>${escapeHtml(fileList)}</code>.`;
            warningEl.classList.remove('d-none');

            if (!document.getElementById('btnForcePush')) {
                const forceBtn = document.createElement('button');
                forceBtn.id = 'btnForcePush';
                forceBtn.className = 'btn btn-outline-danger btn-sm';
                forceBtn.textContent = 'Submit Anyway (include conflicts)';
                forceBtn.onclick = () => proposePromotion(true);
                btn.insertAdjacentElement('beforebegin', forceBtn);
            }
        } else {
            throw new Error(result.error || 'Failed to submit promotion request.');
        }
    } catch (error) {
        console.error('Promote request error:', error);
        if (typeof showToast === 'function') {
            showToast('<i class="fa-solid fa-circle-exclamation me-1"></i>' + (error.message || 'Network error.'), 'danger');
        } else {
            alert('Failed: ' + error.message);
        }
    } finally {
        btn.disabled = false;
        btn.innerHTML = originalText;
    }
}

// ── Promotion queue (4-eyes approval, reviewer role) — lists pending
//    requests with Approve/Reject buttons. Approve only succeeds if the
//    clicking user has is_reviewer=True AND is not the proposer — the real
//    guard lives on the server (promotion_utils.py); here we only surface
//    the result/error via toast.
async function fetchPromotionRequests(status = 'pending') {
    const response = await fetch(`/api/wazuh/promote/requests?status=${encodeURIComponent(status)}`);
    if (!response.ok) throw new Error('Failed to fetch promotion requests.');
    return response.json();
}

// Cached once per page load (the user's role does not change mid-session).
let _currentUserInfo = null;

async function _getCurrentUserInfo() {
    if (_currentUserInfo) return _currentUserInfo;
    try {
        const response = await fetch('/api/me');
        if (!response.ok) throw new Error('Failed to fetch user info.');
        _currentUserInfo = await response.json();
    } catch (error) {
        console.error('Fetch current user error:', error);
        // Fail closed in the UI too, consistent with the server guard.
        _currentUserInfo = { username: null, is_reviewer: false };
    }
    return _currentUserInfo;
}

function _fmtFilenameList(list) {
    if (!list || list.length === 0) return '<span class="text-muted">all files</span>';
    return list.map((f) => `<code>${escapeHtml(f)}</code>`).join(', ');
}

async function renderPromotionQueue(requests) {
    const listEl = document.getElementById('promotionQueueList');
    const emptyEl = document.getElementById('promotionQueueEmpty');
    if (!listEl || !emptyEl) return; // panel not present on this page

    if (!requests || requests.length === 0) {
        listEl.innerHTML = '';
        emptyEl.classList.remove('d-none');
        return;
    }
    emptyEl.classList.add('d-none');

    const me = await _getCurrentUserInfo();

    listEl.innerHTML = requests.map((r) => {
        const when = new Date(r.proposed_at).toLocaleString();
        const forceWarning = r.force
            ? `<div class="small text-danger mt-1"><i class="fa-solid fa-triangle-exclamation me-1"></i>Includes conflicting files (force): ${_fmtFilenameList([...(r.conflicted_rule_files || []), ...(r.conflicted_decoder_files || [])])}</div>`
            : '';

        // Approve is rendered only when (a) this user is a reviewer AND
        // (b) not the proposer of this request — the same two conditions
        // checked by approve_promotion_request() on the server. Otherwise
        // the button is not rendered at all. Reject stays visible to
        // everyone (no role restriction there).
        const isOwnRequest = me.username && r.proposed_by === me.username;
        const canApprove = me.is_reviewer && !isOwnRequest;
        const approveBtn = canApprove
            ? `<button type="button" class="btn btn-success btn-sm btn-approve-promotion" data-id="${r._id}"><i class="fa-solid fa-check me-1"></i>Approve</button>`
            : `<span class="small text-muted fst-italic">${!me.is_reviewer ? 'Reviewer role required' : 'Cannot approve your own request'}</span>`;

        return `
            <div class="promotion-row border rounded p-2 mb-2" data-request-id="${r._id}">
                <div class="d-flex justify-content-between align-items-start flex-wrap gap-2">
                    <div>
                        <div class="small"><strong>${escapeHtml(r.proposed_by)}</strong> submitted a promote request - ${when}</div>
                        <div class="small text-muted">Rules: ${_fmtFilenameList(r.rule_filenames)}</div>
                        <div class="small text-muted">Decoders: ${_fmtFilenameList(r.decoder_filenames)}</div>
                        ${forceWarning}
                    </div>
                    <div class="d-flex gap-2 align-items-center">
                        ${approveBtn}
                        <button type="button" class="btn btn-outline-danger btn-sm btn-reject-promotion" data-id="${r._id}"><i class="fa-solid fa-xmark me-1"></i>Reject</button>
                    </div>
                </div>
            </div>`;
    }).join('');

    listEl.querySelectorAll('.btn-approve-promotion').forEach((btn) => {
        btn.addEventListener('click', () => handlePromotionAction(btn.dataset.id, 'approve'));
    });
    listEl.querySelectorAll('.btn-reject-promotion').forEach((btn) => {
        btn.addEventListener('click', () => handlePromotionAction(btn.dataset.id, 'reject'));
    });
}

async function loadPromotionQueue() {
    const loadingEl = document.getElementById('promotionQueueLoading');
    if (!loadingEl) return; // panel not present on this page
    loadingEl.classList.remove('d-none');
    try {
        const requests = await fetchPromotionRequests('pending');
        await renderPromotionQueue(requests);
    } catch (error) {
        console.error('Promotion queue error:', error);
        if (typeof showToast === 'function') showToast('<i class="fa-solid fa-circle-exclamation me-1"></i>Failed to load promotion queue.', 'danger');
    } finally {
        loadingEl.classList.add('d-none');
    }
}

async function handlePromotionAction(requestId, action) {
    // action: 'approve' | 'reject'. The server enforces the reviewer role
    // and approved_by != proposed_by guards; client-side checks are purely
    // cosmetic and easy to bypass.
    const row = document.querySelector(`.promotion-row[data-request-id="${requestId}"]`);
    row?.querySelectorAll('button').forEach((b) => { b.disabled = true; });

    try {
        const response = await fetch(`/api/wazuh/promote/${requestId}/${action}`, { method: 'POST' });
        const result = await response.json();

        if (response.ok && result.success) {
            if (action === 'approve') {
                const pushResult = result.push_result || {};
                const hasErrors = (pushResult.errors || []).length > 0;
                if (typeof showToast === 'function') {
                    showToast(
                        hasErrors
                            ? `<i class="fa-solid fa-triangle-exclamation me-1"></i>Approved, but the push had issues: ${pushResult.errors.map((e) => e.error).join('; ')}`
                            : '<i class="fa-solid fa-circle-check me-1"></i>Approved and pushed to the Wazuh Manager. Do not forget to Restart the Manager.',
                        hasErrors ? 'warning' : 'success',
                    );
                }
                if (typeof loadDecoderTable === 'function') loadDecoderTable();
                if (typeof loadRuleTable === 'function') loadRuleTable();
                if (typeof loadSidebarCounts === 'function') loadSidebarCounts();
                if (typeof populateFilenameOptions === 'function') populateFilenameOptions();
            } else {
                if (typeof showToast === 'function') showToast('Promote request rejected/cancelled.', 'secondary');
            }
            loadPromotionQueue();
        } else {
            throw new Error(result.error || `Failed to process ${action}.`);
        }
    } catch (error) {
        console.error(`Promotion ${action} error:`, error);
        if (typeof showToast === 'function') showToast('<i class="fa-solid fa-circle-exclamation me-1"></i>' + (error.message || 'Something went wrong.'), 'danger');
        row?.querySelectorAll('button').forEach((b) => { b.disabled = false; });
    }
}

document.addEventListener('DOMContentLoaded', loadPromotionQueue);

// ── Diff preview — MongoDB (local) vs Wazuh Manager (remote), side-by-side

/** Simple LCS-based line diff. Returns [{type: 'equal'|'add'|'remove', line}]. */
function computeLineDiff(a, b) {
    const n = a.length, m = b.length;

    // Guard against pathological O(n*m) blow-up on very large files.
    if (n * m > 4_000_000) {
        return null;
    }

    const dp = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
    for (let i = n - 1; i >= 0; i--) {
        for (let j = m - 1; j >= 0; j--) {
            dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
        }
    }

    const result = [];
    let i = 0, j = 0;
    while (i < n && j < m) {
        if (a[i] === b[j]) {
            result.push({ type: 'equal', left: a[i], right: b[j] });
            i++; j++;
        } else if (dp[i + 1][j] >= dp[i][j + 1]) {
            result.push({ type: 'remove', left: a[i], right: null });
            i++;
        } else {
            result.push({ type: 'add', left: null, right: b[j] });
            j++;
        }
    }
    while (i < n) { result.push({ type: 'remove', left: a[i], right: null }); i++; }
    while (j < m) { result.push({ type: 'add', left: null, right: b[j] }); j++; }
    return result;
}

function escapeHtml(str) {
    return (str ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function renderDiffGrid(localXml, remoteXml) {
    const localLines = (localXml || '').split('\n');
    const remoteLines = (remoteXml || '').split('\n');
    const diff = computeLineDiff(localLines, remoteLines);

    if (diff === null) {
        return `<div class="p-2 text-muted small">File is too large for a detailed line-by-line diff. Showing the raw versions instead; compare manually below.</div>
                <div class="diff-row"><div class="diff-cell diff-left">${escapeHtml(localXml)}</div><div class="diff-cell diff-right">${escapeHtml(remoteXml)}</div></div>`;
    }

    return diff.map((row) => {
        const rowClass = row.type === 'add' ? 'diff-add' : row.type === 'remove' ? 'diff-remove' : '';
        const left = row.left !== null ? escapeHtml(row.left) : '';
        const right = row.right !== null ? escapeHtml(row.right) : '';
        return `<div class="diff-row ${rowClass}"><div class="diff-cell diff-left">${left}</div><div class="diff-cell diff-right">${right}</div></div>`;
    }).join('');
}

async function openDiffModal(fileType, filename, env) {
    const diffModalEl = document.getElementById('diffModal');
    const diffModal = bootstrap.Modal.getInstance(diffModalEl) || new bootstrap.Modal(diffModalEl);
    document.getElementById('diffModalTitle').textContent = `Diff (${env.toUpperCase()}) - ${filename}`;
    document.getElementById('diffModalLoading').classList.remove('d-none');
    document.getElementById('diffModalError').classList.add('d-none');
    document.getElementById('diffModalWarning').classList.add('d-none');
    document.getElementById('diffModalBody').classList.add('d-none');
    diffModal.show();

    try {
        const response = await fetch(`/api/wazuh/diff/${fileType}/${encodeURIComponent(filename)}?env=${encodeURIComponent(env)}`);
        const result = await response.json();
        if (!response.ok || !result.success) {
            throw new Error(result.message || result.error || 'Failed to load diff.');
        }

        if (result.warnings && result.warnings.length > 0) {
            const warnEl = document.getElementById('diffModalWarning');
            warnEl.innerHTML = result.warnings.map((w) => `<i class="fa-solid fa-triangle-exclamation me-1"></i>${escapeHtml(w)}`).join('<br>');
            warnEl.classList.remove('d-none');
        }

        document.getElementById('diffGrid').innerHTML = renderDiffGrid(result.local_xml, result.remote_xml);
        document.getElementById('diffModalLoading').classList.add('d-none');
        document.getElementById('diffModalBody').classList.remove('d-none');
    } catch (error) {
        console.error('Diff error:', error);
        document.getElementById('diffModalLoading').classList.add('d-none');
        const errEl = document.getElementById('diffModalError');
        errEl.textContent = error.message || 'Failed to load diff.';
        errEl.classList.remove('d-none');
    }
}