/**
 * static/js/common.js
 * Utilities used by MORE THAN ONE page. Loaded on every page via
 * templates/base.html, right after the vendor scripts (Bootstrap,
 * Choices.js) and before sync_common.js and the page's own script.
 *
 * Generic helpers: debounce, esc, fmtDate, sevBadgeHTML, showToast,
 * toggleSidebar, setVal/setChecked, removeRow, tableSkeleton,
 * renderPager/changePage, openXmlModal, confirmDelete, wizard mechanics
 * (initWizards, wizardNav, goToStep, validateStep, reviewRow), and
 * autocomplete fetchers (fetchSids, fetchGroups, fetchDecoders).
 *
 * Keep this file free of anything page-specific. If a function is only
 * ever called from one page, it belongs in that page's own JS file
 * instead, even if it looks "generic" in isolation.
 */

function debounce(fn, delay) {
    let timer;
    return function (...args) {
        clearTimeout(timer);
        timer = setTimeout(() => fn.apply(this, args), delay);
    };
}
function getChoicesValue(elementId) {
    const el = document.getElementById(elementId);
    return el ? (el.value || '') : '';
}
function esc(str) {
    return String(str ?? '').replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]));
}
function fmtDate(v) {
    if (!v) return '-';
    const d = new Date(v);
    if (isNaN(d.getTime())) return String(v);
    return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }) +
           ' - ' + d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
}
function sevBadgeHTML(level) {
    const b = sevBucket(level);
    return `<span class="sev-badge sev-${b}">${esc(level)} · ${sevLabels[b]}</span>`;
}

// [Phase C, 24 Agustus 2026] Badge status sync PER ENVIRONMENT untuk
// tabel Saved Rules/Decoders (rule_list.js/decoder_list.js) -- dipakai
// bersama supaya style-nya konsisten di dua tabel, tidak duplikasi.
// Menerima sync_status_dev/sync_status_prod yang sudah "diratakan" oleh
// builder.py's _with_flat_sync_status() (bukan sync_state nested).
const ENV_STATUS_LABELS = {
    synced: 'Synced',
    modified_local: 'Not pushed',
    conflict: 'Conflict',
    new: 'Never synced',
};

function envSyncBadgesHTML(syncStatusDev, syncStatusProd) {
    const devLabel = ENV_STATUS_LABELS[syncStatusDev] || syncStatusDev || 'Never synced';
    const prodLabel = ENV_STATUS_LABELS[syncStatusProd] || syncStatusProd || 'Never synced';
    const devClass = syncStatusDev || 'new';
    const prodClass = syncStatusProd || 'new';
    return `<div class="sync-badge-group"><span class="sync-badge ${devClass}" title="Status di Dev">Dev: ${devLabel}</span><span class="sync-badge ${prodClass}" title="Status di Prod">Prod: ${prodLabel}</span></div>`;
}

/**
 * Render a Wazuh rule `group` value (a comma-separated list, e.g.
 * "syslog,authentication_failed") as chip badges. Returns an empty string
 * when group is blank so callers can fall back to a '-' placeholder.
 * Used by rule_list.js (Saved Rules table) and rule_builder.js review.
 */
function renderGroupBadges(group) {
    if (!group) return '';
    const parts = String(group).split(',').map((s) => s.trim()).filter(Boolean);
    if (parts.length === 0) return '';
    return parts.map((g) => `<span class="chip">${esc(g)}</span>`).join(' ');
}

// Visual lifecycle_status stepper (Phase D): full version with labels in
// Rule Builder Step 6, compact dot-only version in Saved Rules table.
// lifecycle_status always comes from the server (lifecycle_utils.py);
// this is pure presentation. 'tested' (a sample failed) and 'passed'
// (all passed) both occupy the same timeline stage ("tested against the
// current content, not yet promoted"), hence a single "Passed" dot whose
// color reflects the actual status.
const DISPLAY_STEPS = [
    { key: 'draft', label: 'Draft' },
    { key: 'deployed_dev', label: 'Deployed Dev' },
    { key: 'passed', label: 'Passed' },
    { key: 'promoted_prod', label: 'Promoted Prod' },
];

function renderLifecycleStepper(status, compact) {
    const displayStatus = status === 'tested' ? 'passed' : status;
    const currentIndex = DISPLAY_STEPS.findIndex((s) => s.key === displayStatus);
    const isFailed = status === 'tested';

    const dots = DISPLAY_STEPS.map((step, i) => {
        let stateClass = 'upcoming';
        if (i < currentIndex) stateClass = 'done';
        else if (i === currentIndex) stateClass = isFailed ? 'failed' : 'active';

        const label = (i === currentIndex && isFailed) ? 'Tested (some failed)' : step.label;
        return `
            <li class="lifecycle-step ${stateClass}" title="${escapeHtml(label)}">
                <div class="lifecycle-dot"></div>
                ${compact ? '' : `<div class="lifecycle-label">${escapeHtml(label)}</div>`}
            </li>`;
    }).join('');

    return `<ol class="lifecycle-stepper ${compact ? 'compact' : ''}">${dots}</ol>`;
}
function escapeHtml(str) {
    return (str ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function showToast(message, variant = 'success') {
    const container = document.getElementById('toastContainer');
    if (!container) { console.info('[toast]', message); return; }
    const id = `toast-${Date.now()}`;
    container.insertAdjacentHTML('beforeend', `
      <div id="${id}" class="toast align-items-center text-bg-${variant} border-0" role="alert"
           aria-live="assertive" aria-atomic="true" data-bs-delay="3000">
        <div class="d-flex">
          <div class="toast-body">${message}</div>
          <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
        </div>
      </div>`);
    const toastEl = document.getElementById(id);
    const toast   = new bootstrap.Toast(toastEl);
    toast.show();
    toastEl.addEventListener('hidden.bs.toast', () => toastEl.remove());
}

function toggleSidebar(forceShow) {
    const sidebar = document.getElementById('appSidebar');
    const backdrop = document.getElementById('sidebarBackdrop');
    if (!sidebar || !backdrop) return;
    
    const isCurrentlyOpen = sidebar.classList.contains('open');
    const shouldShow = typeof forceShow === 'boolean' ? forceShow : !isCurrentlyOpen;
    
    if (shouldShow) {
        sidebar.classList.add('open');
        backdrop.classList.add('show');
    } else {
        sidebar.classList.remove('open');
        backdrop.classList.remove('show');
    }
}
function setVal(id, val) {
    const el = document.getElementById(id);
    if (el) el.value = val ?? '';
}

function setChecked(id, val) {
    const el = document.getElementById(id);
    if (el) el.checked = !!val;
}
function removeRow(btn) { btn.closest('.dynamic-row').remove(); }
function tableSkeleton(tbody, cols) {
    tbody.innerHTML = Array.from({ length: 4 }).map(() =>
        `<tr>${Array.from({ length: cols }).map(() => `<td class="table-skeleton"></td>`).join('')}</tr>`
    ).join('');
}
function renderPager(kind) {
    const st = tableState[kind];
    const pagerEl = document.getElementById(kind === 'decoder' ? 'decoderPager' : 'rulePager');
    const totalPages = Math.max(1, Math.ceil(st.total / st.perPage));
    if (st.total === 0) { pagerEl.innerHTML = ''; return; }
    pagerEl.innerHTML = `
        <span>${st.total} item · Halaman ${st.page} dari ${totalPages}</span>
        <div class="d-flex gap-2">
            <button class="btn btn-outline-secondary btn-sm" ${st.page <= 1 ? 'disabled' : ''} onclick="changePage('${kind}', -1)">← Prev</button>
            <button class="btn btn-outline-secondary btn-sm" ${st.page >= totalPages ? 'disabled' : ''} onclick="changePage('${kind}', 1)">Next →</button>
        </div>`;
}
function changePage(kind, delta) {
    tableState[kind].page += delta;
    if (kind === 'decoder') loadDecoderTable(); else loadRuleTable();
}
function openXmlModal(title, xml) {
    document.getElementById('viewXmlModalTitle').textContent = title;
    document.getElementById('viewXmlModalBody').textContent = xml;
    new bootstrap.Modal(document.getElementById('viewXmlModal')).show();
}
let pendingDelete = null;
function confirmDelete(kind, key) {
    pendingDelete = { kind, key };
    document.getElementById('confirmDeleteText').textContent =
        kind === 'decoder' ? `Decoder "${key}" will be permanently deleted from MongoDB.` :
        kind === 'tech'   ? 'This tech stack item will be permanently deleted from MongoDB.' :
                            `Rule '#${key}' will be permanently deleted from MongoDB.`;
    new bootstrap.Modal(document.getElementById('confirmDeleteModal')).show();
}

document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('confirmDeleteBtn')?.addEventListener('click', async () => {
        if (!pendingDelete) return;
        const { kind, key } = pendingDelete;
        const url = kind === 'decoder' ? `/builder/decoder/${encodeURIComponent(key)}` :
                    kind === 'tech'   ? `/api/tech-stack/${encodeURIComponent(key)}` :
                                        `/builder/rule/${encodeURIComponent(key)}`;
        try {
            const res = await fetch(url, { method: 'DELETE' });
            if (!res.ok) throw new Error();
            showToast(kind === 'decoder' ? `<i class="fa-solid fa-trash me-1"></i>Decoder "${key}" deleted.` :
                      kind === 'tech'   ? `<i class="fa-solid fa-trash me-1"></i>Stack "${key}" deleted.` :
                                          `<i class="fa-solid fa-trash me-1"></i>Rule #${key} deleted.`, 'success');
            if (kind === 'decoder') loadDecoderTable();
            else if (kind === 'tech') loadTechStack();
            else loadRuleTable();
        } catch { showToast('<i class="fa-solid fa-circle-exclamation me-1"></i>Delete failed. Check the DELETE endpoint in the backend.', 'danger'); }
        finally {
            pendingDelete = null;
            bootstrap.Modal.getInstance(document.getElementById('confirmDeleteModal'))?.hide();
        }
    });
});
async function loadSidebarCounts() {
    try {
        const [dRes, rRes] = await Promise.all([
            fetch('/builder/decoder/list?page=1&per_page=1'),
            fetch('/builder/rule/list?page=1&per_page=1'),
        ]);
        if (dRes.ok) { const d = await dRes.json(); document.getElementById('decoderCountBadge').textContent = d.total ?? '-'; }
        if (rRes.ok) { const r = await rRes.json(); document.getElementById('ruleCountBadge').textContent = r.total ?? '-'; }
    } catch { /* backend list endpoints may not exist yet — fail quietly */ }
}

/* ─────────────────────────────────────────────────────────────────────
   Severity mapping — reused by the level picker (Rule Builder step 1),
   the review step, and the Saved Rules table. Buckets follow Wazuh's
   own convention for alert levels 0–16.
───────────────────────────────────────────────────────────────────── */
function sevBucket(level) {
    const n = Number(level);
    if (isNaN(n)) return 'info';
    if (n <= 3) return 'info';
    if (n <= 6) return 'low';
    if (n <= 9) return 'medium';
    if (n <= 12) return 'high';
    return 'critical';
}
const sevLabels = { info: 'Informational', low: 'Low', medium: 'Medium', high: 'High', critical: 'Critical' };


function initLevelSevHint() {
    const select = document.getElementById('rule_level');
    if (!select) return;
    select.addEventListener('change', updateLevelSevHint);
    updateLevelSevHint();
}
function updateLevelSevHint() {
    const select = document.getElementById('rule_level');
    const hint = document.getElementById('rule_level_sev_hint');
    if (!select || !hint) return;
    const b = sevBucket(select.value);
    hint.innerHTML = `Severity: <span class="sev-badge sev-${b}">${sevLabels[b]}</span>`;
}

const wizardState = {
    dec:  { step: 1, total: 4, requiredByStep: { 1: ['dec_name'] } },
    rule: { step: 1, total: 6, requiredByStep: { 1: ['rule_id', 'rule_level', 'rule_description'] } },
};

function initWizards(prefix) {
    goToStep(prefix, 1);

    // Auto-refresh the live XML preview as the person fills in fields.
    if (prefix === 'dec') {
        document.getElementById('tabDecoder').addEventListener('input', debounce(() => generateDecoderXML(true), 500));
        document.getElementById('tabDecoder').addEventListener('change', debounce(() => generateDecoderXML(true), 150));
    } else if (prefix === 'rule') {
        document.getElementById('tabRule').addEventListener('input', debounce(() => generateRuleXML(true), 500));
        document.getElementById('tabRule').addEventListener('change', debounce(() => generateRuleXML(true), 150));
    }
}

function wizardNav(prefix, delta) {
    const state = wizardState[prefix];
    if (delta > 0 && !validateStep(prefix, state.step)) return;
    const next = Math.min(Math.max(state.step + delta, 1), state.total);
    goToStep(prefix, next);
}

function goToStep(prefix, step) {
    const state = wizardState[prefix];
    if (!state) {
        console.warn(`Wizard state untuk prefix "${prefix}" tidak ditemukan.`);
        return;
    }
    state.step = step;

    const root = prefix === 'dec' ? document.getElementById('tabDecoder') : document.getElementById('tabRule');
    root.querySelectorAll('.wizard-pane').forEach(p => p.classList.toggle('active', Number(p.dataset.step) === step));

    const track = document.getElementById(prefix === 'dec' ? 'decWizardTrack' : 'ruleWizardTrack');
    track.querySelectorAll('li').forEach(li => {
        const n = Number(li.dataset.goto);
        li.classList.toggle('active', n === step);
        li.classList.toggle('done', n < step);
    });

    document.getElementById(prefix === 'dec' ? 'decStepCaption' : 'ruleStepCaption').textContent = `Step ${step} of ${state.total}`;
    document.getElementById(prefix === 'dec' ? 'decPrevBtn' : 'rulePrevBtn').disabled = step === 1;
    const nextBtn = document.getElementById(prefix === 'dec' ? 'decNextBtn' : 'ruleNextBtn');
    if (step === state.total) { nextBtn.style.visibility = 'hidden'; } else { nextBtn.style.visibility = 'visible'; }

    if (step === state.total) {
        if (prefix === 'dec') { renderDecoderReview(); generateDecoderXML(); }
        else { renderRuleReview(); generateRuleXML(); }
    }
}

function validateStep(prefix, step) {
    const state = wizardState[prefix];
    const required = (state.requiredByStep[step] || []);
    const missing = required.filter(id => !(document.getElementById(id)?.value || '').trim());
    if (missing.length) {
        const errEl = document.getElementById(prefix === 'dec' ? 'decoderError' : 'ruleError');
        const labels = missing.map(id => document.querySelector(`label[for="${id}"]`)?.textContent || id);
        showToast(`⚠ Lengkapi dulu: ${labels.join(', ')}`, 'warning');
        return false;
    }
    return true;
}

function reviewRow(label, value) {
    if (value === undefined || value === null || value === '' || (Array.isArray(value) && !value.length)) return '';
    const v = Array.isArray(value) ? value.join(', ') : value;
    return `<div class="col-6"><div class="text-muted" style="font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;">${esc(label)}</div><div>${v}</div></div>`;
}

async function fetchSids(q = '') {
    try {
        const res  = await fetch(`/api/autocomplete/sids?q=${encodeURIComponent(q)}`);
        const data = await res.json();
        return data.map(item => ({ value: String(item.id), label: `${item.id} - ${item.description || '(no description)'}` }));
    } catch { return []; }
}
async function fetchGroups(q = '') {
    try {
        const res  = await fetch(`/api/autocomplete/groups?q=${encodeURIComponent(q)}`);
        const data = await res.json();
        return data.map(g => ({ value: g, label: g }));
    } catch { return []; }
}
/* ─────────────────────────────────────────────────────────────────────
   Version History + Rollback modal (Phase 4 of the versioning roadmap)
   Used by both Saved Rules and Saved Decoders row-actions.
   - openHistoryModal('rule', ruleId)
   - openHistoryModal('decoder', { filename, name })
───────────────────────────────────────────────────────────────────── */

const CHANGE_SOURCE_LABELS = {
    app_edit: 'Edited',
    pull: 'Pulled from Wazuh',
    deleted: 'Deleted',
    rollback: 'Rollback',
};

async function openHistoryModal(kind, key) {
    const bodyEl = document.getElementById('historyModalBody');
    const titleEl = document.getElementById('historyModalTitle');
    titleEl.textContent = kind === 'decoder' ? `History: ${key.name}` : `History: Rule #${key}`;
    bodyEl.innerHTML = `<div class="text-muted p-3">Loading history...</div>`;
    new bootstrap.Modal(document.getElementById('historyModal')).show();

    const url = kind === 'decoder'
        ? `/builder/decoder/history?filename=${encodeURIComponent(key.filename)}&name=${encodeURIComponent(key.name)}`
        : `/builder/rule/${encodeURIComponent(key)}/history`;

    try {
        const res = await fetch(url);
        if (!res.ok) throw new Error();
        const entries = await res.json();
        renderHistoryList(kind, key, entries);
    } catch {
        bodyEl.innerHTML = `<div class="text-muted p-3">Failed to load history. Check the backend endpoint.</div>`;
    }
}

function renderHistoryList(kind, key, entries) {
    const bodyEl = document.getElementById('historyModalBody');
    if (!entries.length) {
        bodyEl.innerHTML = `<div class="text-muted p-3">No version history yet.</div>`;
        return;
    }

    bodyEl.innerHTML = entries.map((h, idx) => {
        const isCurrent = idx === 0; // entries sorted newest-first by the backend
        const isTombstone = h.change_source === 'deleted';
        const sourceLabel = CHANGE_SOURCE_LABELS[h.change_source] || h.change_source;
        const hasContent = kind === 'decoder'
            ? Array.isArray(h.snapshot) && h.snapshot.length > 0
            : !!h.snapshot;

        let subtitle;
        if (h.commit_message) {
            subtitle = esc(h.commit_message);
        } else if (kind === 'decoder') {
            const count = Array.isArray(h.snapshot) ? h.snapshot.length : 0;
            subtitle = count === 0
                ? '<span class="text-muted">Empty group (all siblings deleted)</span>'
                : `<span class="text-muted">${count} decoder(s), no commit message</span>`;
        } else {
            subtitle = h.snapshot
                ? `<span class="text-muted">Level ${esc(h.snapshot.level ?? '-')} · ${esc(h.snapshot.description ?? '')}</span>`
                : '<span class="text-muted">No content data</span>';
        }

        const rollbackBtn = (isCurrent || isTombstone) ? '' : `
               <button class="btn btn-outline-secondary btn-sm history-rollback-btn"
                       data-version="${h.version_number}">
                 Rollback to this version
               </button>`;
        const viewXmlBtn = hasContent ? `
               <button class="btn btn-outline-secondary btn-sm history-view-xml-btn"
                       data-version="${h.version_number}">
                 View XML
               </button>` : '';

        return `
            <div class="history-entry" style="border-bottom:1px solid var(--border-color, #2a2a2a); padding:10px 4px;">
                <div class="d-flex justify-content-between align-items-start gap-2">
                    <div>
                        <div>
                            <strong>v${h.version_number}</strong>
                            ${isCurrent ? '<span class="chip">Current</span>' : ''}
                            <span class="chip">${esc(sourceLabel)}</span>
                        </div>
                        <div style="margin-top:4px;">${subtitle}</div>
                        <div class="cell-muted" style="font-size:.8rem; margin-top:2px;">
                            ${esc(h.changed_by || 'system')} · ${fmtDate(h.changed_at)}
                        </div>
                    </div>
                    <div class="d-flex gap-2">${viewXmlBtn}${rollbackBtn}</div>
                </div>
            </div>`;
    }).join('');

    // Two-click inline confirm (button text flips to a confirmation
    // prompt on first click, executes on second) instead of stacking a
    // second Bootstrap modal on top of this one — rollback is also
    // non-destructive to history (see rollback_rule/rollback_decoder
    // docstrings in builder.py: it always records a NEW version rather
    // than erasing anything), so a lighter-weight confirm than the
    // full confirmDelete modal flow felt appropriate.
    bodyEl.querySelectorAll('.history-rollback-btn').forEach(btn => {
        btn.addEventListener('click', () => handleRollbackClick(btn, kind, key));
    });
    bodyEl.querySelectorAll('.history-view-xml-btn').forEach(btn => {
        const version = Number(btn.dataset.version);
        const entry = entries.find(e => e.version_number === version);
        btn.addEventListener('click', () => viewHistoryXml(kind, entry, version));
    });
}

async function viewHistoryXml(kind, entry, version) {
    try {
        if (kind === 'rule') {
            const res = await fetch('/builder/rule/xml', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(entry.snapshot),
            });
            const data = await res.json();
            openXmlModal(`Rule #${entry.rule_id} v${version}`, data.xml || '// no XML returned');
        } else {
            const parts = await Promise.all((entry.snapshot || []).map(async sib => {
                const res = await fetch('/builder/decoder/xml', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(sib),
                });
                const data = await res.json();
                return data.xml || '';
            }));
            const combined = parts.map(p => p.trim()).join('\n\n') || '// empty group in this version';
            openXmlModal(`${entry.name} v${version}`, combined);
        }
    } catch {
        showToast('Failed to load XML for this version.', 'danger');
    }
}

async function handleRollbackClick(btn, kind, key) {
    const version = btn.dataset.version;
    if (btn.dataset.confirming !== 'true') {
        btn.dataset.confirming = 'true';
        btn.textContent = 'Click again to confirm';
        btn.classList.remove('btn-outline-secondary');
        btn.classList.add('btn-outline-danger');
        setTimeout(() => {
            if (btn.dataset.confirming === 'true' && document.body.contains(btn)) {
                btn.dataset.confirming = 'false';
                btn.textContent = 'Rollback to this version';
                btn.classList.remove('btn-outline-danger');
                btn.classList.add('btn-outline-secondary');
            }
        }, 4000);
        return;
    }

    // Optional note for WHY this rollback is happening — becomes the new
    // version's commit_message. Native prompt() is a deliberate scope
    // choice here (not a themed modal) since this is a secondary,
    // skippable input on top of an already-confirmed action; empty/
    // cancelled input just falls back to the backend's auto-generated
    // "Rollback ke versi N" message (see rollback_rule/rollback_decoder).
    const commitMessage = (window.prompt('Rollback message (optional):', '') || '').trim();

    btn.disabled = true;
    btn.textContent = 'Processing...';
    try {
        const url = kind === 'decoder' ? '/builder/decoder/rollback' : `/builder/rule/${encodeURIComponent(key)}/rollback/${version}`;
        const bodyPayload = kind === 'decoder'
            ? { filename: key.filename, name: key.name, version_number: Number(version), commit_message: commitMessage }
            : { commit_message: commitMessage };
        const options = {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(bodyPayload),
        };

        const res = await fetch(url, options);
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Rollback failed.');

        const promo = data.promotion_request;
        if (!promo) {
            showToast(`Rollback to version ${version} succeeded. Content already matches the server, no promote needed.`, 'success');
        } else if (promo.success) {
            showToast(`Rollback to version ${version} succeeded. Promotion request submitted, awaiting reviewer approval.`, 'success');
        } else {
            showToast(`Rollback to version ${version} saved, but auto promotion request FAILED: ${promo.error || 'unknown reason'}. Submit manually via Sync & Manager.`, 'warning');
        }

        if (typeof loadPromotionQueue === 'function') loadPromotionQueue();

        bootstrap.Modal.getInstance(document.getElementById('historyModal'))?.hide();
        if (kind === 'decoder') { if (typeof loadDecoderTable === 'function') loadDecoderTable(); }
        else { if (typeof loadRuleTable === 'function') loadRuleTable(); }
    } catch (e) {
        showToast(`❌ ${e.message}`, 'danger');
        btn.disabled = false;
        btn.dataset.confirming = 'false';
        btn.textContent = 'Rollback to this version';
        btn.classList.remove('btn-outline-danger');
        btn.classList.add('btn-outline-secondary');
    }
}