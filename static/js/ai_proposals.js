/**
 * static/js/ai_proposals.js
 * Page-specific logic for GET /ai-proposals (templates/ai_proposals.html).
 *
 * AI proposals are DRAFTS only: they live in `ai_proposals` and never touch
 * the `rules` collection. This page lets a human review a draft, open it in
 * the Rule Builder (which prefills the wizard), or dismiss it. Nothing is
 * ever promoted automatically.
 *
 * Endpoints (blueprints/api.py):
 *   GET  /api/ai/proposals                 -> list (optional ?status=)
 *   POST /api/ai/proposals/generate        -> run pipeline once (manual trigger)
 *   POST /api/ai/proposals/<id>/dismiss    -> mark dismissed
 * CSRF ditangani global oleh csrf.js.
 */

let aiProposalsCache = [];
let currentProposalId = null;

function confidenceChip(confidence) {
    const c = (confidence || 'unknown').toLowerCase();
    const cls = { high: 'sev-low', medium: 'sev-medium', low: 'sev-high' }[c] || '';
    return `<span class="sev-badge ${cls}">${esc(c)}</span>`;
}

function severityChip(sev) {
    const s = (sev || '').toLowerCase();
    const cls = { critical: 'sev-critical', high: 'sev-high', medium: 'sev-medium', low: 'sev-low' }[s] || '';
    return s ? `<span class="sev-badge ${cls}">${esc(s)}</span>` : '<span class="text-muted">-</span>';
}

function statusChip(status) {
    const s = (status || 'pending').toLowerCase();
    const style = s === 'pending' ? '' : 'background:var(--surface-alt);color:var(--text-secondary)';
    return `<span class="chip" style="${style}">${esc(s)}</span>`;
}

function exploitChip(p) {
    const e = p.exploitdb;
    if (!e) return '<span class="text-muted">-</span>';
    if (e.status === 'error' || e.status === 'retry_pending' || e.status === 'exhausted') {
        return `<span class="sev-badge sev-medium" title="${esc(e.error || 'lookup failed')}">retry</span>`;
    }
    if (!e.found) return '<span class="text-muted">none</span>';
    const n = (e.matches || []).length;
    return `<span class="sev-badge sev-high">${n} EDB</span>`;
}

function renderExploitSection(p) {
    const e = p.exploitdb;
    if (!e) {
        return '<div class="detail-note mt-3">Exploit-DB: not checked (feature disabled or no CVE).</div>';
    }
    const matches = Array.isArray(e.matches) ? e.matches : [];
    const codeByEdb = {};
    (e.code || []).forEach((c) => { if (c && c.edb_id) codeByEdb[c.edb_id] = c; });

    const items = matches.map((m) => {
        const c = codeByEdb[m.edb_id];
        const code = c && c.code_excerpt
            ? `<pre class="detail-code">${esc(c.code_excerpt)}</pre>`
            : '';
        return `<div class="detail-sample">
            <div>
                <a href="${esc(m.url)}" target="_blank" rel="noopener noreferrer">EDB-${esc(m.edb_id)}</a>
                <span class="sev-badge ${m.verified ? 'sev-low' : 'sev-medium'}">${m.verified ? 'verified' : 'unverified'}</span>
            </div>
            <div class="small mt-1">${esc(m.title)}</div>
            <div class="text-muted small">${esc(m.type)} / ${esc(m.platform)} / ${esc(m.date_published)}</div>
            ${code}
        </div>`;
    }).join('');

    const status = e.status || (e.found ? 'ok' : 'empty');
    const note = e.new_since_proposal
        ? '<div class="detail-note mt-2"><i class="fa-solid fa-triangle-exclamation me-1"></i>Exploit baru ditemukan setelah proposal dibuat. Draft TIDAK diubah otomatis — review ulang rule ini.</div>'
        : '';
    return `<div class="mb-1 mt-3"><strong>Exploit-DB</strong> <span class="chip">${esc(status)}</span></div>
        ${e.error ? `<div class="text-muted small mb-2">${esc(e.error)}</div>` : ''}
        ${items || '<div class="text-muted">No public exploit found.</div>'}
        ${note}`;
}

async function loadAiProposals() {
    const tbody = document.getElementById('aiProposalsTableBody');
    const emptyEl = document.getElementById('aiProposalsEmpty');
    tableSkeleton(tbody, 8);
    emptyEl.classList.add('d-none');

    const status = document.getElementById('apStatusFilter')?.value ?? 'pending';
    const url = status ? `/api/ai/proposals?status=${encodeURIComponent(status)}` : '/api/ai/proposals';

    try {
        const res = await fetch(url);
        const data = await res.json();
        const items = Array.isArray(data) ? data : (data.items || []);
        aiProposalsCache = items;
        renderAiProposalsTable();
    } catch (err) {
        console.error('Load AI proposals error:', err);
        tbody.innerHTML = '';
        emptyEl.classList.remove('d-none');
        emptyEl.querySelector('h6').textContent = 'Unable to load data';
        emptyEl.querySelector('div').textContent = 'Failed to load: ' + esc(err.message);
    }
}

function renderAiProposalsTable() {
    const tbody = document.getElementById('aiProposalsTableBody');
    const emptyEl = document.getElementById('aiProposalsEmpty');
    const q = (document.getElementById('apSearchInput')?.value || '').trim().toLowerCase();

    const filtered = q ? aiProposalsCache.filter((p) =>
        [p.cve_id, p.vendor, p.product, p.advisory_title].some((v) => (v || '').toLowerCase().includes(q))
    ) : aiProposalsCache;

    if (!filtered.length) {
        tbody.innerHTML = '';
        emptyEl.classList.remove('d-none');
        emptyEl.querySelector('h6').textContent = q ? 'No results' : 'No AI proposals';
        emptyEl.querySelector('div').textContent = q
            ? `Nothing found for "${esc(q)}".`
            : 'Register your Tech Stack, enable the AI job (or click the wand), and proposals will appear here.';
        return;
    }

    emptyEl.classList.add('d-none');
    tbody.innerHTML = filtered.map((p) => {
        const ruleId = (p.rule_draft && (p.rule_draft.id || p.rule_draft.rule_id)) || '';
        return `
        <tr>
            <td class="cell-mono">${esc(p.cve_id) || '-'}</td>
            <td>${esc(p.vendor) || '-'}${p.product ? ` / ${esc(p.product)}` : ''}</td>
            <td>${severityChip(p.advisory_severity)}</td>
            <td>${confidenceChip(p.confidence)}</td>
            <td class="cell-mono">${esc(ruleId) || '-'}</td>
            <td>${exploitChip(p)}</td>
            <td>${statusChip(p.status)}</td>
            <td>
                <div class="row-actions">
                    <button class="icon-btn" title="Review" onclick="openProposalModal('${p._id}')">
                        <i class="fa-solid fa-eye"></i>
                    </button>
                    ${p.status === 'pending' ? `
                    <button class="icon-btn" title="Open in Rule Builder" onclick="openProposalInBuilder('${p._id}')">
                        <i class="fa-solid fa-pen-to-square"></i>
                    </button>
                    <button class="icon-btn danger" title="Dismiss" onclick="dismissProposal('${p._id}')">
                        <i class="fa-solid fa-ban"></i>
                    </button>` : ''}
                </div>
            </td>
        </tr>`;
    }).join('');
}

function _proposalById(id) {
    return aiProposalsCache.find((p) => p._id === id);
}

async function openProposalModal(id) {
    let p = _proposalById(id);
    if (!p) { showToast('Proposal not found, reload the page.', 'warning'); return; }
    currentProposalId = id;

    // Listing mengirim tanpa excerpt kode (code_omitted). Ambil detail agar
    // modal punya data lengkap; gagal = pakai data di cache.
    try {
        const res = await fetch(`/api/ai/proposals/${encodeURIComponent(id)}`);
        const data = await res.json();
        if (data && data.success && data.item) {
            p = data.item;
            const idx = aiProposalsCache.findIndex((x) => x._id === id);
            if (idx !== -1) aiProposalsCache[idx] = p;
        }
    } catch (err) {
        console.error('Load proposal detail error:', err);
    }

    document.getElementById('aiProposalModalTitle').textContent =
        `AI Proposal: ${p.cve_id || ''} (${p.vendor || ''}${p.product ? ' / ' + p.product : ''})`;

    const d = p.rule_draft || {};
    const mitre = Array.isArray(d.mitre_ids) ? d.mitre_ids.join(', ') : (d.mitre_ids || '');
    const rows = [
        ['Advisory title', esc(p.advisory_title) || '-'],
        ['Severity / Score', `${esc(p.advisory_severity) || '-'} / ${esc(p.advisory_score ?? '-')}`],
        ['Exploitation', esc(p.advisory_exploitation) || '-'],
        ['Ransomware', esc(p.advisory_ransomware) || '-'],
        ['Confidence', confidenceChip(p.confidence)],
        ['Proposed rule ID', `<code>${esc(d.id || d.rule_id || '') || '-'}</code>`],
        ['Level', esc(d.level ?? '-')],
        ['Description', esc(d.description) || '-'],
        ['if_sid / if_group', esc([d.if_sid, d.if_group].filter(Boolean).join(' / ')) || '-'],
        ['match / regex', `<code>${esc([d.match, d.regex].filter(Boolean).join('  |  ')) || '-'}</code>`],
        ['Fields', Array.isArray(d.fields) && d.fields.length
            ? d.fields.map((f) => `<code>${esc(f.name)}=${esc(f.value)}</code> (${esc(f.type || 'osregex')})`).join('<br>')
            : '-'],
        ['URL', Array.isArray(d.urls) && d.urls.length
            ? d.urls.map((u) => `<code>${esc(u.value)}</code>${u.type ? ' (' + esc(u.type) + ')' : ''}`).join('<br>')
            : '-'],
        ['Static fields', d.static_fields && Object.keys(d.static_fields).length
            ? Object.entries(d.static_fields).map(([k, arr]) =>
                (Array.isArray(arr) ? arr : [arr]).map((e) =>
                    `<code>${esc(k)}=${esc(e && e.value !== undefined ? e.value : e)}</code>`).join('<br>')).join('<br>')
            : '-'],
        ['Group', esc(d.group) || '-'],
        ['MITRE', esc(mitre) || '-'],
    ];

    const samples = Array.isArray(p.test_samples) && p.test_samples.length
        ? p.test_samples.map((s) => `
            <div class="detail-sample">
                <span class="sev-badge ${s.expect_match ? 'sev-low' : 'sev-medium'}">${s.expect_match ? 'MUST MATCH' : 'MUST NOT MATCH'}</span>
                <div class="font-monospace small mt-1">${esc(s.log)}</div>
                ${s.note ? `<div class="text-muted small mt-1">${esc(s.note)}</div>` : ''}
            </div>`).join('')
        : '<div class="text-muted">No test samples proposed. You must add at least one positive sample in the Rule Builder before saving.</div>';

    document.getElementById('aiProposalModalBody').innerHTML = `
        <div class="mb-3">
            ${p.rationale ? `<div class="mb-2"><strong>Rationale</strong><div>${esc(p.rationale)}</div></div>` : ''}
            ${p.notes ? `<div class="mb-2"><strong>Notes</strong><div>${esc(p.notes)}</div></div>` : ''}
        </div>
        <table class="detail-table">
            <tbody>
                ${rows.map(([k, v]) => `<tr><th>${k}</th><td>${v}</td></tr>`).join('')}
            </tbody>
        </table>
        <div class="mb-1"><strong>Proposed test samples</strong></div>
        ${samples}
        ${renderExploitSection(p)}
        <div class="detail-note mt-3">
            <i class="fa-solid fa-triangle-exclamation me-1"></i>
            This is an AI draft. It has NOT been saved and is NOT deployed. Open it in the Rule Builder to review every field, adjust the pattern, then save through the normal flow (validate, test on Dev, promote).
        </div>
    `;

    document.getElementById('aiProposalDismissBtn').disabled = p.status !== 'pending';
    const recheckBtn = document.getElementById('aiProposalRecheckBtn');
    if (recheckBtn) recheckBtn.disabled = p.status !== 'pending';
    document.getElementById('aiProposalOpenBtn').disabled = false;

    bootstrap.Modal.getOrCreateInstance(document.getElementById('aiProposalModal')).show();
}

function openProposalInBuilder(id) {
    if (!id) return;
    // The Rule Builder reads ?ai_proposal=<id> and prefills the wizard.
    window.location.href = `/rule?ai_proposal=${encodeURIComponent(id)}`;
}

function openCurrentProposalInBuilder() {
    openProposalInBuilder(currentProposalId);
}

async function dismissProposal(id) {
    if (!id) return;
    try {
        const res = await fetch(`/api/ai/proposals/${encodeURIComponent(id)}/dismiss`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: '{}',
        });
        const data = await res.json();
        if (!data.success) {
            showToast(data.error || 'Failed to dismiss.', 'danger');
            return;
        }
        bootstrap.Modal.getInstance(document.getElementById('aiProposalModal'))?.hide();
        showToast('Proposal dismissed.', 'success');
        loadAiProposals();
    } catch (err) {
        showToast('Request error: ' + err.message, 'danger');
    }
}

function dismissCurrentProposal() {
    dismissProposal(currentProposalId);
}

async function recheckCurrentProposalExploits() {
    if (!currentProposalId) return;
    const btn = document.getElementById('aiProposalRecheckBtn');
    if (btn) btn.disabled = true;
    try {
        const res = await fetch(
            `/api/ai/proposals/${encodeURIComponent(currentProposalId)}/recheck-exploits`,
            { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' },
        );
        const data = await res.json();
        if (!data.success) {
            showToast(data.error || 'Exploit-DB recheck failed.', 'danger');
            return;
        }
        showToast('Exploit-DB rechecked.', 'success');
        await loadAiProposals();
        if (_proposalById(currentProposalId)) await openProposalModal(currentProposalId);
    } catch (err) {
        showToast('Request error: ' + err.message, 'danger');
    } finally {
        if (btn) btn.disabled = false;
    }
}

let aiGenerating = false;

async function generateAiProposals() {
    // Re-entrancy guard: the pipeline can take minutes (KEV download + LLM
    // calls), so block a second run even if the click somehow slips through
    // (double-click, Enter key, or a programmatic call). The button is also
    // disabled, but the flag is the authoritative guard.
    if (aiGenerating) return;
    aiGenerating = true;

    const btn = document.getElementById('apGenerateBtn');
    const icon = btn ? btn.querySelector('i') : null;
    if (btn) {
        btn.disabled = true;
        btn.classList.add('is-loading');
        btn.setAttribute('aria-busy', 'true');
        if (icon) icon.className = 'fa-solid fa-spinner fa-spin';
    }
    showToast('Running AI pipeline. This can take a while (downloads the KEV feed and calls the model).', 'info');

    try {
        const res = await fetch('/api/ai/proposals/generate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ max_items: 5 }),
        });
        const data = await res.json();
        if (!data.success) {
            showToast(data.error || 'AI pipeline failed.', 'danger');
            return;
        }
        const parts = [`${data.generated || 0} new`];
        if (data.skipped_existing) parts.push(`${data.skipped_existing} already proposed`);
        if (data.duplicates) parts.push(`${data.duplicates} duplicate`);
        if (data.errors) parts.push(`${data.errors} failed`);
        showToast(`AI pipeline done: ${parts.join(', ')} (${data.relevant || 0} relevant CVEs).`, 'success');
        loadAiProposals();
    } catch (err) {
        showToast('Request error: ' + err.message, 'danger');
    } finally {
        aiGenerating = false;
        if (btn) {
            btn.disabled = false;
            btn.classList.remove('is-loading');
            btn.removeAttribute('aria-busy');
            if (icon) icon.className = 'fa-solid fa-wand-magic-sparkles';
        }
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('apSearchInput');
    if (searchInput) searchInput.addEventListener('input', debounce(() => {
        renderAiProposalsTable();
    }, 350));

    const statusFilter = document.getElementById('apStatusFilter');
    if (statusFilter) statusFilter.addEventListener('change', loadAiProposals);

    loadAiProposals();
});
