/**
 * static/js/rule_builder.js
 * Page-specific logic for GET /rule (templates/rule_builder.html).
 * Depends on common.js and sync_common.js (both loaded first via base.html).
 */

// ── Rule group tag input (Step 5) ────────────────────────────────────
// The Wazuh `group` field is a comma-separated list (e.g.
// "syslog,authentication_failed"). The visible UI is a tag input; the
// hidden input #rule_group always holds the canonical comma-joined value
// so existing save/edit code reading .value keeps working unchanged.

function _ruleGroupTags() {
    const raw = (document.getElementById('rule_group')?.value || '').trim();
    return raw ? raw.split(',').map((s) => s.trim()).filter(Boolean) : [];
}

function setRuleGroupValue(str) {
    const hidden = document.getElementById('rule_group');
    if (hidden) hidden.value = str || '';
    renderRuleGroupTags();
}

function renderRuleGroupTags() {
    const list = document.getElementById('rule_group_tag_list');
    const typer = document.getElementById('rule_group_typer');
    if (!list) return;
    const tags = _ruleGroupTags();
    list.innerHTML = tags.map((t) =>
        `<span class="tag-chip">${esc(t)}<button type="button" class="tag-chip-remove" data-tag="${esc(t)}" title="Remove group"><i class="fa-solid fa-xmark"></i></button></span>`
    ).join('');
    if (typer) typer.value = '';
}

function removeRuleGroupTag(tag) {
    const tags = _ruleGroupTags().filter((t) => t !== tag);
    setRuleGroupValue(tags.join(','));
    generateRuleXML(true);
}

function _commitRuleGroupTyper() {
    const typer = document.getElementById('rule_group_typer');
    if (!typer) return;
    const text = typer.value.trim();
    if (!text) return;
    const existing = new Set(_ruleGroupTags());
    const additions = text.split(',').map((s) => s.trim()).filter((s) => s && !existing.has(s));
    if (additions.length > 0) {
        setRuleGroupValue([..._ruleGroupTags(), ...additions].join(','));
    } else {
        typer.value = '';
    }
    generateRuleXML(true);
}

function initRuleGroupTagInput() {
    const typer = document.getElementById('rule_group_typer');
    const list = document.getElementById('rule_group_tag_list');
    if (!typer || !list) return;
    list.addEventListener('click', (e) => {
        const btn = e.target.closest('.tag-chip-remove');
        if (btn) removeRuleGroupTag(btn.dataset.tag);
    });
    typer.addEventListener('keydown', (e) => {
        if (e.key === ',' || e.key === 'Enter') {
            e.preventDefault();
            _commitRuleGroupTyper();
        } else if (e.key === 'Backspace' && typer.value === '') {
            // Remove the last tag on empty backspace, like chip inputs.
            const tags = _ruleGroupTags();
            tags.pop();
            setRuleGroupValue(tags.join(','));
            generateRuleXML(true);
        }
    });
    typer.addEventListener('blur', _commitRuleGroupTyper);
    renderRuleGroupTags();
}
if (document.getElementById('rule_group_typer')) initRuleGroupTagInput();

function renderRuleReview() {
    const p = collectRulePayload();
    const html = [
        reviewRow('ID', esc(p.rule_id) || '<span class="text-danger">missing</span>'),
        reviewRow('Level', p.level !== '' ? sevBadgeHTML(p.level) : ''),
        reviewRow('Description', esc(p.description) || '<span class="text-danger">missing</span>'),
        reviewRow('if_sid / if_group', [p.if_sid, p.if_group].filter(Boolean).join(' / ')),
        reviewRow('match', p.match ? `<code>${esc(p.match)}</code>` : ''),
        reviewRow('regex', p.regex ? `<code>${esc(p.regex)}</code>` : ''),
        reviewRow('URL', (p.urls || []).map(u => u.value)),
        reviewRow('Static fields', Object.entries(p.static_fields || {}).map(([k, v]) => `${k} (${v.length})`)),
        reviewRow('Fields', p.fields.map(f => f.name)),
        reviewRow('frequency/timeframe', (p.frequency || p.timeframe) ? `${p.frequency || '-'} / ${p.timeframe || '-'}s` : ''),
        reviewRow('group', renderGroupBadges(p.group)),
        reviewRow('MITRE', p.mitre_ids),
    ].filter(Boolean).join('');
    document.getElementById('ruleReviewSummary').innerHTML = html || '<div class="text-muted">Nothing filled in yet.</div>';
}
function addUrlRow(values) {
    const container = document.getElementById('urlRows');
    const row = document.createElement('div');
    row.className = 'dynamic-row d-flex gap-2 align-items-start url-row mb-2';
    row.innerHTML = `
        <textarea class="form-control form-control-sm font-monospace u-value" rows="1"
                  placeholder="e.g. /eval-stdin.php  or pcre2 pattern"></textarea>
        <select class="form-select form-select-sm u-type" style="max-width:110px">
            <option value="">osregex</option>
            <option value="osregex">osregex</option>
            <option value="osmatch">osmatch</option>
            <option value="pcre2">pcre2</option>
        </select>
        <div class="form-check form-check-inline mb-0 pt-1">
            <input class="form-check-input u-negate" type="checkbox" title="Negate">
            <label class="form-check-label small text-muted">negate</label>
        </div>
        <button type="button" class="icon-btn danger flex-shrink-0" onclick="removeRow(this)">✕</button>`;
    container.appendChild(row);
    if (values) {
        row.querySelector('.u-value').value = values.value || '';
        row.querySelector('.u-type').value  = values.type || '';
        row.querySelector('.u-negate').checked = !!values.negate;
    }
}

// Wazuh STATIC fields with their own dedicated elements (see
// services/wazuh_contract.py). `url` is intentionally excluded: it has its
// own URL Conditions section above.
const STATIC_FIELD_OPTIONS = [
    'srcip', 'dstip', 'srcport', 'dstport', 'id', 'status', 'data',
    'extra_data', 'user', 'system_name', 'program_name', 'protocol',
    'hostname', 'location', 'action', 'srcgeoip', 'dstgeoip',
];

function addStaticFieldRow(values) {
    const container = document.getElementById('staticFieldRows');
    if (!container) return;
    const row = document.createElement('div');
    row.className = 'dynamic-row d-flex gap-2 align-items-start static-field-row mb-2';
    const options = STATIC_FIELD_OPTIONS
        .map((f) => `<option value="${f}">${f}</option>`)
        .join('');
    row.innerHTML = `
        <select class="form-select form-select-sm sf-name" style="max-width:150px">
            ${options}
        </select>
        <textarea class="form-control form-control-sm font-monospace sf-value" rows="1"
                  placeholder="e.g. 10.0.0.1  or  pcre2 pattern"></textarea>
        <select class="form-select form-select-sm sf-type" style="max-width:110px">
            <option value="">default</option>
            <option value="osregex">osregex</option>
            <option value="osmatch">osmatch</option>
            <option value="pcre2">pcre2</option>
        </select>
        <div class="form-check form-check-inline mb-0 pt-1">
            <input class="form-check-input sf-negate" type="checkbox" title="Negate">
            <label class="form-check-label small text-muted">negate</label>
        </div>
        <button type="button" class="icon-btn danger flex-shrink-0" onclick="removeRow(this)">✕</button>`;
    container.appendChild(row);
    if (values) {
        row.querySelector('.sf-name').value = values.name || STATIC_FIELD_OPTIONS[0];
        row.querySelector('.sf-value').value = values.value || '';
        row.querySelector('.sf-type').value = values.type || '';
        row.querySelector('.sf-negate').checked = !!values.negate;
    }
}

function addFieldRow(values) {
    const container = document.getElementById('fieldRows');
    const row = document.createElement('div');
    row.className = 'dynamic-row d-flex gap-2 align-items-center field-row mb-2';
    row.innerHTML = `
        <input type="text" class="form-control form-control-sm f-name" placeholder="Field name (e.g. srcip)">
        <input type="text" class="form-control form-control-sm font-monospace f-value" placeholder="Pattern (e.g. \\d+\\.\\d+\\.\\d+\\.\\d+)">
        <select class="form-select form-select-sm f-type" style="max-width:110px">
            <option value="">osregex</option>
            <option value="osregex">osregex</option>
            <option value="osmatch">osmatch</option>
            <option value="pcre2">pcre2</option>
        </select>
        <div class="form-check form-check-inline mb-0">
            <input class="form-check-input f-negate" type="checkbox" title="Negate">
            <label class="form-check-label small text-muted">negate</label>
        </div>
        <button type="button" class="icon-btn danger flex-shrink-0" onclick="removeRow(this)">✕</button>`;
    container.appendChild(row);
    if (values) {
        row.querySelector('.f-name').value  = values.name || '';
        row.querySelector('.f-value').value = values.value || '';
        row.querySelector('.f-type').value  = values.type || '';
        row.querySelector('.f-negate').checked = !!values.negate;
    }
}

function addListRow(values) {
    const container = document.getElementById('listRows');
    const row = document.createElement('div');
    row.className = 'dynamic-row list-row mb-2';
    row.innerHTML = `
        <div class="d-flex gap-2 align-items-center flex-wrap">
            <input type="text" class="form-control form-control-sm l-field" style="max-width:130px" placeholder="field (e.g. srcip)">
            <select class="form-select form-select-sm l-lookup" style="max-width:205px">
                <option value="address_match_key">address_match_key</option>
                <option value="address_match_key_value">address_match_key_value</option>
                <option value="match_key">match_key</option>
                <option value="not_match_key">not_match_key</option>
            </select>
            <input type="text" class="form-control form-control-sm font-monospace l-path flex-grow-1" placeholder="e.g. etc/lists/ultimate-ipsets">
            <button type="button" class="icon-btn danger flex-shrink-0" onclick="removeRow(this)">✕</button>
        </div>`;
    container.appendChild(row);
    if (values) {
        row.querySelector('.l-field').value  = values.field || '';
        row.querySelector('.l-lookup').value = values.lookup || 'address_match_key';
        row.querySelector('.l-path').value   = values.path || '';
    }
}

function addSameFieldRow(value) {
    const container = document.getElementById('sameFieldRows');
    const row = document.createElement('div');
    row.className = 'dynamic-row d-flex gap-2 align-items-center same-field-row mb-2';
    row.innerHTML = `
        <input type="text" class="form-control form-control-sm sf-name" placeholder="Field name (e.g. user_agent)">
        <button type="button" class="icon-btn danger flex-shrink-0" onclick="removeRow(this)">✕</button>`;
    container.appendChild(row);
    if (value) row.querySelector('.sf-name').value = value;
}

function addMitreRow(value) {
    const container = document.getElementById('mitreRows');
    const row = document.createElement('div');
    row.className = 'dynamic-row d-flex gap-2 align-items-center mb-2';
    row.innerHTML = `
        <input type="text" class="form-control form-control-sm font-monospace mitre-id-input" placeholder="MITRE ID (e.g. T1110)">
        <button type="button" class="icon-btn danger flex-shrink-0" onclick="removeRow(this)">✕</button>`;
    container.appendChild(row);
    if (value) row.querySelector('.mitre-id-input').value = value;
}

function addInfoRow(values) {
    const container = document.getElementById('infoRows');
    const row = document.createElement('div');
    row.className = 'dynamic-row d-flex gap-2 align-items-center info-row mb-2';
    row.innerHTML = `
        <input type="text" class="form-control form-control-sm info-value" placeholder="e.g. Remote Code Execution or https://nvd.nist.gov/...">
        <select class="form-select form-select-sm info-type" style="max-width:100px">
            <option value="text">text</option>
            <option value="link">link</option>
            <option value="cve">cve</option>
            <option value="ovsdb">ovsdb</option>
        </select>
        <button type="button" class="icon-btn danger flex-shrink-0" onclick="removeRow(this)">✕</button>`;
    container.appendChild(row);
    if (values) {
        row.querySelector('.info-value').value = values.value || '';
        row.querySelector('.info-type').value  = values.type || 'text';
    }
}

/**
 * One "Test Sample" row: example log + expected match (or non-match),
 * optional note, and a Run button that tests via /tester/logtest (always Dev).
 */
function addTestSampleRow(values) {
    const container = document.getElementById('testSampleRows');
    const row = document.createElement('div');
    row.className = 'dynamic-row test-sample-row mb-2 p-2 border rounded';
    row.innerHTML = `
        <div class="d-flex gap-2 align-items-start mb-1">
            <textarea class="form-control form-control-sm font-monospace ts-log" rows="2" placeholder="Paste one log line here..."></textarea>
            <button type="button" class="icon-btn danger flex-shrink-0" onclick="removeRow(this)"><i class="fa-solid fa-xmark"></i></button>
        </div>
        <div class="d-flex gap-2 align-items-center flex-wrap">
            <select class="form-select form-select-sm ts-expect" style="max-width:220px">
                <option value="true">Must MATCH this rule</option>
                <option value="false">Must NOT match (negative test)</option>
            </select>
            <input type="text" class="form-control form-control-sm ts-note flex-grow-1" placeholder="Note (optional), e.g. normal brute force case">
            <button type="button" class="btn btn-sm btn-outline-secondary ts-run-btn flex-shrink-0" onclick="runTestSample(this)"><i class="fa-solid fa-play me-1"></i>Run</button>
        </div>
        <div class="ts-result small mt-1"></div>`;
    container.appendChild(row);
    if (values) {
        row.querySelector('.ts-log').value = values.log || '';
        row.querySelector('.ts-expect').value = values.expect_match === false ? 'false' : 'true';
        row.querySelector('.ts-note').value = values.note || '';
    }
}

/**
 * wazuh-logtest tests against the ACTIVE Dev ruleset (last push+reload),
 * not the draft in this wizard. Check sync_state.dev of the rule being
 * edited and show an honest status banner so PASS/FAIL badges are not
 * misleading: red if never saved, yellow if saved but not synced, green
 * if synced.
 */
async function updateDevSyncTestWarning() {
    const ruleId = (document.getElementById('rule_id')?.value || '').trim();
    const warningEl = document.getElementById('devSyncTestWarning');
    if (!warningEl) return;

    if (!ruleId) {
        warningEl.innerHTML = '';
        return;
    }

    try {
        const res = await fetch(`/builder/rule/${encodeURIComponent(ruleId)}`);
        if (res.status === 404) {
            warningEl.innerHTML = `<div class="alert alert-danger small py-2 mb-2"><i class="fa-solid fa-circle-exclamation me-1"></i>Rule ${escapeHtml(ruleId)} has not been saved to MongoDB yet. The results below do NOT reflect this draft (they test against the currently active Dev ruleset).</div>`;
            return;
        }
        if (!res.ok) { warningEl.innerHTML = ''; return; }

        const r = await res.json();
        const devStatus = r.sync_state && r.sync_state.dev && r.sync_state.dev.sync_status;

        if (devStatus === 'synced') {
            warningEl.innerHTML = `<div class="alert alert-success small py-2 mb-2"><i class="fa-solid fa-circle-check me-1"></i>Rule ${escapeHtml(ruleId)} is pushed and synced to Dev. Results below should reflect the saved draft.</div>`;
        } else {
            warningEl.innerHTML = `<div class="alert alert-warning small py-2 mb-2"><i class="fa-solid fa-triangle-exclamation me-1"></i>Rule ${escapeHtml(ruleId)} is saved but NOT re-pushed and reloaded to Dev since the last change. Results may reflect an OLD version. Push to Dev and Reload in Sync & Manager for accurate results.</div>`;
        }
    } catch (e) {
        warningEl.innerHTML = '';
    }
}

/**
 * Union of <order> fields for a decoder name, cached per page load.
 */
const _decoderOrderFieldsCache = {};
async function fetchDecoderOrderFields(name) {
    if (!name) return [];
    if (_decoderOrderFieldsCache[name]) return _decoderOrderFieldsCache[name];
    try {
        const res = await fetch(`/builder/decoder/order-fields?name=${encodeURIComponent(name)}`);
        const data = await res.json();
        const fields = data.order_fields || [];
        _decoderOrderFieldsCache[name] = fields;
        return fields;
    } catch (e) {
        console.warn('Failed to fetch decoder order fields:', e);
        return [];
    }
}

/**
 * Grade a /tester/logtest response against one Test Sample's expectation.
 * The valid Wazuh verdict lives at output.rule (direct child of output);
 * any nested "rule" key inside log data is just log content, not a verdict.
 * A top-level response `error` (outside `data`) means logtest itself
 * failed to run, separate from match/no-match.
 *
 * For expect_match=true, the rule must match AND all <order> fields of
 * the decoder actually used (output.decoder.name) must be extracted
 * (present and non-empty) in output.data. This extraction check is
 * intentionally skipped for expect_match=false.
 */
async function gradeLogtestResult(data, targetRuleId, expectMatch) {
    if (data && data.error !== undefined && data.error !== 0 && data.error !== null) {
        return {
            passed: false,
            reason: `Logtest error (code ${data.error}): ${(data.data && data.data.messages || []).join(' ') || 'no detail.'}`,
            matchedRuleId: null,
        };
    }

    const output = (data && data.data && data.data.output) || {};
    const ruleInfo = output.rule || {};
    const matchedRuleId = ruleInfo.id ?? null; // string, e.g. "102103"
    const actuallyMatchedTarget = matchedRuleId !== null && String(matchedRuleId) === String(targetRuleId);

    if (!expectMatch) {
        return {
            passed: !actuallyMatchedTarget,
            reason: !actuallyMatchedTarget
                ? `Rule ${targetRuleId} did not match, as expected (negative test).`
                : `Expected NO match, but rule ${targetRuleId} triggered.`,
            matchedRuleId,
        };
    }

    // expect_match = true from here down.
    if (!actuallyMatchedTarget) {
        return {
            passed: false,
            reason: matchedRuleId
                ? `Expected rule ${targetRuleId} to match, but rule ${matchedRuleId} matched.`
                : `Expected rule ${targetRuleId} to match, but no rule matched at all.`,
            matchedRuleId,
        };
    }

    // Rule matched: now check decoder extraction quality.
    const decoderName = (output.decoder && output.decoder.name) || null;
    const extractedData = output.data || {};
    const orderFields = await fetchDecoderOrderFields(decoderName);
    const missingFields = orderFields.filter((f) => {
        const val = extractedData[f];
        return val === undefined || val === null || val === '';
    });

    if (missingFields.length > 0) {
        return {
            passed: false,
            reason: `Rule ${targetRuleId} matched, but decoder "${decoderName}" failed to extract fields: ${missingFields.join(', ')}. (If this decoder has siblings with different <order>, this may be a false alarm; verify manually.)`,
            matchedRuleId,
        };
    }

    return {
        passed: true,
        reason: orderFields.length > 0
            ? `Rule ${targetRuleId} matched; all decoder fields "${decoderName}" (${orderFields.join(', ')}) extracted.`
            : `Rule ${targetRuleId} matched as expected.`,
        matchedRuleId,
    };
}

/**
 * Run one sample via /tester/logtest (always Dev) and grade it against
 * the Rule ID currently entered in Step 1.
 */
async function runTestSample(btn) {
    const row = btn.closest('.test-sample-row');
    const log = row.querySelector('.ts-log').value.trim();
    const expectMatch = row.querySelector('.ts-expect').value === 'true';
    const resultEl = row.querySelector('.ts-result');
    const targetRuleId = (document.getElementById('rule_id')?.value || '').trim();

    if (!log) {
        resultEl.innerHTML = '<span class="text-danger">Enter a log before running.</span>';
        return;
    }
    if (!targetRuleId) {
        resultEl.innerHTML = '<span class="text-danger">Enter a Rule ID (Step 1) before running the test.</span>';
        return;
    }

    await updateDevSyncTestWarning();

    const originalText = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>';
    resultEl.innerHTML = '<span class="text-muted">Running logtest on Dev...</span>';

    try {
        const res = await fetch('/tester/logtest', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ log }),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Failed to run logtest.');

        const grade = await gradeLogtestResult(data, targetRuleId, expectMatch);
        const badgeClass = grade.passed ? 'text-success' : 'text-danger';
        const badgeText = grade.passed ? 'PASS' : 'FAIL';

        // Stash the grade on the row so runAllTestSamples() can collect
        // results without re-running logtest per sample.
        row.dataset.lastGrade = JSON.stringify({ passed: grade.passed, matchedRuleId: grade.matchedRuleId, reason: grade.reason });

        resultEl.innerHTML = `
            <div class="${badgeClass} fw-bold mb-1"><i class="fa-solid ${grade.passed ? 'fa-circle-check' : 'fa-circle-xmark'} me-1"></i>${badgeText} - ${escapeHtml(grade.reason)}</div>
            <details>
                <summary class="text-muted" style="cursor:pointer;">View raw response</summary>
                <pre class="mb-0 mt-1" style="white-space:pre-wrap; max-height:220px; overflow:auto;">${escapeHtml(JSON.stringify(data, null, 2))}</pre>
            </details>`;
    } catch (e) {
        resultEl.innerHTML = `<span class="text-danger"><i class="fa-solid fa-circle-exclamation me-1"></i>${escapeHtml(e.message)}</span>`;
        delete row.dataset.lastGrade;
    } finally {
        btn.disabled = false;
        btn.innerHTML = originalText;
    }
}

/**
 * [8 September 2026] Deploy SATU rule ke Wazuh Dev + reload analysisd,
 * dipanggil otomatis oleh runAllTestSamples() TANPA modal konfirmasi.
 *
 * wazuh-logtest menguji terhadap ruleset yang SEDANG AKTIF di Dev, jadi
 * test samples baru akurat kalau versi terbaru rule sudah di-deploy.
 * Batasan "Opsi 1 terbatas": satu file, hanya Dev, hanya rule custom,
 * tidak pernah force (conflict -> endpoint balikin 409).
 *
 * Return {ok: true, reason: 'deployed'|'already_synced', ...} kalau
 * test boleh dijalankan terhadap versi terkini, atau
 * {ok: false, reason, error} kalau terblokir (hasil nanti TIDAK
 * disimpan ke test_results/lifecycle -- lihat runAllTestSamples).
 */
async function deployRuleToDev(ruleId) {
    try {
        const res = await fetch(`/builder/rule/${encodeURIComponent(ruleId)}/deploy-dev`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({}),
        });
        const data = await res.json();
        if (res.ok) {
            if (data.deployed) {
                return { ok: true, reason: 'deployed', message: data.message || `Rule ${ruleId} deployed to Dev & reloaded.` };
            }
            if (data.reason === 'already_synced') {
                return { ok: true, reason: 'already_synced', message: data.message || `Rule ${ruleId} already synced to Dev.` };
            }
        }
        return { ok: false, reason: data.reason || 'deploy_failed', error: data.error || 'Deploy to Dev failed.' };
    } catch (e) {
        console.error('Deploy rule to Dev error:', e);
        return { ok: false, reason: 'network_error', error: `Deploy to Dev failed: ${e.message}` };
    }
}

/**
 * Run ALL test samples in sequence, then submit the complete result
 * snapshot to the server (POST /builder/rule/<id>/test-results) so
 * lifecycle_status updates permanently, not just in the browser.
 *
 * [8 September 2026] Orkestrasi baru ("Opsi 1 terbatas", tanpa modal):
 *   1. Save rule ke MongoDB dulu (prasyarat: deploy membaca dari DB,
 *      bukan dari form wizard).
 *   2. Deploy otomatis ke Dev + reload (deployRuleToDev). Ini yang
 *      memastikan test samples diuji terhadap versi TERKINI di Dev,
 *      bukan ruleset lama -- sesuai alur LARAS
 *      (Draft -> Deploy Dev -> Reload Dev -> Logtest).
 *   3. Jalankan semua sample.
 *   4. Simpan snapshot hasil HANYA kalau test benar-benar dijalankan
 *      terhadap versi terkini (deployed / already_synced). Kalau deploy
 *      terblokir (builtin/conflict/DB down/push gagal), samples tetap
 *      jalan sebagai PREVIEW tapi hasilnya TIDAK disimpan ke
 *      test_results / lifecycle_status (Opsi 3: jangan biarkan
 *      keputusan permanen dicatat berdasarkan pengujian terhadap
 *      ruleset yang salah versi).
 */
async function runAllTestSamples() {
    const ruleId = (document.getElementById('rule_id')?.value || '').trim();
    if (!ruleId) {
        if (typeof showToast === 'function') showToast('Enter a Rule ID (Step 1) before running the test.', 'warning');
        return;
    }

    // 1) Simpan dulu supaya MongoDB punya versi terbaru (sumber XML push).
    const saved = await saveRule({ silent: true });
    if (!saved) {
        if (typeof showToast === 'function') showToast('Rule failed to save. Fix the errors before running all samples.', 'danger');
        return;
    }

    // 2) Deploy otomatis ke Dev + reload (tanpa modal konfirmasi).
    const deploy = await deployRuleToDev(ruleId);
    const canCommitResults = deploy.ok;
    if (deploy.ok) {
        if (typeof showToast === 'function') showToast(`<i class="fa-solid fa-circle-check me-1"></i>${deploy.message}`, 'success');
    } else {
        if (typeof showToast === 'function') {
            showToast(`<i class="fa-solid fa-triangle-exclamation me-1"></i>${deploy.error} Results shown are a PREVIEW against the currently active Dev ruleset and will NOT be saved.`, 'warning');
        }
    }

    // 3) Jalankan semua sample berurutan.
    const rows = document.querySelectorAll('.test-sample-row');
    const results = [];
    for (const row of rows) {
        const btn = row.querySelector('.ts-run-btn');
        if (!btn) continue;
        await runTestSample(btn);

        // Read back what runTestSample() just rendered, so logtest is not
        // run twice for the same sample. The grade is stashed in the row's
        // dataset after grading.
        const grade = row.dataset.lastGrade ? JSON.parse(row.dataset.lastGrade) : null;
        if (grade) {
            results.push({
                log: row.querySelector('.ts-log').value.trim(),
                expect_match: row.querySelector('.ts-expect').value === 'true',
                passed: grade.passed,
                matched_rule_id: grade.matchedRuleId,
                reason: grade.reason,
            });
        }
    }

    if (results.length === 0) return;

    // 4) Simpan hasil HANYA kalau test dijalankan terhadap versi terkini.
    if (!canCommitResults) return;

    try {
        const res = await fetch(`/builder/rule/${encodeURIComponent(ruleId)}/test-results`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ samples: results }),
        });
        const data = await res.json();
        if (res.ok && data.saved) {
            if (typeof showToast === 'function') {
                showToast(data.all_passed ? '<i class="fa-solid fa-circle-check me-1"></i>All test samples passed. Results saved.' : '<i class="fa-solid fa-triangle-exclamation me-1"></i>Some test samples failed. Results saved.', data.all_passed ? 'success' : 'warning');
            }
            updateLifecycleStepper(data.lifecycle_status);
        } else if (res.status === 404) {
            if (typeof showToast === 'function') showToast('<i class="fa-solid fa-circle-info me-1"></i>Save this rule first (Save to MongoDB) so test results can be recorded.', 'secondary');
        }
    } catch (e) {
        console.error('Failed to save test results:', e);
    }
}

/**
 * Re-render the lifecycle_status stepper in Step 6, called after Run All
 * Samples finishes and saves, and after the rule is saved.
 */
function updateLifecycleStepper(status) {
    const container = document.getElementById('ruleLifecycleStepper');
    if (!container || !status) return;
    container.innerHTML = renderLifecycleStepper(status, false);
}

/**
 * Fetch the current lifecycle_status from the server (not computed
 * client-side) for the rule being edited, then render the stepper.
 * Called when editRule() loads an existing rule.
 */
async function refreshLifecycleStepper(ruleId) {
    const container = document.getElementById('ruleLifecycleStepper');
    if (!container) return;
    if (!ruleId) { container.innerHTML = ''; return; }

    try {
        const res = await fetch(`/builder/rule/${encodeURIComponent(ruleId)}`);
        if (!res.ok) { container.innerHTML = ''; return; }
        const r = await res.json();
        updateLifecycleStepper(r.lifecycle_status);
    } catch (e) {
        container.innerHTML = '';
    }
}

function collectRulePayload() {
    const urls = [];
    document.querySelectorAll('.url-row').forEach(row => {
        const value = row.querySelector('.u-value').value.trim();
        const type  = row.querySelector('.u-type').value;
        const neg   = row.querySelector('.u-negate').checked;
        if (value) urls.push({ value, type, negate: neg });
    });

    const fields = [];
    document.querySelectorAll('.field-row').forEach(row => {
        const name  = row.querySelector('.f-name').value.trim();
        const value = row.querySelector('.f-value').value.trim();
        const type  = row.querySelector('.f-type').value;
        const neg   = row.querySelector('.f-negate').checked;
        if (name && value) fields.push({ name, value, type, negate: neg });
    });

    // Static fields (dedicated elements): grouped as {name: [{value,type,negate}]}.
    const staticFields = {};
    document.querySelectorAll('.static-field-row').forEach(row => {
        const name  = row.querySelector('.sf-name').value.trim();
        const value = row.querySelector('.sf-value').value.trim();
        const type  = row.querySelector('.sf-type').value;
        const neg   = row.querySelector('.sf-negate').checked;
        if (name && value) {
            (staticFields[name] = staticFields[name] || []).push({ value, type, negate: neg });
        }
    });

    const lists = [];
    document.querySelectorAll('.list-row').forEach(row => {
        const field  = row.querySelector('.l-field').value.trim();
        const lookup = row.querySelector('.l-lookup').value;
        const path   = row.querySelector('.l-path').value.trim();
        if (field && path) lists.push({ field, lookup, path });
    });

    const sameFields = [];
    document.querySelectorAll('.same-field-row').forEach(row => {
        const v = row.querySelector('.sf-name').value.trim();
        if (v) sameFields.push(v);
    });

    const infoEntries = [];
    document.querySelectorAll('.info-row').forEach(row => {
        const value = row.querySelector('.info-value').value.trim();
        const type  = row.querySelector('.info-type').value;
        if (value) infoEntries.push({ value, type });
    });

    const mitreIds = [];
    document.querySelectorAll('.mitre-id-input').forEach(inp => {
        const v = inp.value.trim();
        if (v) mitreIds.push(v);
    });

    const options = [];
    ['opt_no_log', 'opt_no_full_log', 'opt_no_email_alert', 'opt_alert_by_email'].forEach(id => {
        const el = document.getElementById(id);
        if (el && el.checked) options.push(el.value);
    });

    // Collect Test Samples from the DOM.
    const testSamples = [];
    document.querySelectorAll('.test-sample-row').forEach(row => {
        const log = row.querySelector('.ts-log').value.trim();
        const expectMatch = row.querySelector('.ts-expect').value === 'true';
        const note = row.querySelector('.ts-note').value.trim();
        if (log) testSamples.push({ log, expect_match: expectMatch, note: note || null });
    });

    const getChoicesVal = (choicesInstance, delimiter = ',') => {
        if (!choicesInstance) return '';
        const raw = choicesInstance.getValue(true); // Mengembalikan Array, string, atau null
        if (Array.isArray(raw)) {
            return raw.map(v => String(v).trim()).filter(Boolean).join(delimiter);
        }
        return raw ? String(raw).trim() : '';
    };

    return {
        rule_id:          document.getElementById('rule_id').value.trim(),
        level:            document.getElementById('rule_level').value,
        description:      document.getElementById('rule_description').value.trim(),
        decoded_as:       getChoicesValue('rule_decoded_as'),
        if_sid:           getChoicesVal(choicesIfSid, ','),    // Output: "31100,31102"
        if_group:         getChoicesVal(choicesIfGroup, '|'), // Output: "blackhat_seo|seo_cloaking"
        if_level:         document.getElementById('rule_if_level').value.trim(),
        if_matched_sid:   document.getElementById('rule_if_matched_sid').value.trim(),
        if_matched_group: document.getElementById('rule_if_matched_group').value.trim(),
        match:            document.getElementById('rule_match').value.trim(),
        match_type:       document.getElementById('rule_match_type').value,
        regex:            document.getElementById('rule_regex').value.trim(),
        regex_type:       document.getElementById('rule_regex_type').value,
        urls, fields, lists,
        static_fields:    staticFields,
        time:             document.getElementById('rule_time').value.trim(),
        same_srcip:       document.getElementById('rule_same_srcip').checked,
        different_srcip:  document.getElementById('rule_different_srcip').checked,
        same_url:         document.getElementById('rule_same_url').checked,
        same_fields:      sameFields,
        group:            document.getElementById('rule_group').value.trim(),
        mitre_ids:        mitreIds,
        info:             infoEntries,
        info_type:        '',
        frequency:        document.getElementById('rule_frequency').value.trim(),
        timeframe:        document.getElementById('rule_timeframe').value.trim(),
        ignore:           document.getElementById('rule_ignore').value.trim(),
        options,
        filename:         (document.getElementById('rule_filename')?.value || '').trim(),
        wrapper_group:    (document.getElementById('rule_wrapper_group')?.value || '').trim(),
        commit_message:   (document.getElementById('rule_commit_message')?.value || '').trim(),
        // At least one entry with expect_match=true is required before
        // saving; validated client-side and re-validated in the backend
        // (blueprints/builder.py). Deliberately NOT in RULE_CONTENT_FIELDS:
        // QA metadata only, never sent as part of the rule XML to Wazuh.
        test_samples:     testSamples,
        // Tech Stack linkage: list of ObjectId strings from choicesTechStack.
        // LARAS metadata only, does not affect the rule XML (separated by
        // RULE_CONTENT_FIELDS in sync_utils.py).
        tech_stack_ids:   choicesTechStack ? choicesTechStack.getValue(true) : [],
    };
}

async function generateRuleXML(silent) {
    const payload = collectRulePayload();
    const errEl   = document.getElementById('ruleError');
    if (!silent) errEl.textContent = '';
    if (!payload.rule_id || !payload.description) { if (!silent) errEl.textContent = 'Rule ID and description are required.'; return; }
    try {
        const res  = await fetch('/builder/rule/xml', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        const data = await res.json();
        if (data.xml) { document.getElementById('ruleOutput').textContent = data.xml; }
        else if (!silent) { errEl.textContent = data.error || 'Unknown error'; }
    } catch (e) { if (!silent) errEl.textContent = e.message; }
}
async function saveRule({ silent = false } = {}) {
    const payload = collectRulePayload();
    const errEl   = document.getElementById('ruleError');
    const saveBtn = document.getElementById('btnSaveRule');
    errEl.textContent = '';

    // Client-side validation for instant UX; the backend re-validates in
    // save_rule() and remains the source of truth.
    if (!payload.test_samples || payload.test_samples.length === 0) {
        errEl.textContent = 'At least 1 Test Sample is required before the rule can be saved.';
        goToStep('rule', 6);
        return false;
    }
    if (!payload.test_samples.some(s => s.expect_match === true)) {
        errEl.textContent = 'At least 1 Test Sample with "Must MATCH" is required (not only negative tests).';
        goToStep('rule', 6);
        return false;
    }

    if (saveBtn) saveBtn.disabled = true;
    try {
        const res  = await fetch('/builder/rule/save', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        const data = await res.json();
        if (data.xml) {
            document.getElementById('ruleOutput').textContent = data.xml;
            if (!silent) {
                showToast(data.upserted ? '<i class="fa-solid fa-circle-check me-1"></i>Rule saved (new).' : '<i class="fa-solid fa-circle-check me-1"></i>Rule updated.', 'success');
            }
            if (data.compat_warnings && data.compat_warnings.length > 0) {
                showToast('<i class="fa-solid fa-triangle-exclamation me-1"></i>' + data.compat_warnings.join(' '), 'warning');
            }
            if (typeof populateFilenameOptions === 'function') populateFilenameOptions();
            loadSidebarCounts();
            if (typeof updateLifecycleStepper === 'function' && data.lifecycle_status) {
                updateLifecycleStepper(data.lifecycle_status);
            }
            return true;
        } else { errEl.textContent = data.error || 'Unknown error'; }
    } catch (e) { errEl.textContent = e.message; }
    finally { if (saveBtn) saveBtn.disabled = false; }
    return false;
}
function clearRule() {
    ['rule_id', 'rule_description',
     'rule_if_level', 'rule_if_matched_sid', 'rule_if_matched_group',
     'rule_match', 'rule_regex',
     'rule_frequency', 'rule_timeframe', 'rule_ignore',
     'rule_time', 'rule_wrapper_group', 'rule_commit_message'].forEach(id => { const el = document.getElementById(id); if (el) el.value = ''; });
    document.getElementById('rule_level').value = 3;
    document.getElementById('rule_match_type').value = '';
    document.getElementById('rule_regex_type').value = '';
    setRuleGroupValue('');
    if (choicesRuleFilename) { choicesRuleFilename.clearStore(); choicesRuleFilename.clearInput(); }
    ['opt_no_log', 'opt_no_full_log', 'opt_no_email_alert', 'opt_alert_by_email',
     'rule_same_srcip', 'rule_different_srcip', 'rule_same_url'].forEach(id => {
        const el = document.getElementById(id); if (el) el.checked = false;
    });
    if (choicesIfSid)     { choicesIfSid.clearStore();     choicesIfSid.clearInput(); }
    if (choicesIfGroup)   { choicesIfGroup.clearStore();   choicesIfGroup.clearInput(); }
    if (choicesDecodedAs) { choicesDecodedAs.clearStore(); choicesDecodedAs.clearInput(); }
    if (choicesTechStack) { choicesTechStack.clearStore(); choicesTechStack.clearInput(); }

    ['urlRows', 'staticFieldRows', 'fieldRows', 'listRows', 'sameFieldRows', 'mitreRows', 'infoRows', 'testSampleRows'].forEach(id => {
        const el = document.getElementById(id); if (el) el.innerHTML = '';
    });
    const stepperEl = document.getElementById('ruleLifecycleStepper');
    if (stepperEl) stepperEl.innerHTML = '';
    document.getElementById('ruleOutput').textContent = '';
    document.getElementById('ruleError').textContent  = '';
    delete document.getElementById('tabRule').dataset.editingId;
    updateLevelSevHint();
    goToStep('rule', 1);
}

function startNewRule() {
    clearRule();
    document.querySelector('.sidebar-menu[data-bs-target="#tabRule"]').click();
    setActiveNav(document.querySelector('.sidebar-menu[data-bs-target="#tabRule"]'));
}
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
function getIfSidValue() {
    if (!choicesIfSid) return '';
    const vals = choicesIfSid.getValue(true);
    return Array.isArray(vals) ? vals.join(',') : (vals || '');
}

function getIfGroupValue() {
    if (!choicesIfGroup) return '';
    const vals = choicesIfGroup.getValue(true);
    return Array.isArray(vals) ? vals.join('|') : (vals || '');
}

/**
 * Prefill the Rule Builder wizard from an AI proposal draft.
 *
 * This is the "human-in-the-loop handoff": the AI never writes to `rules`.
 * The proposal lives in `ai_proposals` (status pending) until a human opens
 * it here, reviews/edits every field, adds/keeps test samples, and presses
 * Save — which runs the normal save path (backend validation, test_samples
 * requirement, lifecycle starts at `draft`).
 *
 * `proposal` is the object returned by GET /api/ai/proposals: it carries
 * `rule_draft` (the LLM's proposed rule fields) and `test_samples`.
 * Mapping mirrors editRule() so the same DOM helpers are reused.
 */
/**
 * Coerce an AI-provided value into a plain string for an <input>/<textarea>.
 *
 * The LLM occasionally returns a field-scoped object for match/regex
 * (e.g. {"url": "\.php$"}). Assigning that straight to .value stringifies it
 * to "[object Object]" (bug seen 29 September 2026). The backend normalizer
 * (services/ai_utils.py) already fixes this at the source; this is the
 * frontend safety net so a bad draft can never silently produce garbage XML.
 */
function _aiScalar(value) {
    if (value === null || value === undefined) return '';
    if (typeof value === 'string') return value;
    if (typeof value === 'number') return String(value);
    if (typeof value === 'boolean') return '';
    if (Array.isArray(value)) {
        return value.map(_aiScalar).filter(Boolean).join(',');
    }
    if (typeof value === 'object') {
        // Pull the first usable scalar (prefer common keys), else join pairs
        // as "field=pattern" so the human at least sees the intent to fix.
        for (const k of ['value', 'pattern', 'text', 'content']) {
            if (k in value) return _aiScalar(value[k]);
        }
        return Object.entries(value)
            .map(([k, v]) => `${k}=${_aiScalar(v)}`)
            .filter((s) => !s.endsWith('='))
            .join(' | ');
    }
    return '';
}

function prefillRuleFromProposal(proposal) {
    if (!proposal || typeof proposal !== 'object') return;
    const d = proposal.rule_draft || {};

    if (typeof clearRule === 'function') clearRule();

    // if_sid (comma list) / if_group (comma or pipe list) — may arrive as a
    // string or an array depending on what the LLM returned.
    if (choicesIfSid) {
        choicesIfSid.clearStore();
        const sids = _asList(d.if_sid);
        if (sids.length) {
            choicesIfSid.setChoices(sids.map((s) => ({ value: s, label: s, selected: true })), 'value', 'label', true);
        }
    }
    if (choicesIfGroup) {
        choicesIfGroup.clearStore();
        const groups = _asList(d.if_group);
        if (groups.length) {
            choicesIfGroup.setChoices(groups.map((g) => ({ value: g, label: g, selected: true })), 'value', 'label', true);
        }
    }

    setVal('rule_id', _aiScalar(d.id ?? d.rule_id));
    setVal('rule_level', _aiScalar(d.level ?? 3));
    setVal('rule_description', _aiScalar(d.description));
    setVal('rule_if_level', _aiScalar(d.if_level));
    setVal('rule_if_matched_sid', _aiScalar(d.if_matched_sid));
    setVal('rule_if_matched_group', _aiScalar(d.if_matched_group));
    setVal('rule_match', _aiScalar(d.match));
    setVal('rule_match_type', _aiScalar(d.match_type));
    setVal('rule_regex', _aiScalar(d.regex));
    setVal('rule_regex_type', _aiScalar(d.regex_type));
    setVal('rule_time', _aiScalar(d.time));
    setVal('rule_frequency', _aiScalar(d.frequency));
    setVal('rule_timeframe', _aiScalar(d.timeframe));
    setVal('rule_ignore', _aiScalar(d.ignore));
    setRuleGroupValue(_aiScalar(d.group));

    setChecked('rule_same_srcip', d.same_srcip);
    setChecked('rule_different_srcip', d.different_srcip);
    setChecked('rule_same_url', d.same_url);

    if (Array.isArray(d.urls) && typeof addUrlRow === 'function') d.urls.forEach(addUrlRow);
    if (typeof populateStaticFields === 'function') populateStaticFields(d.static_fields);
    if (Array.isArray(d.fields) && typeof addFieldRow === 'function') d.fields.forEach(addFieldRow);
    if (Array.isArray(d.lists) && typeof addListRow === 'function') d.lists.forEach(addListRow);
    if (Array.isArray(d.same_fields) && typeof addSameFieldRow === 'function') d.same_fields.forEach(addSameFieldRow);
    if (Array.isArray(d.mitre_ids) && typeof addMitreRow === 'function') d.mitre_ids.forEach(addMitreRow);
    if (Array.isArray(d.info) && typeof addInfoRow === 'function') d.info.forEach(addInfoRow);

    if (Array.isArray(proposal.test_samples) && typeof addTestSampleRow === 'function') {
        proposal.test_samples.forEach(addTestSampleRow);
    }
    if (typeof setTechStackSelection === 'function') {
        setTechStackSelection(Array.isArray(proposal.tech_stack_ids) ? proposal.tech_stack_ids : []);
    }

    if (typeof updateLevelSevHint === 'function') updateLevelSevHint();
    document.getElementById('ruleOutput').textContent = '';
    if (typeof generateRuleXML === 'function') generateRuleXML(true);
    if (typeof goToStep === 'function') goToStep('rule', 1);

    // Mark provenance so the human knows this is an AI draft, not an existing
    // saved rule (editRule sets dataset.editingId; we deliberately do NOT set
    // it — saving must create/update by rule_id through the normal path).
    const tab = document.getElementById('tabRule');
    if (tab) {
        tab.dataset.aiProposalId = proposal._id || '';
        tab.dataset.aiProposalCve = proposal.cve_id || '';
    }
    if (typeof showToast === 'function') {
        showToast(
            `<i class="fa-solid fa-robot me-1"></i>AI draft loaded${proposal.cve_id ? ' for ' + esc(proposal.cve_id) : ''}. Review every field before saving.`,
            'warning',
        );
    }
}

/** Coerce a value that may be a string ("a,b"), array, or null into a list of non-empty strings. */
function _asList(value) {
    if (Array.isArray(value)) return value.map((v) => String(v).trim()).filter(Boolean);
    if (typeof value === 'string') return value.split(/[,|]/).map((v) => v.trim()).filter(Boolean);
    if (value === null || value === undefined || value === '') return [];
    return [String(value).trim()];
}

/**
 * Populate the Static Field Conditions rows from a `static_fields` map:
 * {"srcip": [{"value": ..., "type": ..., "negate": ...}], ...}.
 * `url` is skipped because it belongs to the URL Conditions section.
 */
function populateStaticFields(staticFields) {
    if (!staticFields || typeof staticFields !== 'object') return;
    Object.entries(staticFields).forEach(([name, entries]) => {
        if ((name || '').toLowerCase() === 'url') {
            (Array.isArray(entries) ? entries : [entries]).forEach((e) => {
                if (typeof addUrlRow === 'function') addUrlRow(e);
            });
            return;
        }
        (Array.isArray(entries) ? entries : [entries]).forEach((e) => {
            if (typeof addStaticFieldRow === 'function') {
                addStaticFieldRow({ name, value: _aiScalar(e && e.value !== undefined ? e.value : e), type: (e && e.type) || '', negate: !!(e && e.negate) });
            }
        });
    });
}

async function editRule(id) {
    try {
        const res = await fetch(`/builder/rule/${encodeURIComponent(id)}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}: Failed to fetch rule data`);
        
        const r = await res.json();
        if (typeof clearRule === 'function') clearRule();

        if (choicesIfSid) {
            choicesIfSid.clearStore();
            if (r.if_sid) {
                const sids = String(r.if_sid).split(',').map(s => s.trim()).filter(Boolean);
                const sidChoices = sids.map(sid => ({ value: sid, label: sid, selected: true }));
                choicesIfSid.setChoices(sidChoices, 'value', 'label', true);
            }
        }

        if (choicesIfGroup) {
            choicesIfGroup.clearStore();
            if (r.if_group) {
                const groups = String(r.if_group).split(/[,|]/).map(g => g.trim()).filter(Boolean);
                const groupChoices = groups.map(g => ({ value: g, label: g, selected: true }));
                choicesIfGroup.setChoices(groupChoices, 'value', 'label', true);
            }
        }
        setVal('rule_id', r.rule_id ?? r.id ?? '');
        setVal('rule_level', r.level ?? 3);
        setVal('rule_description', r.description);

        setVal('rule_if_level', r.if_level);
        setVal('rule_if_matched_sid', r.if_matched_sid);
        setVal('rule_if_matched_group', r.if_matched_group);
        setVal('rule_match', r.match);
        setVal('rule_match_type', r.match_type);
        setVal('rule_regex', r.regex);
        setVal('rule_regex_type', r.regex_type);
        setVal('rule_time', r.time);
        setVal('rule_wrapper_group', r._wrapper_group);
        setVal('rule_frequency', r.frequency);
        setVal('rule_timeframe', r.timeframe);
        setVal('rule_ignore', r.ignore);
        setRuleGroupValue(r.group);

        if (r.filename && choicesRuleFilename) {
            choicesRuleFilename.setChoices([{ value: r.filename, label: r.filename, selected: true }], 'value', 'label', false);
        }

        setChecked('rule_same_srcip', r.same_srcip);
        setChecked('rule_different_srcip', r.different_srcip);
        setChecked('rule_same_url', r.same_url);

        if (Array.isArray(r.options)) {
            r.options.forEach(opt => setChecked(`opt_${opt}`, true));
        }

        if (Array.isArray(r.urls) && typeof addUrlRow === 'function') r.urls.forEach(addUrlRow);
        if (typeof populateStaticFields === 'function') populateStaticFields(r.static_fields);
        if (Array.isArray(r.fields) && typeof addFieldRow === 'function') r.fields.forEach(addFieldRow);
        if (Array.isArray(r.lists) && typeof addListRow === 'function') r.lists.forEach(addListRow);
        if (Array.isArray(r.same_fields) && typeof addSameFieldRow === 'function') r.same_fields.forEach(addSameFieldRow);
        
        const mitreData = r.mitre_ids || r.mitre;
        if (Array.isArray(mitreData) && typeof addMitreRow === 'function') mitreData.forEach(addMitreRow);

        let infoList = [];
        if (Array.isArray(r.info)) {
            infoList = r.info.filter(Boolean);
        } else if (typeof r.info === 'string' && r.info.trim()) {
            infoList = [{ value: r.info.trim(), type: r.info_type || 'text' }];
        }
        if (typeof addInfoRow === 'function') infoList.forEach(addInfoRow);

        // Populate the Test Samples stored on this rule.
        if (Array.isArray(r.test_samples) && typeof addTestSampleRow === 'function') {
            r.test_samples.forEach(addTestSampleRow);
        }

        // Populate Tech Stack linkage. tech_stack_ids arrives from the
        // server as a list of ObjectId strings. setTechStackSelection()
        // (in sync_common.js) handles the race when options are not loaded.
        if (typeof setTechStackSelection === 'function') {
            setTechStackSelection(Array.isArray(r.tech_stack_ids) ? r.tech_stack_ids : []);
        }

        if (r.decoded_as && typeof choicesDecodedAs !== 'undefined' && choicesDecodedAs) {
            if (typeof choicesDecodedAs.clearStore === 'function') choicesDecodedAs.clearStore();
            choicesDecodedAs.setChoices([{ value: r.decoded_as, label: r.decoded_as, selected: true }], 'value', 'label', true);
        }

        if (typeof updateLevelSevHint === 'function') updateLevelSevHint();
        if (typeof goToStep === 'function') goToStep('rule', 1);
        if (typeof generateRuleXML === 'function') generateRuleXML();

        if (typeof showToast === 'function') showToast(`<i class="fa-solid fa-pen me-1"></i>Editing rule #${id}`, 'primary');
        if (typeof refreshLifecycleStepper === 'function') refreshLifecycleStepper(id);

    } catch (err) {
        console.error("Detail error editRule:", err);
        if (typeof showToast === 'function') showToast('<i class="fa-solid fa-circle-exclamation me-1"></i>Failed to load rule for editing.', 'danger');
    }
}
const urlParams = new URLSearchParams(window.location.search);
if (urlParams.has('edit')) {
  const ruleId = urlParams.get('edit');
  
  editRule(ruleId)
}

// Handoff from the AI Proposals page: /rule?ai_proposal=<id>. Loads the
// proposal and prefills the wizard (human-in-the-loop — nothing is saved
// until the user reviews and presses Save).
if (urlParams.has('ai_proposal')) {
  (async () => {
    const proposalId = urlParams.get('ai_proposal');
    try {
      const res = await fetch('/api/ai/proposals');
      const data = await res.json();
      const list = Array.isArray(data) ? data : (data.items || []);
      const proposal = list.find((p) => p._id === proposalId);
      if (!proposal) {
        if (typeof showToast === 'function') showToast('AI proposal not found.', 'danger');
        return;
      }
      prefillRuleFromProposal(proposal);
    } catch (err) {
      console.error('Failed to load AI proposal:', err);
      if (typeof showToast === 'function') showToast('Failed to load AI proposal.', 'danger');
    }
  })();
}