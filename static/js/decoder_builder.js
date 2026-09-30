/**
 * static/js/decoder_builder.js
 * Page-specific logic for GET /decoder (templates/decoder_builder.html).
 * Depends on common.js and sync_common.js (both loaded first via base.html).
 */
let choicesDecodedAs = null;
let choicesParent    = null;
let choicesDecFilename  = null;

/**
 * Build the choice list for a filename-select's current search term:
 * existing filenames matching the query, plus (if the query doesn't
 * already exactly match one) a synthetic "create new file" choice whose
 * value is the normalized (".xml"-suffixed) filename the user typed.
 */
function _filenameChoicesFor(query, knownFilenames) {
    const q = (query || '').trim();
    const matches = knownFilenames.filter((f) => !q || f.toLowerCase().includes(q.toLowerCase()));
    const choices = matches.map((f) => ({ value: f, label: f }));
    if (q) {
        const normalized = q.toLowerCase().endsWith('.xml') ? q : `${q}.xml`;
        const alreadyExists = knownFilenames.some((f) => f.toLowerCase() === normalized.toLowerCase());
        if (!alreadyExists) {
            choices.push({ value: normalized, label: `➕ Buat file baru: "${normalized}"` });
        }
    }
    return choices;
}

/** Wire a filename <select> into a searchable, "type to create new" Choices.js instance. */
function _initFilenameChoices(elementId, getKnownFilenames) {
    const el = document.getElementById(elementId);
    if (!el) return null;
    const instance = new Choices(el, {
        removeItemButton: true, searchEnabled: true,
        placeholderValue: 'Select an existing file, or type to create a new one',
        noResultsText: 'Tidak ditemukan', noChoicesText: 'Ketik nama file...',
        shouldSort: true,
    });
    el.addEventListener('search', debounce((e) => {
        const choices = _filenameChoicesFor(e.detail.value, getKnownFilenames());
        instance.clearChoices();
        instance.setChoices(choices, 'value', 'label', true);
    }, 200));
    el.addEventListener('focus', () => {
        if (instance.getValue(true).length === 0) {
            instance.setChoices(getKnownFilenames().map((f) => ({ value: f, label: f })), 'value', 'label', true);
        }
    });
    return instance;
}
function renderDecoderReview() {
    const p = collectDecoderPayload();
    const html = [
        reviewRow('Name', esc(p.name) || '<span class="text-danger">missing</span>'),
        reviewRow('Parent', esc(p.parent)),
        reviewRow('Type', esc(p.type)),
        reviewRow('program_name', esc(p.program_name)),
        reviewRow('prematch', p.prematch ? `<code>${esc(p.prematch)}</code>` : ''),
        reviewRow('regex', p.regex ? `<code>${esc(p.regex)}</code>` : ''),
        reviewRow('order', esc(p.order)),
        reviewRow('flags', [p.accumulate ? 'accumulate' : '', p.use_own_name ? 'use_own_name' : ''].filter(Boolean).join(', ')),
    ].filter(Boolean).join('');
    document.getElementById('decoderReviewSummary').innerHTML = html || '<div class="text-muted">Nothing filled in yet.</div>';
}
function initChoices() {
    const ifSidEl = document.getElementById('rule_if_sid');
    if (ifSidEl) {
        choicesIfSid = new Choices(ifSidEl, {
            removeItemButton: true, duplicateItemsAllowed: false, searchEnabled: true,
            searchResultLimit: 50, placeholderValue: 'e.g. 5700, 5701',
            noResultsText: 'No matching rule IDs - type to search',
            noChoicesText: 'Start typing to load rule IDs', shouldSort: false,
        });
        ifSidEl.addEventListener('search', debounce(async (e) => {
            const q = e.detail.value.trim();
            if (!q) return;
            const items = await fetchSids(q);
            choicesIfSid.clearChoices();
            choicesIfSid.setChoices(items, 'value', 'label', true);
        }, 300));
    }

    const ifGroupEl = document.getElementById('rule_if_group');
    if (ifGroupEl) {
        choicesIfGroup = new Choices(ifGroupEl, {
            removeItemButton: true, duplicateItemsAllowed: false, searchEnabled: true,
            placeholderValue: 'e.g. authentication_failed', noResultsText: 'No matching groups',
            noChoicesText: 'Start typing to load groups', shouldSort: true,
        });
        ifGroupEl.addEventListener('search', debounce(async (e) => {
            const items = await fetchGroups(e.detail.value.trim());
            choicesIfGroup.clearChoices();
            choicesIfGroup.setChoices(items, 'value', 'label', true);
        }, 300));
        ifGroupEl.addEventListener('focus', async () => {
            if (choicesIfGroup.getValue(true).length === 0) {
                const items = await fetchGroups('');
                choicesIfGroup.setChoices(items, 'value', 'label', true);
            }
        });
    }

    const decodedAsEl = document.getElementById('rule_decoded_as');
    if (decodedAsEl) {
        choicesDecodedAs = new Choices(decodedAsEl, {
            removeItemButton: true, searchEnabled: true, placeholderValue: 'e.g. sshd',
            noResultsText: 'No matching decoders', noChoicesText: 'Start typing to load decoders',
            shouldSort: true,
        });
        decodedAsEl.addEventListener('search', debounce(async (e) => {
            const items = await fetchDecoders(e.detail.value.trim());
            choicesDecodedAs.clearChoices();
            choicesDecodedAs.setChoices(items, 'value', 'label', true);
        }, 300));
    }

    const parentEl = document.getElementById('dec_parent');
    if (parentEl) {
        choicesParent = new Choices(parentEl, {
            removeItemButton: true, searchEnabled: true, placeholderValue: 'e.g. syslog',
            noResultsText: 'No matching decoders', noChoicesText: 'Start typing to load decoders',
            shouldSort: true,
        });
        parentEl.addEventListener('search', debounce(async (e) => {
            const items = await fetchDecoders(e.detail.value.trim());
            choicesParent.clearChoices();
            choicesParent.setChoices(items, 'value', 'label', true);
        }, 300));
    }

    choicesRuleFilename = _initFilenameChoices('rule_filename', () => knownRuleFilenames);
    choicesDecFilename  = _initFilenameChoices('dec_filename', () => knownDecoderFilenames);
}
function collectDecoderPayload() {
    return {
        name:              document.getElementById('dec_name').value.trim(),
        parent:            getChoicesValue('dec_parent'),
        type:              document.getElementById('dec_type').value,
        program_name:      document.getElementById('dec_program_name').value.trim(),
        program_name_type: document.getElementById('dec_program_name_type').value,
        prematch:          document.getElementById('dec_prematch').value.trim(),
        prematch_type:     document.getElementById('dec_prematch_type').value,
        prematch_offset:   document.getElementById('dec_prematch_offset').value,
        regex:             document.getElementById('dec_regex').value.trim(),
        regex_type:        document.getElementById('dec_regex_type').value,
        regex_offset:      document.getElementById('dec_regex_offset').value,
        order:             document.getElementById('dec_order').value.trim(),
        fts:               document.getElementById('dec_fts').value.trim(),
        ftscomment:        document.getElementById('dec_ftscomment').value.trim(),
        accumulate:        document.getElementById('dec_accumulate').checked,
        use_own_name:      document.getElementById('dec_use_own_name').checked,
        filename:          (document.getElementById('dec_filename')?.value || '').trim(),
        // Free-text note for THIS save — see rule_builder.js's
        // collectRulePayload() for the same field/reasoning.
        commit_message:    (document.getElementById('dec_commit_message')?.value || '').trim(),
    };
}
async function generateDecoderXML(silent) {
    const payload = collectDecoderPayload();
    const errEl   = document.getElementById('decoderError');
    if (!silent) errEl.textContent = '';
    if (!payload.name) { if (!silent) errEl.textContent = 'Decoder name is required.'; return; }
    try {
        const res  = await fetch('/builder/decoder/xml', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        const data = await res.json();
        if (data.xml) { document.getElementById('decoderOutput').textContent = data.xml; }
        else if (!silent) { errEl.textContent = data.error || 'Unknown error'; }
    } catch (e) { if (!silent) errEl.textContent = e.message; }
}
async function saveDecoder() {
    const payload = collectDecoderPayload();
    const errEl   = document.getElementById('decoderError');
    const saveBtn = document.getElementById('btnSaveDecoder');
    errEl.textContent = '';
    if (saveBtn) saveBtn.disabled = true;
    try {
        const res  = await fetch('/builder/decoder/save', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        const data = await res.json();
        if (data.xml) {
            document.getElementById('decoderOutput').textContent = data.xml;
            showToast(data.upserted ? '<i class="fa-solid fa-circle-check me-1"></i>Decoder saved (new).' : '<i class="fa-solid fa-circle-check me-1"></i>Decoder updated.', 'success');
            if (typeof populateFilenameOptions === 'function') populateFilenameOptions();
            loadSidebarCounts();
        } else { errEl.textContent = data.error || 'Unknown error'; }
    } catch (e) { errEl.textContent = e.message; }
    finally { if (saveBtn) saveBtn.disabled = false; }
}
function clearDecoder() {
    ['dec_name', 'dec_program_name', 'dec_prematch', 'dec_regex', 'dec_order', 'dec_fts', 'dec_ftscomment', 'dec_commit_message'].forEach(id => {
        const el = document.getElementById(id); if (el) el.value = '';
    });
    document.getElementById('dec_type').value = '';
    document.getElementById('dec_program_name_type').value = '';
    document.getElementById('dec_prematch_type').value = '';
    document.getElementById('dec_prematch_offset').value = '';
    document.getElementById('dec_regex_type').value = '';
    document.getElementById('dec_regex_offset').value = '';
    document.getElementById('dec_accumulate').checked   = false;
    document.getElementById('dec_use_own_name').checked = false;
    if (choicesParent) { choicesParent.clearStore(); choicesParent.clearInput(); }
    if (choicesDecFilename) { choicesDecFilename.clearStore(); choicesDecFilename.clearInput(); }
    document.getElementById('decoderOutput').textContent = '';
    document.getElementById('decoderError').textContent  = '';
    delete document.getElementById('tabDecoder').dataset.editingName;
    goToStep('dec', 1);
}
function startNewDecoder() {
    clearDecoder();
    document.querySelector('.sidebar-menu[data-bs-target="#tabDecoder"]').click();
    setActiveNav(document.querySelector('.sidebar-menu[data-bs-target="#tabDecoder"]'));
}
async function editDecoder(name) {
    try {
        const res = await fetch(`/builder/decoder/${encodeURIComponent(name)}`);
        if (!res.ok) throw new Error();
        const d = await res.json();
        clearDecoder();
        document.getElementById('dec_name').value = d.name || '';
        document.getElementById('dec_type').value = d.type || '';
        document.getElementById('dec_program_name').value = d.program_name || '';
        document.getElementById('dec_program_name_type').value = d.program_name_type || '';
        document.getElementById('dec_prematch').value = d.prematch || '';
        document.getElementById('dec_prematch_type').value = d.prematch_type || '';
        document.getElementById('dec_prematch_offset').value = d.prematch_offset || '';
        document.getElementById('dec_regex').value = d.regex || '';
        document.getElementById('dec_regex_type').value = d.regex_type || '';
        document.getElementById('dec_regex_offset').value = d.regex_offset || '';
        document.getElementById('dec_order').value = d.order || '';
        document.getElementById('dec_fts').value = d.fts || '';
        document.getElementById('dec_ftscomment').value = d.ftscomment || '';
        document.getElementById('dec_accumulate').checked = !!d.accumulate;
        document.getElementById('dec_use_own_name').checked = !!d.use_own_name;
        if (d.parent && choicesParent) { choicesParent.setChoices([{ value: d.parent, label: d.parent, selected: true }], 'value', 'label', false); }
        if (d.filename && choicesDecFilename) {
            choicesDecFilename.setChoices([{ value: d.filename, label: d.filename, selected: true }], 'value', 'label', false);
        }
        goToStep('dec', 1);
        generateDecoderXML();
        showToast(`<i class="fa-solid fa-pen me-1"></i>Editing decoder "${name}"`, 'primary');
    } catch { showToast('<i class="fa-solid fa-circle-exclamation me-1"></i>Failed to load decoder for editing.', 'danger'); }
}

const urlParams = new URLSearchParams(window.location.search);
if (urlParams.has('edit')) {
  const decoderName = urlParams.get('edit');
  
  editDecoder(decoderName)
}