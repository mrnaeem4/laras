/**
 * static/js/sync_common.js
 * Shared between the two wizard pages (rule_builder.js, decoder_builder.js
 * — they need the "Save to file" filename picker) AND sync_manager.js
 * (which needs the full per-file sync overview for the Pull/Push modals).
 * Loaded on every page via templates/base.html, right after common.js.
 */

// Populated by populateFilenameOptions() from /api/wazuh/files. Used to
// power the "pick an existing file, or type to create a new one" filename
// selects in the rule & decoder wizards without a network round-trip on
// every keystroke.
let knownRuleFilenames = [];
let knownDecoderFilenames = [];

// Choices.js instance for the Tech Stack multi-select in Rule Builder
// Step 6 (see initChoices below). Its value is a list of ObjectId strings
// from /api/tech-stack; rule_builder.js (collectRulePayload/editRule/
// clearRule) uses it through this global.
let choicesTechStack = null;
// Map id -> label (e.g. "nginx nginx 1.24.0") to render selected choices
// when editing; populated together with the option load.
let techStackLabelMap = {};

// Set the active tech stack selection on the Choices instance; used by
// editRule() (rule_builder.js). Robust against the race where options are
// not loaded yet (empty techStackLabelMap): the selection is deferred and
// applied automatically once the options arrive.
let _pendingTechStackSelection = [];
function setTechStackSelection(ids) {
    _pendingTechStackSelection = Array.isArray(ids) ? ids : [];
    if (!choicesTechStack) return;
    choicesTechStack.clearStore();
    if (_pendingTechStackSelection.length === 0) return;
    const choices = _pendingTechStackSelection.map((id) => ({
        value: id,
        label: techStackLabelMap[id] || id,
        selected: true,
    }));
    choicesTechStack.setChoices(choices, 'value', 'label', true);
}

const tableState = {
    decoder: { page: 1, perPage: 10, q: '', total: 0 },
    rule:    { page: 1, perPage: 10, q: '', level: '', techStack: '', total: 0 },
};
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

    // Tech Stack multi-select (Rule Builder Step 6). Options are loaded once
    // from /api/tech-stack; the list is small, no debounced search needed.
    const techStackEl = document.getElementById('rule_tech_stack');
    if (techStackEl) {
        choicesTechStack = new Choices(techStackEl, {
            removeItemButton: true, duplicateItemsAllowed: false, searchEnabled: true,
            placeholderValue: 'Select tech stack items...',
            noResultsText: 'Not found', noChoicesText: 'No stack registered',
            shouldSort: true,
        });
        (async () => {
            try {
                const res = await fetch('/api/tech-stack');
                const items = await res.json();
                if (Array.isArray(items)) {
                    const choices = items.map((ts) => {
                        const label = [ts.vendor, ts.product, ts.version].filter(Boolean).join(' ');
                        techStackLabelMap[ts._id] = label;
                        return { value: ts._id, label };
                    });
                    choicesTechStack.setChoices(choices, 'value', 'label', true);
                }
            } catch (e) {
                console.warn('Failed to load tech stack for Rule Builder:', e);
            }
            // Apply a selection that was set before the options arrived.
            if (_pendingTechStackSelection.length > 0) {
                setTechStackSelection(_pendingTechStackSelection);
            }
        })();
    }
}