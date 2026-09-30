/**
 * static/js/tech_stack.js
 * Page-specific logic for GET /tech-stack (templates/tech_stack.html).
 * CRUD: list, create, update, delete item tech stack.
 * Endpoints: /api/tech-stack*, /api/kev/* (blueprints/api.py).
 * CSRF ditangani global oleh csrf.js.
 * Mengikuti pola visual decoder_list.js / rule_list.js.
 */

let techStackCache = [];
let choicesTsVendor = null;
let choicesTsProduct = null;

function categoryLabel(cat) {
    return {
        os: 'OS', web: 'Web Server / App', db: 'Database',
        network: 'Network', app: 'Aplikasi', other: 'Lainnya',
    }[cat] || (cat ? esc(cat) : '\u2014');
}

function envLabel(env) {
    return { dev: 'Dev', prod: 'Prod', both: 'Keduanya' }[env] || (env ? esc(env) : '\u2014');
}

// ── Catalog dropdowns (vendor/product dari feed KEV) ───────────────────

// Choices.js tidak punya opsi "create" bawaan untuk single-select; pola yang
// dipakai di proyek ini (lihat _filenameChoicesFor di sync_common.js) adalah
// menambahkan pilihan sintetis dari teks yang sedang diketik. Jadi user tetap
// bisa memakai nilai sendiri yang belum ada di katalog KEV.
function _catalogChoicesFor(query, values) {
    const q = (query || '').trim();
    const matches = values.filter((v) => !q || v.toLowerCase().includes(q.toLowerCase()));
    const choices = matches.map((v) => ({ value: v, label: v }));
    if (q && !values.some((v) => v.toLowerCase() === q.toLowerCase())) {
        choices.push({ value: q, label: `Use "${q}"` });
    }
    return choices;
}

let _allVendors = [];
let _allProducts = [];

function _initCatalogChoices(elementId) {
    const el = document.getElementById(elementId);
    if (!el) return null;
    const instance = new Choices(el, {
        searchEnabled: true,
        shouldSort: true,
        placeholderValue: 'Type to search or add your own',
        noResultsText: 'No match - keep typing to add your own',
        noChoicesText: 'Type to search',
        itemSelectText: '',
        allowHTML: false,
    });
    return instance;
}

async function _loadVendors() {
    try {
        const res = await fetch('/api/kev/catalog/vendors');
        const data = await res.json();
        _allVendors = Array.isArray(data.vendors) ? data.vendors : [];
    } catch (err) {
        console.warn('Failed to load KEV vendors:', err);
        _allVendors = [];
    }
    if (choicesTsVendor) {
        choicesTsVendor.setChoices(_allVendors.map((v) => ({ value: v, label: v })), 'value', 'label', true);
    }
}

async function _loadProducts(vendor) {
    // vendor kosong -> tampilkan SELURUH product di katalog supaya dropdown
    // tidak pernah kosong saat modal dibuka (dulu kosong sampai vendor
    // dipilih, yang membingungkan). Begitu vendor dipilih, daftar dipersempit
    // ke product vendor itu.
    const url = vendor
        ? `/api/kev/catalog/products?vendor=${encodeURIComponent(vendor)}`
        : '/api/kev/catalog/products';
    let products = [];
    try {
        const res = await fetch(url);
        const data = await res.json();
        products = Array.isArray(data.products) ? data.products : [];
    } catch (err) {
        console.warn('Failed to load KEV products:', err);
    }
    _allProducts = products;
    if (choicesTsProduct) {
        // PENTING: jangan panggil choicesTsProduct.clearStore() di sini.
        // Di Choices.js v10, clearStore() me-reset SELURUH store ke default
        // (termasuk daftar choices), sehingga product yang baru saja di-set
        // langsung hilang dan dropdown kosong. clearChoices() sudah cukup
        // untuk mengganti daftar opsi; setChoices(..., clearStore=true)
        // menangani reset pilihan.
        choicesTsProduct.clearChoices();
        choicesTsProduct.setChoices(products.map((p) => ({ value: p, label: p })), 'value', 'label', true);
    }
}

function _choicesValue(instance) {
    if (!instance) return '';
    const v = instance.getValue(true);
    if (Array.isArray(v)) return (v[0] || '').toString().trim();
    return (v || '').toString().trim();
}

function _setChoicesValue(instance, value) {
    if (!instance) return;
    // removeActiveItems() hanya membatalkan PILIHAN, tidak menghapus daftar
    // opsi (beda dengan clearStore() yang me-reset store ke default).
    instance.removeActiveItems();
    if (!value) return;
    // Nilai yang tersimpan (mis. produk lama/custom yang tidak ada di daftar
    // product KEV vendor tsb) tidak akan ter-select kalau opsinya belum ada;
    // setChoiceByValue() diam-diam gagal dan field ter-submit kosong. Jadi
    // pastikan opsinya ada dulu sebelum memilih.
    const stored = instance._store && instance._store.choices;
    const has = Array.isArray(stored) && stored.some((c) => c.value === value);
    if (!has) {
        instance.setChoices([{ value, label: value }], 'value', 'label', false);
    }
    instance.setChoiceByValue(value);
}

async function syncKevCatalog() {
    const btn = document.getElementById('tsKevSyncBtn');
    if (btn) btn.disabled = true;
    try {
        const res = await fetch('/api/kev/sync', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
        const data = await res.json();
        if (!data.success) {
            showToast(data.error || 'Sync failed.', 'danger');
            return;
        }
        showToast(`KEV catalog synced: ${data.inserted} new vendor/product pairs.`, 'success');
        await _loadVendors();
    } catch (err) {
        showToast('Sync request error: ' + err.message, 'danger');
    } finally {
        if (btn) btn.disabled = false;
    }
}

// ── List & table ───────────────────────────────────────────────────────

async function loadTechStack() {
    const tbody = document.getElementById('techStackTableBody');
    const emptyEl = document.getElementById('techStackTableEmpty');
    tableSkeleton(tbody, 7);
    emptyEl.classList.add('d-none');
    try {
        const res = await fetch('/api/tech-stack');
        const data = await res.json();
        if (!Array.isArray(data)) throw new Error(data.error || 'Response tidak valid.');
        techStackCache = data;
        renderTechStackTable();
    } catch (err) {
        console.error('Load tech stack error:', err);
        tbody.innerHTML = '';
        emptyEl.classList.remove('d-none');
        emptyEl.querySelector('h6').textContent = 'Unable to load data';
        emptyEl.querySelector('div').textContent = 'Failed to load: ' + esc(err.message);
    }
}

function renderTechStackTable() {
    const tbody = document.getElementById('techStackTableBody');
    const emptyEl = document.getElementById('techStackTableEmpty');
    const q = (document.getElementById('tsSearchInput')?.value || '').trim().toLowerCase();

    const filtered = q ? techStackCache.filter((item) =>
        [item.vendor, item.product, item.version, item.note].some((v) => (v || '').toLowerCase().includes(q))
    ) : techStackCache;

    if (!filtered.length) {
        tbody.innerHTML = '';
        emptyEl.classList.remove('d-none');
        emptyEl.querySelector('h6').textContent = q ? 'No results' : 'No stack registered';
        emptyEl.querySelector('div').textContent = q ? `Nothing found for "${esc(q)}".` : 'Click "Add Stack" to register the first technology.';
        return;
    }

    emptyEl.classList.add('d-none');
    tbody.innerHTML = filtered.map((item) => `
        <tr>
            <td class="cell-mono">${esc(item.vendor)}</td>
            <td>${esc(item.product)}</td>
            <td class="cell-muted">${esc(item.version) || '<span class="text-muted">-</span>'}</td>
            <td>${item.category ? `<span class="chip">${categoryLabel(item.category)}</span>` : '<span class="text-muted">-</span>'}</td>
            <td>${item.environment ? `<span class="chip" style="background:var(--surface-alt);color:var(--text-secondary)">${envLabel(item.environment)}</span>` : '<span class="text-muted">-</span>'}</td>
            <td class="cell-muted" style="max-width:240px" title="${esc(item.note)}">${esc(item.note) || '<span class="text-muted">-</span>'}</td>
            <td>
                <div class="row-actions">
                    <button class="icon-btn" title="Edit" onclick="openTechStackForm('${item._id}')">
                        <i class="fa-solid fa-pen"></i>
                    </button>
                    <button class="icon-btn danger" title="Delete" onclick="confirmDeleteTechStack('${item._id}')">
                        <i class="fa-solid fa-trash"></i>
                    </button>
                </div>
            </td>
        </tr>`).join('');
}

async function openTechStackForm(itemId = null) {
    document.getElementById('techStackFormError').textContent = '';
    const modal = bootstrap.Modal.getOrCreateInstance(document.getElementById('techStackModal'));

    if (!itemId) {
        document.getElementById('techStackModalTitle').textContent = 'Add Stack';
        document.getElementById('tsId').value = '';
        _setChoicesValue(choicesTsVendor, '');
        await _loadProducts('');
        _setChoicesValue(choicesTsProduct, '');
        document.getElementById('tsVersion').value = '';
        document.getElementById('tsNote').value = '';
        ['tsCategory', 'tsEnvironment'].forEach((id) => document.getElementById(id).value = '');
        modal.show();
        return;
    }

    const item = techStackCache.find((i) => i._id === itemId);
    if (!item) { showToast('Item not found, reload the page.', 'warning'); return; }

    document.getElementById('techStackModalTitle').textContent = `Edit: ${item.vendor} ${item.product}`;
    document.getElementById('tsId').value = item._id;
    _setChoicesValue(choicesTsVendor, item.vendor || '');
    await _loadProducts(item.vendor || '');
    _setChoicesValue(choicesTsProduct, item.product || '');
    document.getElementById('tsVersion').value = item.version || '';
    document.getElementById('tsCategory').value = item.category || '';
    document.getElementById('tsEnvironment').value = item.environment || '';
    document.getElementById('tsNote').value = item.note || '';
    modal.show();
}

async function saveTechStackItem() {
    const id = document.getElementById('tsId').value;
    const payload = {
        vendor: _choicesValue(choicesTsVendor),
        product: _choicesValue(choicesTsProduct),
        version: document.getElementById('tsVersion').value,
        category: document.getElementById('tsCategory').value,
        environment: document.getElementById('tsEnvironment').value,
        note: document.getElementById('tsNote').value,
    };

    const errEl = document.getElementById('techStackFormError');
    errEl.textContent = '';

    try {
        const url = id ? `/api/tech-stack/${id}` : '/api/tech-stack';
        const method = id ? 'PUT' : 'POST';
        const res = await fetch(url, {
            method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        const data = await res.json();

        if (!data.success) {
            errEl.textContent = data.error || 'Failed to save.';
            return;
        }

        bootstrap.Modal.getInstance(document.getElementById('techStackModal'))?.hide();
        showToast(id ? 'Stack updated.' : 'Stack added.', 'success');
        loadTechStack();
    } catch (err) {
        console.error('Save tech stack error:', err);
        errEl.textContent = `Request error: ${err.message}`;
    }
}

function confirmDeleteTechStack(itemId) {
    confirmDelete('tech', itemId);
}

document.addEventListener('DOMContentLoaded', async () => {
    const searchInput = document.getElementById('tsSearchInput');
    if (searchInput) searchInput.addEventListener('input', debounce(() => {
        renderTechStackTable();
    }, 350));

    choicesTsVendor = _initCatalogChoices('tsVendor');
    choicesTsProduct = _initCatalogChoices('tsProduct');

    // Vendor: search adds a "use this value" option; selecting a vendor
    // reloads the product options for that vendor.
    const vendorEl = document.getElementById('tsVendor');
    if (vendorEl && choicesTsVendor) {
        vendorEl.addEventListener('search', (e) => {
            const choices = _catalogChoicesFor(e.detail.value, _allVendors);
            choicesTsVendor.clearChoices();
            choicesTsVendor.setChoices(choices, 'value', 'label', true);
        });
        vendorEl.addEventListener('change', (e) => {
            _loadProducts(e.detail?.value || _choicesValue(choicesTsVendor));
        });
    }

    // Product: same "type to add your own" behaviour, but filtered against
    // the currently loaded product list (vendor-scoped once a vendor is
    // chosen, otherwise the whole catalog).
    const productEl = document.getElementById('tsProduct');
    if (productEl && choicesTsProduct) {
        productEl.addEventListener('search', (e) => {
            const choices = _catalogChoicesFor(e.detail.value, _allProducts);
            choicesTsProduct.clearChoices();
            choicesTsProduct.setChoices(choices, 'value', 'label', true);
        });
    }

    await _loadVendors();
    await _loadProducts('');
    loadTechStack();
});
