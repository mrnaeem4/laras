let lvOptions = '<option value="">Select Level</option>';
for (let i = 0; i < 16; i++) {
    lvOptions += `
        <div class="form-check mb-1">
            <input class="form-check-input level-checkbox" type="checkbox" value="${i}" id="lvl_${i}">
            <label class="form-check-label" for="lvl_${i}">
                Level ${i}
            </label>
        </div>
    `;
}
document.getElementById('levelCheckboxContainer').innerHTML = lvOptions;

function getSelectedLevels() {
    let selectedLevels = [];
    // Ambil semua checkbox yang kondisinya :checked
    document.querySelectorAll('.level-checkbox:checked').forEach(checkbox => {
        selectedLevels.push(checkbox.value);
    });
    return selectedLevels; // Mengembalikan array, contoh: ["1", "3", "4"]
}

// 1. Logika untuk buka-tutup dropdown saat tombol diklik
const dropdownBtn = document.getElementById('dropdownMenuButton');
const dropdownMenu = document.getElementById('levelCheckboxContainer');

dropdownBtn.addEventListener('click', function(e) {
    e.stopPropagation(); // Mencegah event 'bubbling' ke dokumen
    dropdownMenu.classList.toggle('show');
});

// 2. Tutup dropdown otomatis jika user mengklik di luar area dropdown
document.addEventListener('click', function(e) {
    if (!dropdownMenu.contains(e.target) && e.target !== dropdownBtn) {
        dropdownMenu.classList.remove('show');
    }
});

// 3. PENTING: Mencegah dropdown tertutup sendiri saat user mengklik checkbox di dalamnya
dropdownMenu.addEventListener('click', function(e) {
    e.stopPropagation();
});

async function loadRuleTable() {
    const tbody = document.getElementById('ruleTableBody');
    const emptyEl = document.getElementById('ruleTableEmpty');
    const st = tableState.rule;
    
    // --- PERBAIKAN: Selalu update state level dengan checkbox terbaru ---
    // Mengambil array level, misal: [0, 1, 2]
    const currentLevels = getSelectedLevels().map(Number); 
    
    // Mengubah array menjadi string JSON untuk dikirim ke backend, misal: "[0,1,2]"
    // Jika tidak ada yang dicentang, kirim string kosong "" agar tidak memfilter level
    st.level = currentLevels.length > 0 ? JSON.stringify(currentLevels) : '';
    // -----------------------------------------------------------------

    tableSkeleton(tbody, 8);
    emptyEl.classList.add('d-none');
    try {
        // endpoint disesuaikan dengan prefix Anda (/builder/rule/list)
        const params = new URLSearchParams({
            q: st.q || '',
            level: st.level || '',
            page: st.page,
            per_page: st.perPage,
        });
        if (st.techStack) params.set('tech_stack', st.techStack);
        const res = await fetch(`/builder/rule/list?${params.toString()}`);
        if (!res.ok) throw new Error('list endpoint unavailable');
        const data = await res.json();
        st.total = data.total || 0;
        document.getElementById('ruleCountBadge').textContent = st.total;
        const items = data.items || [];
        if (!items.length) { tbody.innerHTML = ''; emptyEl.classList.remove('d-none'); renderPager('rule'); return; }
        tbody.innerHTML = items.map(r => `
            <tr>
                <td class="cell-mono">${esc(r.rule_id)}</td>
                <td>${sevBadgeHTML(r.level)}</td>
                <td class="wrap-col">${esc(r.filename)}</td>
                <td class="wrap-col">${esc(r.description)}</td>
                <td class="wrap-col">${r.group ? renderGroupBadges(r.group) : '-'}</td>
                <td class="small">${renderTechStackChips(r.tech_stack_items)}</td>
                <td class="small">${envSyncBadgesHTML(r.sync_status_dev, r.sync_status_prod)}</td>
                <td>${renderLifecycleStepper(r.lifecycle_status, true)}</td>
                <td class="cell-muted wrap-col">${fmtDate(r.updated_at)}</td>
                <td>
                    <div class="row-actions">
                        <button class="icon-btn" title="View XML" onclick="viewRuleXml('${esc(r.rule_id)}')">
                            <i class="fa-solid fa-eye"></i>
                        </button>
                        <button class="icon-btn" title="Version History" onclick="openHistoryModal('rule', '${esc(r.rule_id)}')">
                            <i class="fa-solid fa-clock-rotate-left"></i>
                        </button>
                        <a class="icon-btn" title="Edit" href="/rule?edit=${esc(r.rule_id)}">
                            <i class="fa-solid fa-pen"></i>
                        </a>
                        <button class="icon-btn danger" title="Delete" onclick="confirmDelete('rule', '${esc(r.rule_id)}')">
                            <i class="fa-solid fa-trash"></i>
                        </button>
                    </div>
                </td>
            </tr>`).join('');
        renderPager('rule');
    } catch (e) {
        tbody.innerHTML = '';
        emptyEl.classList.remove('d-none');
        emptyEl.querySelector('h6').textContent = 'Unable to load data';
        emptyEl.querySelector('div').textContent = 'Endpoint GET /builder/rule/list is not available in the backend.';
    }
}

// Render tech stack labels as small chips in the Tech Stack column.
// tech_stack_items comes from the backend (builder.py list_rules enrichment):
// [{_id, vendor, product}].
function renderTechStackChips(items) {
    if (!Array.isArray(items) || items.length === 0) return '<span class="text-muted">-</span>';
    return items.map((ts) =>
        `<span class="chip" title="${esc(ts._id)}">${esc(ts.vendor)} ${esc(ts.product)}</span>`
    ).join(' ');
}

// Load the Tech Stack filter options once from /api/tech-stack.
async function loadTechStackFilterOptions() {
    const select = document.getElementById('techStackFilter');
    if (!select) return;
    try {
        const res = await fetch('/api/tech-stack');
        const items = await res.json();
        if (!Array.isArray(items)) return;
        select.innerHTML = '<option value="">All Tech Stack</option>' +
            items.map((ts) =>
                `<option value="${esc(ts._id)}">${esc(ts.vendor)} ${esc(ts.product)}${ts.version ? ' ' + esc(ts.version) : ''}</option>`
            ).join('');
    } catch (e) {
        console.warn('Failed to load tech stack filter options:', e);
    }
}

// Pemicu saat input pencarian diketik
document.getElementById('ruleSearchInput').addEventListener('input', (e) => {
    tableState.rule.q = e.target.value;
    tableState.rule.page = 1; // Reset ke halaman pertama saat mencari
    loadRuleTable();
});

// Pemicu saat checkbox di dalam container dropdown berubah status (dicentang/dilepas)
document.getElementById('levelCheckboxContainer').addEventListener('change', () => {
    tableState.rule.page = 1; // Reset ke halaman pertama saat filter berubah
    loadRuleTable();
});

// Tech Stack filter: changing the selection reloads the table with
// ?tech_stack=<id>.
const techStackFilter = document.getElementById('techStackFilter');
if (techStackFilter) techStackFilter.addEventListener('change', () => {
    tableState.rule.techStack = techStackFilter.value;
    tableState.rule.page = 1;
    loadRuleTable();
});
async function viewRuleXml(id) {
    try {
        const res = await fetch(`/builder/rule/${encodeURIComponent(id)}`);
        const data = await res.json();
        const xmlRes = await fetch('/builder/rule/xml', {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data),
        });
        const xmlData = await xmlRes.json();
        openXmlModal(`Rule - ${id}`, xmlData.xml || '// no XML returned');
    } catch { showToast('<i class="fa-solid fa-circle-exclamation me-1"></i>Failed to load rule XML.', 'danger'); }
}
document.addEventListener('DOMContentLoaded', () => {
    loadRuleTable();
    loadTechStackFilterOptions();
});