async function loadDecoderTable() {
    const tbody = document.getElementById('decoderTableBody');
    const emptyEl = document.getElementById('decoderTableEmpty');
    const st = tableState.decoder;
    tableSkeleton(tbody, 7);
    emptyEl.classList.add('d-none');
    try {
        const res = await fetch(`/builder/decoder/list?q=${encodeURIComponent(st.q)}&page=${st.page}&per_page=${st.perPage}`);
        if (!res.ok) throw new Error('list endpoint unavailable');
        const data = await res.json();
        st.total = data.total || 0;
        document.getElementById('decoderCountBadge').textContent = st.total;
        const items = data.items || [];
        if (!items.length) { tbody.innerHTML = ''; emptyEl.classList.remove('d-none'); renderPager('decoder'); return; }
        tbody.innerHTML = items.map(d => `
            <tr>
                <td class="cell-mono">${esc(d.name)}</td>
                <td class="cell-muted">${d.parent ? esc(d.parent) : '<span class="text-muted">-</span>'}</td>
                <td>${d.type ? `<span class="chip">${esc(d.type)}</span>` : '<span class="text-muted">-</span>'}</td>
                <td class="cell-muted">${d.program_name ? esc(d.program_name) : '-'}</td>
                <td class="small">${envSyncBadgesHTML(d.sync_status_dev, d.sync_status_prod)}</td>
                <td class="cell-muted">${fmtDate(d.updated_at)}</td>
                <td>
                    <div class="row-actions">
                        <button class="icon-btn" title="View XML" onclick="viewDecoderXml('${esc(d._id)}')">
                            <i class="fa-solid fa-eye"></i>
                        </button>
                        <button class="icon-btn" title="Version History" onclick="openHistoryModal('decoder', { filename: '${esc(d.filename)}', name: '${esc(d.name)}' })">
                            <i class="fa-solid fa-clock-rotate-left"></i>
                        </button>
                        <a class="icon-btn" title="Edit" href="/decoder?edit=${esc(d._id)}">
                            <i class="fa-solid fa-pen"></i>
                        </a>
                        <button class="icon-btn danger" title="Delete" onclick="confirmDelete('decoder', '${esc(d._id)}')">
                            <i class="fa-solid fa-trash"></i>
                        </button>
                    </div>
                </td>
            </tr>`).join('');
        renderPager('decoder');
    } catch (e) {
        tbody.innerHTML = '';
        emptyEl.classList.remove('d-none');
        emptyEl.querySelector('h6').textContent = 'Unable to load data';
        emptyEl.querySelector('div').textContent = 'Endpoint GET /builder/decoder/list is not available in the backend.';
    }
}

async function viewDecoderXml(name) {
    try {
        const res = await fetch(`/builder/decoder/${encodeURIComponent(name)}`);
        const data = await res.json();
        const xmlRes = await fetch('/builder/decoder/xml', {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data),
        });
        const xmlData = await xmlRes.json();
        openXmlModal(`Decoder - ${name}`, xmlData.xml || '// no XML returned');
    } catch { showToast('<i class="fa-solid fa-circle-exclamation me-1"></i>Failed to load decoder XML.', 'danger'); }
}

document.addEventListener('DOMContentLoaded', () => {
    loadDecoderTable()
});

document.addEventListener('DOMContentLoaded', () => {
    const decSearch = document.getElementById('decoderSearchInput');
    if (decSearch) decSearch.addEventListener('input', debounce(() => {
        tableState.decoder.q = decSearch.value.trim(); tableState.decoder.page = 1; loadDecoderTable();
    }, 350));
})