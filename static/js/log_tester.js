/**
 * static/js/log_tester.js
 * Page-specific logic for GET /tester/log (templates/log_tester.html).
 * Sends a log message to the Wazuh Manager logtest endpoint
 * (POST /tester/logtest via blueprints/tester.py) and renders the result.
 */

/* ───────────────────────────────────────────────────────────────────
    Log Tester
─────────────────────────────────────────────────────────────────── */
async function runLogtest() {
    const log       = document.getElementById('logMessage').value.trim();
    const resultsEl = document.getElementById('logtestResults');
    const token = sessionStorage.getItem('wazuh_token');
    if (!log) { resultsEl.textContent = 'Please enter a log message.'; return; }
    resultsEl.textContent = 'Running...';
    try {
        const res  = await fetch('/tester/logtest', {
            method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
            body: JSON.stringify({ log }),
        });
        resultsEl.textContent = JSON.stringify(await res.json(), null, 2);
    } catch (e) { resultsEl.textContent = 'Error: ' + e.message; }
}