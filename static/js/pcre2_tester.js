/**
 * static/js/pcre2_tester.js
 * Page-specific logic for GET /tester/pcre2 (templates/pcre2_tester.html).
 * Tests a PCRE2 pattern against a log string locally
 * (POST /tester/pcre2/test) or validates the pattern alone
 * (POST /tester/pcre2/validate) via blueprints/tester.py.
 */

/* ───────────────────────────────────────────────────────────────────
    PCRE2 Tester
─────────────────────────────────────────────────────────────────── */
async function testPCRE2() {
    const pattern = document.getElementById('pcre2Pattern').value.trim();
    const log     = document.getElementById('pcre2Log').value.trim();
    const resEl   = document.getElementById('pcre2Results');
    if (!pattern) { resEl.textContent = 'Please enter a pattern.'; return; }
    resEl.textContent = 'Testing...';
    try {
        const res  = await fetch('/tester/pcre2/test', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ pattern, log }),
        });
        resEl.textContent = JSON.stringify(await res.json(), null, 2);
    } catch (e) { resEl.textContent = 'Error: ' + e.message; }
}
async function validateOnly() {
    const pattern = document.getElementById('pcre2Pattern').value.trim();
    const resEl   = document.getElementById('pcre2Results');
    if (!pattern) { resEl.textContent = 'Please enter a pattern.'; return; }
    try {
        const res  = await fetch('/tester/pcre2/validate', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ pattern }),
        });
        resEl.textContent = JSON.stringify(await res.json(), null, 2);
    } catch (e) { resEl.textContent = 'Error: ' + e.message; }
}