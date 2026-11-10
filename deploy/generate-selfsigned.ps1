<#
.SYNOPSIS
    Generate a self-signed TLS certificate for the LARAS app container.

.DESCRIPTION
    Creates deploy/certs/cert.pem and deploy/certs/key.pem (PEM format,
    RSA 2048, 825-day validity) for use by gunicorn inside the `app`
    container.

    Docker Desktop on Windows needs to read these two files. openssl is
    used because it is bundled with Git for Windows and produces the PEM
    pair gunicorn expects directly.

    The certificate includes a SAN (Subject Alternative Name) extension
    for localhost plus every local IPv4 address found on this machine, so
    the cert is valid whether you reach the app at https://localhost:5000
    or https://<your-ip>:5000.

.NOTES
    Browsers will STILL warn about a self-signed certificate — that is
    expected and cannot be avoided without importing this cert into the
    client trust store (a manual step on each client machine). Click
    "Advanced -> Proceed" once per browser.

    deploy/certs/ is gitignored. Never commit certificates.
#>

[CmdletBinding()]
param(
    # Number of days the certificate is valid.
    [int]$Days = 825,

    # Extra hostnames/IPs to include as SANs, e.g. -ExtraHosts "laras.soc.local","10.0.0.5"
    [string[]]$ExtraHosts = @()
)

$ErrorActionPreference = 'Stop'

# Resolve paths relative to this script so it works from any CWD.
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$CertsDir  = Join-Path $ScriptDir 'certs'
$CertFile  = Join-Path $CertsDir 'cert.pem'
$KeyFile   = Join-Path $CertsDir 'key.pem'

Write-Host '=== LARAS — generate self-signed TLS certificate ===' -ForegroundColor Cyan

# ── Locate openssl ────────────────────────────────────────────────────
$openssl = Get-Command openssl -ErrorAction SilentlyContinue
if (-not $openssl) {
    Write-Host 'ERROR: openssl tidak ditemukan di PATH.' -ForegroundColor Red
    Write-Host ''
    Write-Host 'openssl biasanya ikut terpasang bersama Git for Windows. Coba salah satu:' -ForegroundColor Yellow
    Write-Host '  1. Tambahkan ke PATH, misalnya:'
    Write-Host '     C:\Program Files\Git\usr\bin'
    Write-Host '  2. Atau jalankan script ini dari "Git Bash" (openssl sudah tersedia di sana).'
    Write-Host '  3. Atau install OpenSSL: winget install ShiningLight.OpenSSL.Light'
    exit 1
}
Write-Host "openssl: $($openssl.Source)"

# ── Prepare output directory ──────────────────────────────────────────
if (-not (Test-Path -LiteralPath $CertsDir)) {
    New-Item -ItemType Directory -Path $CertsDir | Out-Null
    Write-Host "Direktori dibuat: $CertsDir"
} else {
    Write-Host "Direktori sudah ada: $CertsDir"
}

# ── Build the SAN list ────────────────────────────────────────────────
# Always include localhost, the loopback addresses, and the machine name.
$sanEntries = New-Object System.Collections.Generic.List[string]
$sanEntries.Add('DNS:localhost')
$sanEntries.Add('IP:127.0.0.1')
$sanEntries.Add('IP:::1')

$hostName = $env:COMPUTERNAME
if ($hostName) { $sanEntries.Add("DNS:$hostName") }

# Every local IPv4 address, so the app is reachable via LAN IP without a
# warning about a name mismatch.
try {
    Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.IPAddress -notlike '169.254.*' } |
        ForEach-Object { $sanEntries.Add("IP:$($_.IPAddress)") }
} catch {
    Write-Host 'Catatan: tidak bisa membaca daftar IP lokal — SAN hanya localhost.' -ForegroundColor Yellow
}

foreach ($h in $ExtraHosts) {
    if ($h -match '^\d+\.\d+\.\d+\.\d+$') { $sanEntries.Add("IP:$h") } else { $sanEntries.Add("DNS:$h") }
}

$sanList = ($sanEntries | Select-Object -Unique) -join ','
Write-Host ''
Write-Host 'SAN yang disertakan:' -ForegroundColor Cyan
$sanEntries | Select-Object -Unique | ForEach-Object { Write-Host "  - $_" }

# ── Generate key + certificate ────────────────────────────────────────
Write-Host ''
Write-Host 'Membuat private key dan certificate...' -ForegroundColor Cyan

# -addext requires OpenSSL 1.1.1+. Git for Windows ships 3.x, so this is
# fine in practice; the check below fails loudly rather than producing a
# cert silently missing its SANs.
$opensslVersion = (& $openssl.Source version) 2>&1
Write-Host "  $opensslVersion"

& $openssl.Source req -x509 -newkey rsa:2048 -nodes `
    -keyout $KeyFile `
    -out $CertFile `
    -days $Days `
    -subj "/C=ID/ST=DKI Jakarta/L=Jakarta/O=LARAS SOC/CN=localhost" `
    -addext "subjectAltName=$sanList" `
    -addext "keyUsage=critical,digitalSignature,keyEncipherment" `
    -addext "extendedKeyUsage=serverAuth"

if ($LASTEXITCODE -ne 0) {
    Write-Host 'ERROR: openssl gagal membuat sertifikat.' -ForegroundColor Red
    exit 1
}

# ── Lock down key permissions (best effort on Windows) ────────────────
# Windows ACLs do not map to Unix 600, but we can at least remove
# inherited permissions and grant only the current user.
try {
    icacls $KeyFile /inheritance:r /grant:r "$($env:USERNAME):(R,W)" | Out-Null
} catch {
    Write-Host 'Catatan: tidak bisa mengatur ACL pada key.pem (tidak fatal).' -ForegroundColor Yellow
}

# ── Verify ────────────────────────────────────────────────────────────
Write-Host ''
Write-Host 'Verifikasi sertifikat:' -ForegroundColor Cyan
& $openssl.Source x509 -in $CertFile -noout -subject -dates -ext subjectAltName

Write-Host ''
Write-Host 'SELESAI.' -ForegroundColor Green
Write-Host "  cert : $CertFile"
Write-Host "  key  : $KeyFile"
Write-Host ''
Write-Host 'Langkah berikutnya:' -ForegroundColor Yellow
Write-Host '  docker compose --profile local-mongo --profile local-minio up -d --build'
Write-Host '  Buka: https://localhost:5000'
Write-Host ''
Write-Host 'Browser akan menampilkan peringatan self-signed — itu normal.' -ForegroundColor Yellow
Write-Host 'Klik "Advanced" -> "Proceed to localhost".'
