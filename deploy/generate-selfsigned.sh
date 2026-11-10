#!/usr/bin/env sh
#
# Generate a self-signed TLS certificate for the LARAS app container.
#
# Creates deploy/certs/cert.pem and deploy/certs/key.pem (PEM, RSA 2048)
# for gunicorn inside the `app` container.
#
# SANs include localhost, the loopback addresses, the hostname, and every
# local IPv4 address, so the app is reachable by name or IP without a
# name-mismatch error.
#
# Browsers will STILL warn about a self-signed certificate. That is
# expected; click "Advanced -> Proceed" once per browser. To remove the
# warning you must import cert.pem into each client's trust store.
#
# Usage:
#   sh deploy/generate-selfsigned.sh [days] [extra-host ...]
#   sh deploy/generate-selfsigned.sh 825 laras.soc.local 10.0.0.5
#
# deploy/certs/ is gitignored. Never commit certificates.

set -eu

DAYS="${1:-825}"
if [ "$#" -gt 0 ]; then
    shift
fi

# Resolve paths relative to this script so it works from any CWD.
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CERTS_DIR="$SCRIPT_DIR/certs"
CERT_FILE="$CERTS_DIR/cert.pem"
KEY_FILE="$CERTS_DIR/key.pem"

echo "=== LARAS — generate self-signed TLS certificate ==="

if ! command -v openssl >/dev/null 2>&1; then
    echo "ERROR: openssl tidak ditemukan di PATH." >&2
    echo "  Debian/Ubuntu : sudo apt-get install -y openssl" >&2
    echo "  Alpine        : apk add openssl" >&2
    echo "  macOS         : sudah tersedia (atau: brew install openssl)" >&2
    exit 1
fi

echo "openssl: $(openssl version)"

mkdir -p "$CERTS_DIR"
echo "Direktori: $CERTS_DIR"

# ── Build the SAN list ────────────────────────────────────────────────
# Note: subjectAltName must be a single comma-separated string.
SAN="DNS:localhost,IP:127.0.0.1,IP:::1"

HOSTNAME_VAL=$(hostname 2>/dev/null || echo "")
if [ -n "$HOSTNAME_VAL" ]; then
    SAN="$SAN,DNS:$HOSTNAME_VAL"
fi

# Local IPv4 addresses. Both `hostname -I` (Linux) and `ip -4 addr`
# shapes are attempted; absence is non-fatal.
if command -v hostname >/dev/null 2>&1 && hostname -I >/dev/null 2>&1; then
    for ip in $(hostname -I 2>/dev/null); do
        case "$ip" in
            127.*|169.254.*) : ;;
            *:*) : ;;  # skip IPv6 here
            *) SAN="$SAN,IP:$ip" ;;
        esac
    done
elif command -v ip >/dev/null 2>&1; then
    for ip in $(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1); do
        SAN="$SAN,IP:$ip"
    done
fi

# Extra hosts passed on the command line.
for extra in "$@"; do
    case "$extra" in
        [0-9]*.[0-9]*.[0-9]*.[0-9]*) SAN="$SAN,IP:$extra" ;;
        *) SAN="$SAN,DNS:$extra" ;;
    esac
done

echo ""
echo "SAN yang disertakan:"
echo "$SAN" | tr ',' '\n' | sed 's/^/  - /'

# ── Generate key + certificate ────────────────────────────────────────
echo ""
echo "Membuat private key dan certificate..."

# Generate into TEMP paths and only publish on success.
#
# Why this matters: `openssl req -newkey` writes the key file early, before
# it finishes writing the certificate. If the command then fails (unsupported
# -addext, bad SAN, disk full), a partial key can be left behind. Because the
# container now FAILS CLOSED on a missing cert, a leftover partial pair is
# more dangerous than no pair at all: it looks present, so the entrypoint
# proceeds and gunicorn fails at TLS negotiation with a confusing error.
# Writing to temp files means a failure leaves NO publishable cert behind.
#
# We also verify the key and certificate actually match before publishing —
# a mismatched pair would fail at container startup.
TMP_KEY="${KEY_FILE}.tmp.$$"
TMP_CERT="${CERT_FILE}.tmp.$$"
# Clean up temp files on ANY exit (success or failure) so nothing partial
# is left lying around for a later run to trip over.
cleanup_tmp() {
    rm -f "$TMP_KEY" "$TMP_CERT"
}
trap cleanup_tmp EXIT INT TERM

# -addext needs OpenSSL 1.1.1+. Fall back to a temporary config file on
# older versions so the SANs are never silently dropped — a cert without
# SANs is rejected outright by modern browsers.
if openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$TMP_KEY" \
        -out "$TMP_CERT" \
        -days "$DAYS" \
        -subj "/C=ID/ST=DKI Jakarta/L=Jakarta/O=LARAS SOC/CN=localhost" \
        -addext "subjectAltName=$SAN" \
        -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
        -addext "extendedKeyUsage=serverAuth" 2>/dev/null \
   && [ -s "$TMP_KEY" ] && [ -s "$TMP_CERT" ]; then
    :
else
    echo "Catatan: -addext tidak didukung — memakai file config sementara."
    TMP_CNF=$(mktemp)
    cat > "$TMP_CNF" <<EOF
[req]
distinguished_name = dn
x509_extensions = v3_req
prompt = no
[dn]
CN = localhost
O = LARAS SOC
[v3_req]
subjectAltName = $SAN
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
EOF
    if ! openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout "$TMP_KEY" \
            -out "$TMP_CERT" \
            -days "$DAYS" \
            -config "$TMP_CNF" \
       || [ ! -s "$TMP_KEY" ] || [ ! -s "$TMP_CERT" ]; then
        rm -f "$TMP_CNF"
        echo "ERROR: openssl gagal membuat sertifikat. Tidak ada file yang" >&2
        echo "       dipublikasikan — perbaiki errornya lalu jalankan ulang." >&2
        exit 1
    fi
    rm -f "$TMP_CNF"
fi

# ── Verify key/cert are a matching pair BEFORE publishing ─────────────
# Comparing the public modulus of each is the standard check. If they do
# not match, gunicorn would fail to load the cert at runtime.
KEY_MODULUS=$(openssl rsa -noout -modulus -in "$TMP_KEY" 2>/dev/null | openssl md5)
CERT_MODULUS=$(openssl x509 -noout -modulus -in "$TMP_CERT" 2>/dev/null | openssl md5)
if [ -z "$KEY_MODULUS" ] || [ "$KEY_MODULUS" != "$CERT_MODULUS" ]; then
    echo "ERROR: private key dan certificate TIDAK cocok (modulus berbeda)." >&2
    echo "       Tidak ada file yang dipublikasikan. Jalankan ulang script." >&2
    exit 1
fi

# Sanity: the cert must not already be expired.
if ! openssl x509 -in "$TMP_CERT" -noout -checkend 0 >/dev/null 2>&1; then
    echo "ERROR: certificate yang dihasilkan sudah kadaluarsa." >&2
    exit 1
fi

# ── Publish atomically ────────────────────────────────────────────────
# mv within the same directory is atomic on POSIX, so a reader never sees
# a half-written cert/key.
chmod 600 "$TMP_KEY"
chmod 644 "$TMP_CERT"
mv -f "$TMP_KEY" "$KEY_FILE"
mv -f "$TMP_CERT" "$CERT_FILE"
trap - EXIT INT TERM

# ── Verify ────────────────────────────────────────────────────────────
echo ""
echo "Verifikasi sertifikat:"
openssl x509 -in "$CERT_FILE" -noout -subject -dates -ext subjectAltName

echo ""
echo "SELESAI."
echo "  cert : $CERT_FILE"
echo "  key  : $KEY_FILE"
echo ""
echo "Langkah berikutnya:"
echo "  docker compose --profile local-mongo --profile local-minio up -d --build"
echo "  Buka: https://localhost:5000"
echo ""
echo "Browser akan menampilkan peringatan self-signed — itu normal."
echo "Klik \"Advanced\" -> \"Proceed\"."
