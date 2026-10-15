from flask import Flask, request, jsonify, send_from_directory
from urllib.parse import urlparse
from datetime import datetime, timezone
import socket, ssl, ipaddress, re

app = Flask(__name__)
DASHBOARD = "certwatch_interactive_dashboard.html"

@app.get("/")
def home():
    return send_from_directory(".", DASHBOARD)

def validate_host(host):
    if not host or len(host) > 253 or any(ch.isspace() for ch in host):
        raise ValueError("Enter a valid public hostname, such as example.com.")
    try:
        ip = ipaddress.ip_address(host)
        if not ip.is_global:
            raise ValueError("Only public websites can be checked.")
        raise ValueError("Enter a website hostname, such as example.com, not an IP address.")
    except ValueError as err:
        if str(err).startswith("Only public") or str(err).startswith("Enter a website"):
            raise
    labels = host.rstrip(".").split(".")
    if len(labels) < 2 or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", x) for x in labels):
        raise ValueError("Enter a valid hostname, such as example.com.")
    try:
        addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise ValueError("Hostname not found. Check the spelling and try again.")
    if not addresses:
        raise ValueError("Hostname did not resolve to an IP address.")
    for item in addresses:
        if not ipaddress.ip_address(item[4][0]).is_global:
            raise ValueError("Only public websites can be checked.")
    return host.rstrip(".")

@app.post("/api/check")
def check_certificate():
    data = request.get_json(silent=True) or {}
    raw = str(data.get("url", "")).strip()
    parsed = urlparse(raw if "://" in raw else "https://" + raw)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        return jsonify(error="Enter a website such as example.com or https://example.com."), 400
    if parsed.username or parsed.password or parsed.port not in (None, 443):
        return jsonify(error="Credentials and custom ports are not supported."), 400
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        return jsonify(error="Enter only the hostname, without a page path or query."), 400
    try:
        host = validate_host(parsed.hostname)
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                tls_version = tls.version() or "Unknown"
        if not cert.get("notAfter"):
            raise ValueError("The website did not provide an expiry date.")
        expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        days = int((expiry - now).total_seconds() // 86400)
        if (expiry - now).total_seconds() < 0:
            status = "Expired"
        elif days <= 3:
            status = "Critical"
        elif days <= 14:
            status = "Warning"
        else:
            status = "Healthy"
        issuer = []
        for group in cert.get("issuer", ()):
            for key, value in group:
                if key in ("organizationName", "commonName"):
                    issuer.append(value)
        return jsonify(
            website=host, issuer=", ".join(dict.fromkeys(issuer)) or "Issuer unavailable",
            expires_at=expiry.isoformat(), days_left=days, status=status,
            tls_version=tls_version, checked_at=now.isoformat()
        )
    except ValueError as err:
        return jsonify(error=str(err)), 400
    except (socket.timeout, TimeoutError):
        return jsonify(error="Connection timed out. Try again later."), 400
    except ssl.SSLCertVerificationError:
        return jsonify(error="Certificate validation failed: it may be expired, untrusted, or mismatched."), 400
    except ssl.SSLError:
        return jsonify(error="A secure TLS connection could not be established."), 400
    except OSError:
        return jsonify(error="Could not connect to HTTPS port 443. Check your internet connection and hostname."), 400
    except Exception:
        app.logger.exception("Unexpected certificate check error")
        return jsonify(error="An unexpected error occurred while checking this website."), 500

if __name__ == "__main__":
    # Local development only. Do not expose Flask's debug server publicly.
        import os

app.run(
    host="0.0.0.0",
    port=int(os.environ.get("PORT", 10000)),
    debug=False
)
