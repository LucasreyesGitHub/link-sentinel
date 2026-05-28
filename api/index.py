import os
import re
import secrets
import socket
import ipaddress
import requests
from urllib.parse import urlparse
from flask import Flask, render_template, request, session, abort

app = Flask(__name__, template_folder='../templates')

# SECRET_KEY debe configurarse como variable de entorno en Vercel.
# Sin ella, las sesiones se invalidan en cada reinicio de la función serverless.
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

API_KEY = os.getenv("VT_API_KEY")
GH_TOKEN = os.getenv("GH_TOKEN")

_REDES_PRIVADAS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local / metadata AWS
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

def _ip_privada(host):
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(host))
        return any(ip in red for red in _REDES_PRIVADAS)
    except Exception:
        return True  # No se puede resolver → bloquear por seguridad

def validar_url(url):
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    if parsed.scheme not in ('http', 'https'):
        return False
    host = parsed.hostname
    return bool(host) and not _ip_privada(host)

def analizar_github_repo(url):
    match = re.search(r"github\.com/([\w\-]+)/([\w\-]+)", url)
    if not match:
        return None
    user, repo = match.groups()
    api_url = f"https://api.github.com/repos/{user}/{repo}/contents"
    headers = {"Accept": "application/vnd.github.v3+json"}
    if GH_TOKEN:
        headers["Authorization"] = f"token {GH_TOKEN}"
    try:
        res = requests.get(api_url, headers=headers, timeout=5)
        if res.status_code != 200:
            return None
        items = res.json()
        if not isinstance(items, list):
            return None
        exts = ['.exe', '.bat', '.vbs', '.pyw', '.ps1', '.sh', '.com', '.zip', '.rar', '.bin', '.msi']
        keys = ['malware', 'payload', 'exploit', 'virus', 'bin', 'tools']
        found = []
        for item in items:
            if not isinstance(item, dict):
                continue
            n = item.get('name', '').lower()
            if any(n.endswith(ex) for ex in exts) or any(k in n for k in keys):
                t = "📁 Carpeta" if item.get('type') == 'dir' else "Archivo"
                found.append(f"{t}: {item['name']}")
        return found if found else None
    except requests.RequestException:
        return None

def consultar_vt(url):
    if not API_KEY:
        return None, "Servicio no disponible"
    headers = {"x-apikey": API_KEY}
    try:
        res = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            data={"url": url},
            headers=headers,
            timeout=5,
        )
        if res.status_code == 200:
            id_an = res.json()['data']['id']
            rep = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{id_an}",
                headers=headers,
                timeout=5,
            )
            if rep.status_code == 200:
                stats = rep.json()['data']['attributes']['results']
                return sum(1 for r in stats.values() if r['category'] == 'malicious'), None
    except requests.RequestException:
        return None, "Servicio no disponible"
    return None, "Error al analizar"

@app.route('/', methods=['GET', 'POST'])
def index():
    resultado, peligros, url_final, error = None, None, None, None

    if request.method == 'GET':
        session['csrf_token'] = secrets.token_hex(16)

    if request.method == 'POST':
        stored = session.get('csrf_token', '')
        enviado = request.form.get('csrf_token', '')
        if not stored or not secrets.compare_digest(enviado, stored):
            abort(403)
        session['csrf_token'] = secrets.token_hex(16)

        url_in = request.form.get('url', '').strip()[:2048]
        if url_in:
            if not url_in.startswith(('http://', 'https://')):
                url_in = 'https://' + url_in

            if not validar_url(url_in):
                error = "URL no válida o no permitida"
            else:
                try:
                    r_url = requests.head(
                        url_in,
                        allow_redirects=True,
                        timeout=5,
                        headers={"User-Agent": "LinkSentinel/1.0"},
                    )
                    url_final = r_url.url
                    if not validar_url(url_final):
                        error = "La URL redirige a una dirección no permitida"
                        url_final = None
                    else:
                        resultado, error = consultar_vt(url_final)
                        if url_final and "github.com" in url_final.lower():
                            peligros = analizar_github_repo(url_final)
                except requests.RequestException:
                    error = "No se pudo alcanzar la URL"

    csrf_token = session.get('csrf_token', '')
    return render_template(
        'index.html',
        resultado=resultado,
        peligros=peligros,
        url=url_final,
        error=error,
        csrf_token=csrf_token,
    )

# IMPORTANTE: Para Vercel, NO usamos app.run()
