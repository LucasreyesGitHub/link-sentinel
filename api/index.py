import os
import requests
import re
from flask import Flask, render_template, request

# Configuración de la App con ruta de templates corregida para Vercel
app = Flask(__name__, template_folder='../templates')

API_KEY = os.getenv("VT_API_KEY")
GH_TOKEN = os.getenv("GH_TOKEN")

def analizar_github_repo(url):
    match = re.search(r"github\.com/([\w\-\.]+)/([\w\-\.]+)", url)
    if not match: return None
    user, repo = match.groups()
    repo = repo.replace('.git', '').split('/')[0]
    api_url = f"https://api.github.com/repos/{user}/{repo}/contents"
    headers = {"Accept": "application/vnd.github.v3+json"}
    if GH_TOKEN: headers["Authorization"] = f"token {GH_TOKEN}"
    try:
        res = requests.get(api_url, headers=headers, timeout=2)
        if res.status_code == 200:
            items = res.json()
            exts = ['.exe', '.bat', '.vbs', '.pyw', '.ps1', '.sh', '.com', '.zip', '.rar', '.bin', '.msi']
            keys = ['malware', 'payload', 'exploit', 'virus', 'bin', 'tools']
            found = []
            for item in items:
                n = item['name'].lower()
                if any(n.endswith(ex) for ex in exts) or any(k in n for k in keys):
                    t = "📁 Carpeta" if item['type'] == 'dir' else "Archivo"
                    found.append(f"{t}: {item['name']}")
            return found if found else None
    except: return None
    return None

def consultar_vt(url):
    if not API_KEY: return None, "Falta API Key"
    headers = {"x-apikey": API_KEY}
    try:
        res = requests.post("https://www.virustotal.com/api/v3/urls", data={"url": url}, headers=headers, timeout=2)
        if res.status_code == 200:
            id_an = res.json()['data']['id']
            rep = requests.get(f"https://www.virustotal.com/api/v3/analyses/{id_an}", headers=headers, timeout=2)
            stats = rep.json()['data']['attributes']['results']
            return sum(1 for r in stats.values() if r['category'] == 'malicious'), None
    except: return None, "Servicio lento"
    return None, "Error API"

@app.route('/', methods=['GET', 'POST'])
def index():
    resultado, peligros, url_final, error = None, None, None, None
    if request.method == 'POST':
        url_in = request.form.get('url', '').strip()
        if url_in:
            if not url_in.startswith('http'): url_in = 'https://' + url_in
            try:
                r_url = requests.head(url_in, allow_redirects=True, timeout=2)
                url_final = r_url.url
            except: url_final = url_in
            resultado, error = consultar_vt(url_final)
            if "github.com" in url_final.lower():
                peligros = analizar_github_repo(url_final)
    return render_template('index.html', resultado=resultado, peligros=peligros, url=url_final, error=error)

# IMPORTANTE: Para Vercel, NO usamos app.run()
