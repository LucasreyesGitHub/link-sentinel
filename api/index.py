import os
import requests
import re
from flask import Flask, render_template, request
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)

# Configuración
API_KEY = os.getenv("VT_API_KEY")
GH_TOKEN = os.getenv("GH_TOKEN")

@app.route('/', methods=['GET', 'POST'])
def index():
    resultado, peligros, url_final, error = None, None, None, None

    if request.method == 'POST':
        url_input = request.form.get('url', '').strip()
        if url_input:
            if not url_input.startswith('http'): url_input = 'https://' + url_input
            
            # PASO 1: REDIRECCIÓN (Timeout de 1.5s)
            try:
                res_url = requests.head(url_input, allow_redirects=True, timeout=1.5)
                url_final = res_url.url
            except:
                url_final = url_input

            # PASO 2: VIRUSTOTAL (Si falla, no cuelga la web)
            if API_KEY:
                try:
                    h = {"x-apikey": API_KEY}
                    r_vt = requests.post("https://www.virustotal.com/api/v3/urls", data={"url": url_final}, headers=h, timeout=1.5)
                    if r_vt.status_code == 200:
                        id_an = r_vt.json()['data']['id']
                        rep = requests.get(f"https://www.virustotal.com/api/v3/analyses/{id_an}", headers=h, timeout=1.5)
                        stats = rep.json()['data']['attributes']['results']
                        resultado = sum(1 for r in stats.values() if r['category'] == 'malicious')
                except:
                    error = "Servicio de reputación lento. Mostrando análisis local..."

            # PASO 3: GITHUB OSINT (Si falla, no cuelga la web)
            if "github.com" in url_final.lower():
                try:
                    match = re.search(r"github\.com/([\w\-\.]+)/([\w\-\.]+)", url_final)
                    if match:
                        user, repo = match.groups()
                        repo = repo.replace('.git', '').split('/')[0]
                        api_gh = f"https://api.github.com/repos/{user}/{repo}/contents"
                        gh_h = {"Accept": "application/vnd.github.v3+json"}
                        if GH_TOKEN: gh_h["Authorization"] = f"token {GH_TOKEN}"
                        
                        res_gh = requests.get(api_gh, headers=gh_h, timeout=1.5)
                        if res_gh.status_code == 200:
                            exts = ['.exe', '.bat', '.vbs', '.pyw', '.ps1', '.sh', '.com', '.zip', '.rar', '.bin']
                            keys = ['malware', 'payload', 'exploit', 'virus', 'bin']
                            items = res_gh.json()
                            peligros = []
                            for i in items:
                                n = i['name'].lower()
                                if any(n.endswith(ex) for ex in exts) or any(k in n for k in keys):
                                    t = "📁 Carpeta" if i['type'] == 'dir' else "Archivo"
                                    peligros.append(f"{t}: {i['name']}")
                except:
                    print("GitHub API Timeout")

    return render_template('index.html', resultado=resultado, peligros=peligros, url=url_final, error=error)

