# 🛡️ Link Sentinel

Analizador de seguridad de URLs desarrollado en Python. Este proyecto combina análisis heurístico (basado en reglas lógicas) con consultas de reputación global utilizando la API de VirusTotal.

## 🌐 Demo Online

🚀 **Accede directamente a la herramienta sin instalar nada:**  
👉 [Link Sentinel Web App](TU_LINK_DE_VERCEL_AQUI)

---

## 🚀 Características

- 🔒 **Detección de Protocolo:** Identifica sitios sin cifrado SSL (HTTP).
- 🧩 **Análisis Estructural:** Detecta patrones comunes en ataques de phishing.
- 🌍 **Integración con VirusTotal:** Consulta más de 70 motores antivirus en tiempo real.

---

## 🧠 ¿Cómo funciona?

El sistema analiza la URL en dos niveles:

- **Lógica local:** Evalúa comportamientos sospechosos (por ejemplo, ausencia de HTTPS o estructura irregular).
- **Consulta remota:** Envía un hash de la URL a VirusTotal para verificar si ha sido reportada como maliciosa.

---

## 🛠️ Uso local (opcional)

Si deseas ejecutarlo en tu entorno local:

1. Clona el repositorio:
   ```bash
   git clone <TU_REPO_URL>
   cd link-sentinel
2. Crea un archivo .env y añade tu API Key:
   VT_API_KEY=tu_api_key_aqui
3. Instala las dependencias:
   pip install -r requirements.txt
4. Ejecuta el script:
   python main.py     
    
