# Link Sentinel 🛡️

Analizador de seguridad de URLs escrito en Python. Este proyecto combina análisis de reglas lógicas (heurística) con consultas de reputación global mediante la API de VirusTotal.

## 🚀 Características
- **Detección de Protocolo:** Identifica sitios sin cifrado SSL.
- **Análisis Estructural:** Busca caracteres usados comúnmente en ataques de phishing.
- **Integración con VirusTotal:** Consulta resultados de más de 70 motores de antivirus en tiempo real.

## 🛠️ Instalación y Uso
1. Clona el repositorio.
2. Crea un archivo `.env` y añade tu `VT_API_KEY`.
3. Instala dependencias: `pip install -r requirements.txt`.
4. Ejecuta: `python main.py`.

## 🧠 ¿Cómo funciona?
El script toma la URL ingresada y realiza dos validaciones:
1. **Lógica local:** Evalúa si la URL tiene comportamientos sospechosos (ej. falta de HTTPS).
2. **Consulta remota:** Envía un hash de la URL a VirusTotal para verificar si ha sido reportada previamente como maliciosa.