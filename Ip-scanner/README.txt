SOC Scan 1.0 - IP Intelligence Scanner
By TheNephilim

Descripción
-----------
Este script permite analizar una lista de direcciones IP utilizando:
- VirusTotal API
- AbuseIPDB API

El script consulta ambas fuentes de inteligencia y genera un reporte en Excel
con los resultados del análisis.

Requisitos
-----------
Python 3.11 o superior

Instalar dependencias:

pip install -r requirements.txt

Configuración
-------------
1. Crear un archivo llamado ".env" en la misma carpeta del script.

2. Dentro del archivo .env agregar:

VT_API_KEY=TU_API_KEY_DE_VIRUSTOTAL
ABUSE_API_KEY=TU_API_KEY_DE_ABUSEIPDB

Uso
---
1. Ejecutar el script:

python Scannerdeips2.py

O hacer doble clic en el archivo .py.

2. Se abrirá una ventana para seleccionar un archivo TXT con las IPs.

Ejemplo de archivo TXT:

8.8.8.8
1.1.1.1
185.220.101.4

3. El script analizará las IPs utilizando VirusTotal y AbuseIPDB.

4. Al finalizar se generará un archivo Excel:

Scanner_Ips_Report.xlsx

Columnas del reporte
--------------------
IP
Domain
Country (AbuseIPDB)
VT_Malicious
VT_Suspicious
Abuse_Score
Reports
