import requests
import time
import os
import tkinter as tk
from tkinter import filedialog
import pycountry
import pandas as pd
from dotenv import load_dotenv

# Cargar variables del .env
load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSE_API_KEY = os.getenv("ABUSE_API_KEY")

results = []


def traducir_pais(codigo):
    try:
        return pycountry.countries.get(alpha_2=codigo).name
    except:
        return codigo


def calcular_estado(vt_malicious, vt_suspicious, abuse_reports):

    score_total = vt_malicious + vt_suspicious + abuse_reports

    if score_total == 0:
        return "Clean"

    elif 1 <= score_total <= 5:
        return "Suspicious"

    else:
        return "Malicious"


def obtener_nombre_archivo(base_name):

    if not os.path.exists(base_name):
        return base_name

    contador = 1

    while True:

        nuevo_nombre = f"Scanner_Ips_Report_{contador}.xlsx"

        if not os.path.exists(nuevo_nombre):
            return nuevo_nombre

        contador += 1


def get_vt_info(ip):

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}

    response = requests.get(url, headers=headers)

    if response.status_code == 200:

        data = response.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]
        code = data["data"]["attributes"].get("country", "Unknown")

        country = traducir_pais(code)

        return stats, country

    else:

        return None, None


def get_abuse_info(ip):

    url = "https://api.abuseipdb.com/api/v2/check"

    querystring = {
        "ipAddress": ip,
        "maxAgeInDays": "365"
    }

    headers = {
        "Key": ABUSE_API_KEY,
        "Accept": "application/json"
    }

    response = requests.get(url, headers=headers, params=querystring)

    if response.status_code == 200:

        data = response.json()["data"]

        code = data.get("countryCode", "Unknown")
        country = traducir_pais(code)

        return {
            "abuseScore": data["abuseConfidenceScore"],
            "totalReports": data["totalReports"],
            "country": country,
            "domain": data.get("domain", "N/A")
        }

    else:

        return None


def scan_ip(ip):

    print(f"\n🟦 Analizando IP: {ip}")

    vt_data, vt_country = get_vt_info(ip)
    abuse_data = get_abuse_info(ip)

    if abuse_data:

        print(
            f"[AbuseIPDB] Domain: {abuse_data['domain']} | "
            f"Score: {abuse_data['abuseScore']} | "
            f"Reports: {abuse_data['totalReports']} | "
            f"Country: {abuse_data['country']}"
        )

    else:

        print("[AbuseIPDB] No se pudo obtener información.")

    if vt_data:

        print(
            f"[VirusTotal] Malicious: {vt_data['malicious']} | "
            f"Suspicious: {vt_data['suspicious']} | "
            f"Country: {vt_country}"
        )

    else:

        print("[VirusTotal] No se pudo obtener información.")

    if vt_data and abuse_data:

        estado = calcular_estado(
            vt_data["malicious"],
            vt_data["suspicious"],
            abuse_data["totalReports"]
        )

        print(f"[Status] {estado}")

        results.append({
            "IP": ip,
            "Domain": abuse_data["domain"],
            "Country": abuse_data["country"],
            "VT_Malicious": vt_data["malicious"],
            "VT_Suspicious": vt_data["suspicious"],
            "Abuse_Score": abuse_data["abuseScore"],
            "Reports": abuse_data["totalReports"],
            "Status": estado
        })


def seleccionar_archivo():

    root = tk.Tk()
    root.withdraw()

    archivo = filedialog.askopenfilename(
        title="Selecciona archivo .txt con IPs",
        filetypes=[("Archivos de texto", "*.txt")]
    )

    return archivo


def generar_excel():

    if not results:
        return

    df = pd.DataFrame(results)

    output_file = obtener_nombre_archivo("Scanner_Ips_Report.xlsx")

    with pd.ExcelWriter(output_file, engine="xlsxwriter") as writer:

        df.to_excel(writer, sheet_name="Results", index=False)

        workbook = writer.book
        worksheet = writer.sheets["Results"]

        formato_rojo = workbook.add_format({'bg_color': '#FFC7CE'})
        formato_amarillo = workbook.add_format({'bg_color': '#FFF2CC'})
        formato_verde = workbook.add_format({'bg_color': '#C6EFCE'})

        status_col = df.columns.get_loc("Status")

        for row_num, status in enumerate(df["Status"], start=1):

            if status == "Malicious":
                worksheet.write(row_num, status_col, status, formato_rojo)

            elif status == "Suspicious":
                worksheet.write(row_num, status_col, status, formato_amarillo)

            elif status == "Clean":
                worksheet.write(row_num, status_col, status, formato_verde)

    print("\n📊 Reporte Excel generado:")
    print(output_file)


def main():

    path = seleccionar_archivo()

    if not path:

        print("❌ No seleccionaste ningún archivo.")
        return

    with open(path, "r") as file:

        ips = [line.strip() for line in file if line.strip()]

    print("\nSOC Scan 1.2 By TheNephilim")
    print("https://www.tiktok.com/@thenephilimx")

    for i, ip in enumerate(ips, start=1):

        scan_ip(ip)

        if i % 5 == 0 and i != len(ips):

            print("⏸ Pausa de 45 segundos por límite de consultas...\n")
            time.sleep(45)

    print("\n" + "═" * 50)
    print("✅ Análisis completado. Puedes revisar los resultados arriba.")

    generar_excel()

    input("🔚 Presiona Enter para salir...")


if __name__ == "__main__":
    main()