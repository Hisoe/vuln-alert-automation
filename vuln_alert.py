import requests
import csv
import google.generativeai as genai

# --- Configuration ---
CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
INVENTORY_FILE = "scan_report.csv"

# PASTE YOUR KEYS HERE
GEMINI_API_KEY = "YOUR_GEMINI_API_KEY"
DISCORD_WEBHOOK_URL = "YOUR_DISCORD_WEBHOOK_URL"

# Configure the AI Model (Using the stable pro model as tested!)
genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel('models/gemini-2.5-flash')

def fetch_cisa_data():
    print("[*] Fetching live threat intelligence from CISA KEV database...")
    try:
        response = requests.get(CISA_URL)
        response.raise_for_status()
        data = response.json()
        cisa_cves = [vuln["cveID"] for vuln in data.get("vulnerabilities", [])]
        print(f"[+] Successfully loaded {len(cisa_cves)} actively exploited vulnerabilities.\n")
        return cisa_cves
    except requests.exceptions.RequestException as e:
        print(f"[-] Error fetching data from CISA: {e}")
        return []

def generate_executive_summary(cve, software):
    print(f"    [*] Asking AI for business risk summary of {cve}...")
    prompt = f"Explain the business risk of vulnerability {cve} affecting {software}. Keep it strictly to a 3-sentence executive summary. Do not use highly technical jargon. Focus on the impact to business operations and data."
    
    try:
        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        return f"Could not generate AI summary due to error: {e}"

def send_discord_alert(alert):
    print(f"[*] Firing webhook alert for {alert['hostname']}...")
    
    # Format the message using Discord's Markdown syntax
    message = (
        f"🚨 **CRITICAL VULNERABILITY DETECTED** 🚨\n"
        f"**Target Host:** `{alert['hostname']}`\n"
        f"**Vulnerability:** {alert['cve']} *(Actively Exploited!)*\n"
        f"**Affected Software:** {alert['software']}\n\n"
        f"**Executive Risk Summary:**\n> {alert['summary']}\n"
        f"--------------------------------------------------"
    )
    
    payload = {"content": message}
    
    try:
        # Send the POST request to Discord
        response = requests.post(DISCORD_WEBHOOK_URL, json=payload)
        response.raise_for_status()
        print("    [+] Alert successfully delivered to Discord!\n")
    except Exception as e:
        print(f"    [-] Failed to send Discord alert: {e}\n")

def analyze_inventory(cisa_cves):
    print("[*] Analyzing local asset inventory...")
    critical_alerts = []
    
    try:
        with open(INVENTORY_FILE, mode='r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            
            for row in reader:
                hostname = row["Hostname"]
                software = f'{row["Vendor"]} {row["Product"]} {row["Version"]}'
                cve = row["Detected_CVE"]
                
                if cve in cisa_cves:
                    print(f"[!] CRITICAL MATCH: {hostname} is vulnerable to {cve}!")
                    
                    # Generate AI Summary
                    ai_summary = generate_executive_summary(cve, software)
                    
                    critical_alerts.append({
                        "hostname": hostname,
                        "software": software,
                        "cve": cve,
                        "summary": ai_summary
                    })
                elif cve != "None":
                    print(f"[v] {hostname} has {cve}, but it is NOT currently actively exploited.")
                else:
                    print(f"[-] {hostname} is clean.")
                    
        return critical_alerts
        
    except FileNotFoundError:
        print(f"[-] Error: Could not find {INVENTORY_FILE}.")
        return []

# --- Execution Block ---
if __name__ == "__main__":
    cisa_list = fetch_cisa_data()
    
    if cisa_list:
        alerts = analyze_inventory(cisa_list)
        
        if alerts:
            print(f"\n[*] Processing {len(alerts)} alerts for Discord transmission...\n")
            for alert in alerts:
                send_discord_alert(alert)
        else:
            print("\n[+] No actively exploited vulnerabilities found. No alerts sent.")