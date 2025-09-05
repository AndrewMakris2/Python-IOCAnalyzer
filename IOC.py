import requests
import re
import time
import base64

"""
==================== STEP-BY-STEP GUIDE TO RUN IOC.PY ====================

1️⃣ Open Terminal and navigate to the folder containing your script:
   cd /path/to/folder/with/IOC.py

2️⃣ Create a virtual environment (only once per project):
   python3 -m venv venv
   - This creates a folder called 'venv' with an isolated Python environment.

3️⃣ Activate the virtual environment:
   source venv/bin/activate
   - Your prompt should now start with '(venv)', indicating the environment is active.

4️⃣ Install required packages inside the virtual environment:
   pip install requests
   - This installs the 'requests' library needed for IOC.py to call VirusTotal API.

5️⃣ Run the IOC analyzer script:
   python IOC.py
   - The script will prompt you to enter IOCs (hashes, IPs, domains, or URLs).
   - Type an IOC and press Enter to analyze.
   - Type 'exit' to quit the program.

6️⃣ Optional: Deactivate the virtual environment when done:
   deactivate
   - This returns you to your system Python environment.

7️⃣ Notes / Tips:
   - Always run the script with the virtual environment activated to ensure it uses the correct packages.
   - Use safe example IOCs first (like Google DNS or EICAR test files) to validate functionality.
   - Avoid using real malware IOCs on an unprotected machine.
"""


# ==============================
# VirusTotal API Key (embedded)
# ==============================
VT_API_KEY = "0c7fb4369539ea51decf0c9d0d355ba049dd1514dfe332d8a03537ed2ea44fcd"

# ==============================
# Function to analyze IOC
# ==============================
def analyze_ioc(ioc_value):
    """
    Analyzes a given IOC (hash, IP, domain, or URL) using the VirusTotal API.
    """
    vt_api_url = "https://www.virustotal.com/api/v3/"
    headers = {
        "x-apikey": VT_API_KEY,
        "Accept": "application/json"
    }

    # Determine IOC type
    ioc_type = "unknown"
    endpoint = ""

    if re.match(r"^[a-f0-9]{32}$", ioc_value, re.IGNORECASE):
        ioc_type = "File Hash (MD5)"
        endpoint = f"files/{ioc_value}"
    elif re.match(r"^[a-f0-9]{40}$", ioc_value, re.IGNORECASE):
        ioc_type = "File Hash (SHA1)"
        endpoint = f"files/{ioc_value}"
    elif re.match(r"^[a-f0-9]{64}$", ioc_value, re.IGNORECASE):
        ioc_type = "File Hash (SHA256)"
        endpoint = f"files/{ioc_value}"
    elif re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc_value):
        ioc_type = "IP Address"
        endpoint = f"ip_addresses/{ioc_value}"
    elif re.match(r"^[a-z0-9-]+\.[a-z]{2,}(?:\.[a-z]{2,})?$", ioc_value, re.IGNORECASE):
        ioc_type = "Domain"
        endpoint = f"domains/{ioc_value}"
    elif ioc_value.startswith(("http://", "https://")):
        encoded_url = base64.urlsafe_b64encode(ioc_value.encode()).decode().strip("=")
        ioc_type = "URL"
        endpoint = f"urls/{encoded_url}"
    else:
        print(f"[-] Could not identify IOC type: {ioc_value}")
        return

    full_url = vt_api_url + endpoint
    print(f"[+] Analyzing {ioc_type}: {ioc_value}")

    try:
        response = requests.get(full_url, headers=headers)
        response.raise_for_status()
        data = response.json()

        if "data" in data and "attributes" in data["data"]:
            attributes = data["data"]["attributes"]

            # File Hash Report
            if ioc_type.startswith("File Hash"):
                stats = attributes.get("last_analysis_stats", {})
                reputation = attributes.get("reputation", 0)
                threat_labels = attributes.get("threat_names", [])

                print("\n--- Analysis Report ---")
                print(f"IOC Type: {ioc_type}")
                print(f"IOC Value: {ioc_value}")
                print(f"Reputation: {reputation}")
                print(f"Malicious Detections: {stats.get('malicious', 0)}")
                print(f"Harmless Detections: {stats.get('harmless', 0)}")
                print(f"Known Threat Names: {', '.join(threat_labels) if threat_labels else 'None'}")

            # IP, Domain, URL Report
            else:
                stats = attributes.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)

                print("\n--- Analysis Report ---")
                print(f"IOC Type: {ioc_type}")
                print(f"IOC Value: {ioc_value}")
                print(f"Malicious Detections: {malicious}")
                if malicious > 0:
                    print("[!] WARNING: This indicator has malicious detections.")
                else:
                    print("[+] This indicator appears harmless based on public scanners.")

        elif "error" in data:
            print(f"[-] API Error: {data['error']['message']}")
        else:
            print(f"[-] No analysis data found for {ioc_value}")

    except requests.exceptions.RequestException as e:
        print(f"[-] Request Error: {e}")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")


# ==============================
# Main Execution
# ==============================
if __name__ == "__main__":
    print("VirusTotal IOC Analyzer")
    print("-----------------------")
    print("Enter a File Hash, IP Address, Domain, or URL to analyze. Type 'exit' to quit.")

    while True:
        ioc_input = input("\nEnter IOC: ").strip()
        if ioc_input.lower() == "exit":
            break
        if ioc_input:
            analyze_ioc(ioc_input)
            time.sleep(1)  # Respect VT API rate limits


