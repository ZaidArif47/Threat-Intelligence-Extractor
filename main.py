import re
import requests
import spacy
import json
from PyPDF2 import PdfReader
from tld_validator import tldValidate
from pdf_summary_extractor import generate_report

# Load the spaCy model (e.g., en_core_web_sm)
nlp = spacy.load("en_core_web_sm")

def get_malware_details(file_hash, api_key):
    url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
    headers = {'x-apikey': api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return None

def is_valid_domain(domain: str) -> bool:
    # Regular expression for domain validation (includes subdomains and multi-level TLDs)
    domain_regex = re.compile(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+\.[A-Za-z]{2,24}$"
    )
    
    # Check if the domain matches the regex
    if domain_regex.match(domain):
        return True
    return False

def extract_iocs(report_text):
    ip_pattern = r'(?:(?:\d{1,3}\.){3}\d{1,3})'
    ip_addresses = re.findall(ip_pattern, report_text)
    
    domain_pattern = r'(?:(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})'
    domains = re.findall(domain_pattern, report_text)
    
    # Validate domains using both is_valid_domain and tldValidate
    valid_domains = [
        domain for domain in domains 
        if is_valid_domain(domain) and tldValidate(domain.split('.')[-1])
    ]
    
    # Remove duplicates by converting lists to sets
    unique_ips = list(set(ip_addresses))
    unique_domains = list(set(valid_domains))
    
    return {'IP addresses': unique_ips, 'Domains': unique_domains}

def extract_ttps(report_text):
    # Process the report text with spaCy NLP
    doc = nlp(report_text)

    # Define potential TTPs patterns with their corresponding IDs and keywords for tactics
    tactics_patterns = {
        'TA0001': ['initial access', 'exploitation', 'gain access', 'entry', 'bypass'],  # Initial Access
        'TA0002': ['execution', 'run', 'launch', 'execute', 'trigger'],  # Execution
        'TA0003': ['persistence', 'maintain access', 'backdoor', 'reboot', 'keep'],  # Persistence
        'TA0005': ['defense evasion', 'obfuscation', 'avoid detection', 'mask', 'bypass'],  # Defense Evasion
        'TA0006': ['credential access', 'steal credentials', 'password', 'harvest'],  # Credential Access
        'TA0007': ['discovery', 'recon', 'enumerate', 'scan'],  # Discovery
        'TA0008': ['lateral movement', 'spread', 'pivot', 'move', 'internal network'],  # Lateral Movement
        'TA0009': ['collection', 'gather data', 'extract data', 'harvest', 'capture'],  # Collection
        'TA0010': ['exfiltration', 'steal', 'extract', 'data theft', 'export'],  # Exfiltration
        'TA0011': ['command and control', 'c2', 'remote control', 'reverse shell'],  # Command and Control
        'TA0040': ['impact', 'destruction', 'damage', 'wipe', 'encrypt'],  # Impact
        'TA0042': ['resource development', 'tools', 'infrastructure', 'setup'],  # Resource Development
        'TA0043': ['reconnaissance', 'scanning', 'recon', 'gather intel']  # Reconnaissance
    }

    # Define techniques with corresponding IDs and keywords
    techniques_patterns = {
        'T1548.001': ['setuid', 'setgid', 'root privileges', 'user privilege escalation'],  # Setuid and Setgid
        'T1548.002': ['user account control', 'bypass uac', 'disable uac', 'elevation of privilege'],  # Bypass User Account Control
        'T1566.001': ['spear phishing', 'malicious attachment', 'email phishing', 'attachment phishing'],  # Spear Phishing Attachment
        'T1059.001': ['powershell', 'cmd.exe', 'script execution', 'powershell command'],  # PowerShell
        'T1071.001': ['web shell', 'HTTP', 'web communication', 'web server'],  # Web Shell
        'T1005': ['data from local system', 'local data', 'file copy', 'data extraction'],  # Data from Local System
        'T1041': ['exfiltration over C2', 'command and control', 'remote server', 'C2 communication']  # Exfiltration over C2
    }

    detected_tactics = []
    detected_techniques = []

    # Check for tactics in the text based on keywords
    for tactic_id, keywords in tactics_patterns.items():
        if any(keyword.lower() in report_text.lower() for keyword in keywords):
            detected_tactics.append([f"'{tactic_id}': '{tactics_patterns[tactic_id][0].title()}'"])

    # Check for techniques in the text based on keywords
    for technique_id, keywords in techniques_patterns.items():
        if any(keyword.lower() in report_text.lower() for keyword in keywords):
            detected_techniques.append([f"'{technique_id}': '{techniques_patterns[technique_id][0].title()}'"])

    return {'Tactics': detected_tactics, 'Techniques': detected_techniques} 

def extract_threat_actors(report_text):
    # Adjusted pattern to capture both "APT" followed by two digits or "APT-C-" followed by two digits
    threat_actor_pattern = r'\b(APT-C?-\d{2}|\bAPT\d{2})\b'
    threat_actors = re.findall(threat_actor_pattern, report_text)
    
    # Remove duplicates by converting to a set and then back to a list
    unique_threat_actors = list(set(threat_actors))
    
    return unique_threat_actors


def extract_hashes_from_pdf(pdf_path):
    # Regular expressions for MD5 and SHA256 hash patterns
    md5_pattern = r'\b[a-fA-F0-9]{32}\b'
    sha256_pattern = r'\b[a-fA-F0-9]{64}\b'

    md5_hashes = set()
    sha256_hashes = set()

    try:
        # Read the PDF file
        reader = PdfReader(pdf_path)
        for page in reader.pages:
            # Extract text from each page
            text = page.extract_text()
            if text:
                # Find all MD5 and SHA256 hashes in the text
                md5_hashes.update(re.findall(md5_pattern, text))
                sha256_hashes.update(re.findall(sha256_pattern, text))

    except Exception as e:
        print(f"Error reading PDF: {e}")
        return None, None

    return md5_hashes, sha256_hashes


def get_virus_details(api_key, file_hash):
    """
    Fetches virus details from VirusTotal using a hash.
    
    Args:
        api_key (str): Your VirusTotal API key.
        file_hash (str): The hash of the file to query (MD5, SHA-1, or SHA-256).
    
    Returns:
        dict: The response from VirusTotal, containing details about the file.
    """
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": api_key
    }
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        return {"error": "File hash not found in VirusTotal database."}
    else:
        return {"error": f"Unexpected error: {response.status_code}, {response.text}"}

def extract_malware(pdfPath, api_key):
    
    md5_hashes, sha256_hashes = extract_hashes_from_pdf(pdfPath)

    result = []
    allHash = {}

    if md5_hashes or sha256_hashes:
        for md5 in md5_hashes:
            # md5 = "fdbb72a18e8e6e029482ee72d900f24a" # (shamoon)
            virus_details = get_virus_details(api_key, md5)
            if "error" not in virus_details:
                virusData = virus_details.get('data', {}).get('attributes', {})
                if virusData:
                    sha256_hash_data = virusData.get(("sha256"), "")
                    malware_name = virusData.get(("meaningful_name"), "")
                    tlsh = virusData.get(("tlsh"), "")
                    ssdeep = virusData.get(("ssdeep"), "")
                    sha1_hash_data = virusData.get(("sha1"), "")
                    md5_hash_data = virusData.get(("md5"), "")
                    tags = virusData.get(("tags"), "")

                    if sha256_hash_data not in allHash:
                        malware_json = [
                            {"Name": malware_name},
                            {"md5": md5_hash_data},
                            {"sha1": sha1_hash_data},
                            {"sha256": sha256_hash_data},
                            {"ssdeep": ssdeep},
                            {"TLSH": tlsh},
                            {"tags": tags},
                        ]
                        result.append(malware_json)
                        allHash[sha256_hash_data] = True

        for sha256 in sha256_hashes:
            if sha256 not in allHash:
                virus_details = get_virus_details(api_key, sha256)
                if "error" not in virus_details:
                    virusData = virus_details.get('data', {}).get('attributes', {})
                    if virusData:
                        sha256_hash_data = virusData.get(("sha256"), "")
                        malware_name = virusData.get(("meaningful_name"), "")
                        tlsh = virusData.get(("tlsh"), "")
                        ssdeep = virusData.get(("ssdeep"), "")
                        sha1_hash_data = virusData.get(("sha1"), "")
                        md5_hash_data = virusData.get(("md5"), "")
                        tags = virusData.get(("tags"), "")

                    
                        malware_json = [
                            {"Name": malware_name},
                            {"md5": md5_hash_data},
                            {"sha1": sha1_hash_data},
                            {"sha256": sha256_hash_data},
                            {"ssdeep": ssdeep},
                            {"TLSH": tlsh},
                            {"tags": tags},
                        ]
                        result.append(malware_json)
                        allHash[sha256_hash_data] = True
    return result

def extract_targeted_entities(report_text):
    # Process the report text using spaCy NLP model
    doc = nlp(report_text)

    # List to hold the targeted entities
    targeted_entities = []

    # Define the relevant keywords for matching
    sector_keywords = ['sector', 'industries', 'organizations', 'Affairs', 'Ministry']

    # Iterate over the sentences or just use simple pattern matching
    for sent in doc.sents:
        # For each sentence, look for relevant sector-related phrases
        for keyword in sector_keywords:
            if keyword in sent.text.lower():
                # Check for the preceding words that may indicate the sector or industry
                # Extract the word preceding the keyword (simple approach)
                words = sent.text.split()
                for i, word in enumerate(words):
                    if keyword in word.lower():
                        # We capture the word(s) that are related to sectors/industries
                        if i > 0:
                            sector_entity = words[i-1] + ' ' + word  # Capture the entity like 'energy sector'
                            targeted_entities.append(sector_entity.capitalize())

    # Return the targeted entities in the desired format
    return {'Targeted Entities': list(set(targeted_entities))}  # Remove duplicates

def extract_threat_intelligence(report_text, api_key, pdf_path):
    iocs = extract_iocs(report_text)
    ttps = extract_ttps(report_text)
    threat_actors = extract_threat_actors(report_text)
    malware = extract_malware(pdf_path, api_key)
    targeted_entities = extract_targeted_entities(report_text)

    outputData = {
        "IoCs": iocs,
        "TTPs": ttps,
        "Threat Actor(s)": threat_actors,
        "Malware": malware,
        "Targeted Entities": targeted_entities
    }

    # return {**iocs, **ttps, **threat_actors, **malware, **targeted_entities}
    return outputData

def main(api_key, pdf_path, output_filename='output.json', output_txt_filename='report_text.txt'):

    # Example report text
    report_text = generate_report(pdf_path)
    # '''
    # The BlindEagle Targeting Ecuador, APT-C-36, CPR, the Ministry of Foreign Affairs, PDF, the Colombian Ministry of Foreign Affairs, MediaFire, PDF, LHA, APT, Banca Empresas, Empresarial Banco de Bogota, AV Villas, Banco Popular, Quasar, Quasar, the Ecuadorian Internal Revenue Service, RAR, RAR, PyInstaller, Microsoft HTML Applications, HTML, Powershell, Powershell, Powershell, AV, WebClient, Remove-Item, PATH, Python Software Foundation, Set-ItemProperty, System, Google, DLL, DLL, APT, office 365 & G, Artificial Intelligence (AI, the Harmony Email & Office, https://gtly[.]to/dGBeBqd8z group, suspected to be from Ecuador, Colombia, Colombia, Github, Colpatria, Ecuador, Colombia, Ecuador, Ecuador, Colombia, Colombia, Ecuador, Powershell, Python, Python, Ecuador, has launched a new campaign targeting the Colombian, Spanish organizations. The attack utilizes a, to, that, the, the, the, of, known for its destructive capabilities. The threat actor exploited a vulnerability in the network perimeter to gain initial access. The malware was delivered using spear-phishing, lateral movement, credential dumping. The malware's behavior was observed communicating with IP address unknown IP and domain research.checkpoint.com, bancaempresas.bancocajasocial.com, conexionenlinea.bancodebogota.com, ctypes.windll, ctypes.windll, os.system, powershell.exe, net.webclient, self.close, linkpc.net, net.webclient, net.webclient, net.webclient, net.webclient, www.python.org, python-3.9.9-embed-win32.zip, py.zip, FILE.attributes, py.zip, zip.items, py.zip, python.exe, python.exe, python.exe, python.exe, mp.py, ByAV2.py, ByAV2.py, systemwin.linkpc, 8mp.py, www.mediafire. The following hashes were also associated with the malware: 2702ea04dcbbbc3341eeffb494b692e15a50fbd264b1d676b56242aae3dd9001, f80eb2fcefb648f5449c618e83c4261f977b18b979aacac2b318a47e99c19f64, 68af317ffde8639edf2562481912161cf398f0edba6e06745d90c1359554c76e, 61685ea4dc4ca4d01e0513d5e23ee04fc9758d6b189325b34d5b16da254cc9f4, c63d15fe69a76186e4049960337d8c04c6230e4c2d3d3164d3531674f5f74cdf, 353406209dea860decac0363d590096e2a8717dd37d6b4d8b0272b02ad82472e, a03259900d4b095d7494944c50d24115c99c54f3c930bea08a43a8f0a1da5a2e, 46addee80c4c882b8a6903cced9b6c0130ec327ae8a59c5946bb954ccea64a12, c067869ac346d007a17e2e91c1e04ca0f980e8e9c4fd5c7baa0cb0cc2398fe59, 10fd1b81c5774c1cc6c00cc06b3ed181b2d78191c58b8e9b54fa302e4990b13d, c4ff3fb6a02ca0e51464b1ba161c0a7387b405c78ead528a645d08ad3e696b12, ac1ea54f35fe9107af1aef370e4de4dc504c8523ddaae10d95beae5a3bf67716. The attack was attributed to the following threat actor(s): APT-C-36. The targeted entities include Bancolombia Sucursal Virtual Personas.
    # '''

    # Save the report_text into a text file
    with open(output_txt_filename, 'w', encoding='utf-8') as txt_file:
        txt_file.write(report_text)

    print(f"Report text has been saved to {output_txt_filename}")

    
    # Execute the extraction function with the VirusTotal API key
    extracted_data = extract_threat_intelligence(report_text, api_key, pdf_path)
    # print(extracted_data)

    # Open the file in write mode and dump the data
    with open(output_filename, 'w') as json_file:
        json.dump(extracted_data, json_file, indent=4)

    print(f"Data has been saved to {output_filename}")

if __name__ == "__main__":
    
    api_key = 'af26b8c4a4662087b1e796a2c5de5528d82cbdf553d022992e7f4e9b5b4d72d4'
    pdf_path = "C3i_HACKATHON_FINAL_ROUND_Q1_DATA/Checkpoint_Chinese-Espionage-Southeast-Asian-Government-Entities(03-07-2023).pdf"  # Replace with your actual PDF file path

    main(api_key, pdf_path)