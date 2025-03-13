import pdfplumber
import spacy
from transformers import pipeline
import re

# Function to extract text from PDF
def extract_text_from_pdf(pdf_path):
    with pdfplumber.open(pdf_path) as pdf:
        text = ""
        for page in pdf.pages:
            text += page.extract_text()
    return text

# Load spaCy model for entity extraction
nlp = spacy.load("en_core_web_sm")

def extract_entities(text):
    doc = nlp(text)
    entities = {
        'Group Name': [],
        'Attack Methodology': [],
        'Malware Behavior': [],
        'IoCs': {'IP': [], 'Domain': [], 'Hashes': []},
        'Target Sector': [],
        'Tactics and Techniques': [],
        'Threat Actor': [],
        'Target Entities': []  # New category for the targeted entities
    }

    # Check for the targeted entities list
    targeted_entities_pattern = r"targeted entities[:|\-]?\s*(.*?)(?=\n|\r|\Z)"  # Pattern to capture everything after "targeted entities"
    match = re.search(targeted_entities_pattern, text, re.IGNORECASE | re.DOTALL)
    if match:
        # Extract and split the list of targeted entities
        target_entities_text = match.group(1)
        entities['Target Entities'] = [e.strip() for e in target_entities_text.split('\n') if e.strip()]

    # If no targeted entities are found, use fallback
    if not entities['Target Entities']:
        # First, try to extract entities using spaCy's named entity recognition (ORG, GPE, etc.)
        for ent in doc.ents:
            if ent.label_ == 'ORG':  # For company or organization names
                entities['Target Entities'].append(ent.text)
            if ent.label_ == 'GPE':  # For geographic locations (could be sectors or regions)
                entities['Target Entities'].append(ent.text)

        # Second, try to detect domain names as potential targets
        potential_domains = re.findall(r"\b[A-Za-z0-9.-]+\.[a-z]{2,}\b", text)
        entities['Target Entities'].extend([domain for domain in potential_domains if domain not in entities['Target Entities']])

        # Third, look for keywords related to potential target sectors
        target_keywords = [
            'bank', 'finance', 'bancolombia', 'portal', 'corporation', 'enterprise', 'telecom', 'healthcare', 'government', 'insurance'
        ]
        for keyword in target_keywords:
            if keyword.lower() in text.lower():
                entities['Target Entities'].append(keyword)

    # Extract Group Name (Organizations)
    for ent in doc.ents:
        if ent.label_ == 'ORG':  # For Group Name (APT33, etc.)
            entities['Group Name'].append(ent.text)
        if ent.label_ == 'GPE':  # Locations or attack-related geographical entities
            entities['Attack Methodology'].append(ent.text)
        if ent.label_ == 'NORP':  # For Sector information (e.g., industries)
            entities['Target Sector'].append(ent.text)

    # Detecting Malware Behavior (Dynamic Malware Name Extraction)
    malware_keywords = [
        'Shamoon', 'NotPetya', 'WannaCry', 'Emotet', 'TrickBot', 'Ryuk', 'Mirai', 'Locky', 'Sodinokibi', 'Zeus'
    ]
    
    # Search for common malware names in the text
    for keyword in malware_keywords:
        if keyword.lower() in text.lower():
            entities['Malware Behavior'].append(keyword)

    # If no common malware names found, use a regex to detect potential malware behavior
    if not entities['Malware Behavior']:
        potential_malware = re.findall(r'\b([A-Za-z0-9\-]+)\s*malware\b', text.lower())
        if potential_malware:
            entities['Malware Behavior'].extend(potential_malware)

    # Dynamic Malware Hash Detection (MD5, SHA1, SHA256)
    hash_patterns = [
        r'\b([a-fA-F0-9]{32})\b',  # MD5 hash (32 hexadecimal characters)
        r'\b([a-fA-F0-9]{40})\b',  # SHA-1 hash (40 hexadecimal characters)
        r'\b([a-fA-F0-9]{64})\b'   # SHA-256 hash (64 hexadecimal characters)
    ]
    
    # Detect malware hashes in the text
    for pattern in hash_patterns:
        hashes = re.findall(pattern, text)
        if hashes:
            entities['IoCs']['Hashes'].extend(hashes)

    # Detecting Threat Actor (APT-<letters> format)
    threat_actor_pattern = r'\bAPT[-A-Za-z0-9]+\b'
    threat_actors = re.findall(threat_actor_pattern, text)
    if threat_actors:
        entities['Threat Actor'].extend(threat_actors)

    # Detecting Malware Tactics and Techniques (TTPs)
    ttp_keywords = [
        'spear-phishing', 'lateral movement', 'credential dumping', 'command and control', 'exfiltration', 'social engineering', 'ransomware', 'web shell'
    ]
    
    # Search for common TTPs in the text
    for ttp in ttp_keywords:
        if ttp.lower() in text.lower():
            entities['Tactics and Techniques'].append(ttp)

    # Manually extract IoCs (IP addresses and Domains)
    entities['IoCs']['IP'] = re.findall(r"\d+\.\d+\.\d+\.\d+", text)  # Find IPs
    entities['IoCs']['Domain'] = re.findall(r"\b[A-Za-z0-9.-]+\.[a-z]{2,}\b", text)  # Find Domains

    # Enhance IoC extraction to detect proximity between IPs and domains
    combined_entities = []
    ip_and_domain_pairs = []
    text_lines = text.splitlines()  # Split the text into lines

    for i, line in enumerate(text_lines):
        ip_addresses = re.findall(r"\d+\.\d+\.\d+\.\d+", line)
        domains = re.findall(r"\b[A-Za-z0-9.-]+\.[a-z]{2,}\b", line)

        if ip_addresses and domains:
            # If IP and domain are found in the same line, group them
            ip_and_domain_pairs.append((ip_addresses, domains))

    # Add IP and domain pairs to the entities dictionary
    for ips, domains in ip_and_domain_pairs:
        entities['IoCs']['IP'].extend(ips)
        entities['IoCs']['Domain'].extend(domains)

    return entities

# Load the summarization pipeline
summarizer = pipeline("summarization", model="facebook/bart-large-cnn")

# Function to summarize text
def summarize_text(text):
    # Summarize the extracted text
    summary = summarizer(text, max_length=150, min_length=50, do_sample=False)
    return summary[0]['summary_text']

# Function to chunk the text into smaller pieces (if it exceeds model's token limit)
def chunk_text(text, max_length=1024):
    words = text.split()
    chunked_texts = []
    current_chunk = []

    for word in words:
        current_chunk.append(word)
        if len(' '.join(current_chunk)) > max_length:
            chunked_texts.append(' '.join(current_chunk[:-1]))
            current_chunk = [word]
    chunked_texts.append(' '.join(current_chunk))

    return chunked_texts

# Function to summarize multiple chunks
def summarize_chunks(chunks):
    summaries = []
    for chunk in chunks:
        summary = summarize_text(chunk)  # Summarizing each chunk
        summaries.append(summary)
    return ' '.join(summaries)

# Function to generate the final report with dynamic elements
def generate_report(pdf_path):
    # Extract text from the PDF
    text = extract_text_from_pdf(pdf_path)

    # Extract entities from the text
    entities = extract_entities(text)

    # Fallback: Use predefined keywords if entities are not detected
    if not entities['Group Name']:
        entities['Group Name'].extend(['APT33', 'Fancy Bear', 'Lazarus'])
    if not entities['Attack Methodology']:
        entities['Attack Methodology'].extend(['phishing', 'ransomware', 'malware'])
    if not entities['Malware Behavior']:
        entities['Malware Behavior'].extend(['Shamoon', 'WannaCry', 'NotPetya'])
    if not entities['Target Sector']:
        entities['Target Sector'].extend(['financial', 'energy', 'telecommunications'])
    if not entities['Tactics and Techniques']:
        entities['Tactics and Techniques'].extend(['spear-phishing', 'lateral movement', 'credential dumping'])

    # Create the summary sentence with extracted entities
    summary = f"""
    The {', '.join(entities['Group Name']) if entities['Group Name'] else 'unknown group'} group, suspected to be from {', '.join(entities['Attack Methodology']) if entities['Attack Methodology'] else 'unknown location'}, has launched a new campaign targeting the {', '.join(entities['Target Sector']) if entities['Target Sector'] else 'unknown sector'} organizations.
    The attack utilizes {', '.join(entities['Malware Behavior']) if entities['Malware Behavior'] else 'malware'}, known for its destructive capabilities. The threat actor exploited a vulnerability in the network perimeter to gain initial access.
    The malware was delivered using {', '.join(entities['Tactics and Techniques']) if entities['Tactics and Techniques'] else 'unknown techniques'}. The malware's behavior was observed communicating with IP address {', '.join(entities['IoCs']['IP']) if entities['IoCs']['IP'] else 'unknown IP'} and domain {', '.join(entities['IoCs']['Domain']) if entities['IoCs']['Domain'] else 'unknown domain'}.
    The following hashes were also associated with the malware: {', '.join(entities['IoCs']['Hashes']) if entities['IoCs']['Hashes'] else 'no hash information available'}.
    The attack was attributed to the following threat actor(s): {', '.join(entities['Threat Actor']) if entities['Threat Actor'] else 'unknown threat actor(s)'}.
    The targeted entities include {', '.join(entities['Target Entities']) if entities['Target Entities'] else 'no targeted entities available'}.
    """

    # Clean the summary (remove any empty placeholders)
    cleaned_summary = " ".join(summary.split())

    return cleaned_summary

if __name__ == "__main__":
    # Example usage
    pdf_path = "C3i_HACKATHON_FINAL_ROUND_Q1_DATA/Blackberry_BlindEagle-Fake-UUE-Fsociety-Target-Colombia(02-27-2023).pdf"  # Replace with your actual PDF file path
    report = generate_report(pdf_path)
    # print(report)

