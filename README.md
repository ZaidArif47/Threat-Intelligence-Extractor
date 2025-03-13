# Threat Intelligence Extraction Project
This script takes in cyber attack data from PDF reports and intelligently extracts critical threat information—such as Indicators of Compromise (IoCs), Tactics, Techniques, and Procedures (TTPs)—by leveraging a mix of powerful APIs, regular expressions, and natural language processing. It's designed to transform raw data into actionable insights for more effective threat detection and response. It boosts the blue cybersecurity team's efficiency and productivity by automating the analysis process, saving valuable time and allowing them to focus on more strategic tasks.

## Installation Instructions

To set up this project locally:

1. Clone this repository:
   ```bash
   git clone https://github.com/ZaidArif47/Threat-Intelligence-Extractor.git
   cd Threat-Intelligence-Extractor
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate # On Windows use `venv\Scripts\activate`
   ```

3. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Download necessary spaCy model:
   ```bash
   python -m spacy download en_core_web_sm
   ```

## Usage

To run the extraction process:

1. Ensure you have your PDF file ready.
2. Update `main.py` with your VirusTotal API key and PDF file path.
3. Execute the script:
   ```bash
   python main.py
   ```

The report_text summary will be saved in `report_text.txt`
The output will be saved in `output.json`.
---

#### **Main Script: `main.py`**
#### **Supporting Script: `pdf_summary_extractor.py`**
