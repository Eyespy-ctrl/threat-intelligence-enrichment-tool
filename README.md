# Threat Intelligence Enrichment Platform

A Python-based Threat Intelligence Enrichment Tool built with Flask that aggregates and correlates intelligence from multiple threat intelligence providers to assist security analysts in investigating IP indicators.

The platform queries multiple security intelligence services and consolidates the results into a single investigation dashboard.

---

## Overview

Threat intelligence enrichment is a critical process in Security Operations Centers (SOCs). Analysts frequently investigate IP addresses, domains, and other indicators of compromise (IOCs). This tool automates the enrichment process by querying multiple threat intelligence sources simultaneously.

This project demonstrates how analysts can build lightweight enrichment platforms similar to those used in professional security environments.

---

## Features

* Multi-source threat intelligence enrichment
* Automated IP,Domain and URL investigation
* Aggregation of multiple threat intelligence APIs
* Structured intelligence storage using SQLite
* Web-based investigation dashboard
* Export results to CSV
* Modular architecture for adding additional intelligence providers

---

## Integrated Threat Intelligence Sources

This platform integrates intelligence from the following providers:

* VirusTotal
* AbuseIPDB
* Shodan
* AlienVault OTX

Each provider contributes additional context such as:

* reputation scores
* open ports
* malware detections
* abuse reports
* threat pulses
* Geo Location
---

## Project Structure

```
ti-tool/
│
├── app.py
├── enrich.py
├── database.py
├── requirements.txt
│
├── modules/
│   ├── virustotal_lookup.py
│   ├── abuseipdb_lookup.py
│   ├── shodan_lookup.py
│   └── alienvault.py
│
├── templates/
│
└── instance/
```

---

## Installation

Clone the repository:

```
git clone https://github.com/YOUR_USERNAME/threat-intelligence-enrichment-tool.git
cd threat-intelligence-enrichment-tool
```

Create a virtual environment:

```
python3 -m venv venv
source venv/bin/activate
```

Install dependencies:

```
pip install -r requirements.txt
```

---

## Environment Variables

Create a `.env` file and add your API keys:

```
VIRUSTOTAL_API_KEY=your_key
ABUSEIPDB_API_KEY=your_key
SHODAN_API_KEY=your_key
ALIENVAULT_API_KEY=your_key
```

---

## Running the Application

Start the Flask application:

```
python app.py
```

Open the web interface:

```
http://127.0.0.1:5000
```

Enter an IP address to perform a threat intelligence enrichment lookup.

---

## Example Use Case

Security analysts can use this tool to:

1. Investigate suspicious IP addresses,URL's and Domains
2. Correlate intelligence from multiple providers
3. Identify malicious infrastructure
4. Export investigation results

---

## Future Improvements

Possible enhancements include:

* Additional enrichment types such as file hashes and email indicators
* Advanced threat scoring and risk prioritization
* Interactive data visualization and investigation dashboards
* Integration with additional intelligence providers
* Automated IOC ingestion

---

## Educational Purpose

This project was created for educational and portfolio purposes to demonstrate:

* API integration
* Threat intelligence enrichment workflows
* Security tool development in Python
* Flask-based security dashboards

---

## License

This project is released under the MIT License.
