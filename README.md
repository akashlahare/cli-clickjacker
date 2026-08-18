# CLI Based Clickjacking Scanner
Simple CLI tool to detect Clickjacking vulnerabilities and generate an HTML report.

## Install:
python3 -m pip install --upgrade pip
python3 -m pip install httpx pandas openpyxl

## Usage:
### Single URL:
python3 cliclickjacker.py -u example.com

### Bulk Scan:
python3 cliclickjacker.py -f urls.txt

### Save Report:
python3 cliclickjacker.py -f urls.txt -o report.html

## Supported Files:
* .txt          → One URL per line
* .csv / .xlsx  → First column = URLs
