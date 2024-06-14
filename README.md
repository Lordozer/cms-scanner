# CMS-Scanner

## Overview
This Python-based CMS scanner detects common Content Management Systems (CMS) like 'joomla', 'wordpress', 'silverstripe', 'drupal', 'typo3', 'aem', 'vbscan', 'moodle', 'oscommerce', 'coldfusion', 'jboss', 'oracle_e_business', 'phpbb', 'php_nuke', 'dotnetnuke', 'umbraco' and 'prestashop'. It utilizes external tools such as JoomScan, WPScan, and DroopScan..etc to perform passive detection of vulnerabilities and versions. The scanner can generate scan reports and search for Common Vulnerabilities and Exposures (CVEs) related to detected CMS versions.

## Features

- Detects CMS types: Joomla, WordPress, SilverStripe, and Drupal
- Scans CMS for common vulnerabilities
- Searches for known CVEs using the NVD API
- Generates detailed reports in PDF, HTML, or plain text formats

## Requirements

- Python 3.x
- Requests library (`pip install requests`)
- ReportLab library (`pip install reportlab`)
- Jinja2 library (`pip install jinja2`)
- JoomScan
- WPScan
- Droopescan


## Installation guide
1. Clone the repository: `git clone https://github.com/lordozer/cms-scanner.git`
2. Navigate to the project directory: `cd cms-scanner`
3. Install dependencies: `pip install -r requirements.txt`
4. clone droopescan in the cms-scanner directory and follow droopescan installation guide. `git clone https://github.com/droope/droopescan.git`
5. clone droopescan in the cms-scanner directory and follow typo3scan installation guide. `git clone https://github.com/whoot/Typo3Scan`
6. clone droopescan in the cms-scanner directory and follow aemscan installation guide. `git clone https://github.com/Raz0r/aemscan`
7. clone droopescan in the cms-scanner directory and follow vbscan installation guide. `git clone https://github.com/OWASP/vbscan`
8. upload the cpe dictionnary official-cpe-dictionary_v2.3.xml.zip and extract it in the cms-scanner directory link: 'https://nvd.nist.gov/products/cpe'
9. sudo apt update && sudo apt install nmap joomscan wpscan -y

## Usage

python main.py -u <URL> [-v] [-o <output_format>]

## Arguments
-u, --url (required): The URL of the site to scan.

-v, --verbose: Enable verbose mode to see detailed output in the terminal.

-o, --output: The output format for the report. Choices are pdf, html, text. Default is text.

-h : help.

## Example
python main.py -u http://example.com -v -o pdf

This command scans the specified URL, enables verbose mode, and generates a PDF report.

## Output
The tool generates a report based on the specified output format:

PDF Report: scan_output.pdf
HTML Report: scan_output.html
Text Report: scan_output.txt

## Dependencies

Python Libraries:

requests
reportlab
jinja2

External Tools:

JoomScan
WPScan
Droopescan

## Contributing
Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or create a pull request.

##disclaimer
url format : https://example.com/
python 3.8<
JMO.
