import os
import argparse
import logging
from logging_config import setup_logging
from cms_detector import detect_cms
import re
import requests
import subprocess
import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph
from jinja2 import Environment, FileSystemLoader

setup_logging()

API_KEY = "0c05f603-2691-45f1-b782-1193e53a07c1"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def parse_arguments():
    parser = argparse.ArgumentParser(description='CMS Vulnerability Scanner')
    parser.add_argument('-u', '--url', required=True, help='The URL of the site to scan')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose mode')
    parser.add_argument('-o', '--output', choices=['pdf', 'html', 'text'], default='text', help='Output format')
    return parser.parse_args()

def run_joomscan(url, verbose=False, output_file=None):
    print("Launching Joomla scanner...")
    scan_output_file = output_file or 'joomscan_output.txt'
    try:
        result = subprocess.Popen(['joomscan', '-u', url], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        with open(scan_output_file, 'w') as file:
            for line in result.stdout:
                file.write(line)
                if verbose:
                    print(line, end='', flush=True)
        result.wait()
        with open(scan_output_file, 'r') as file:
            scan_results = file.read()
        return scan_results
    except Exception as e:
        logging.error(f"Error running JoomScan: {e}")
        return None

def run_wpscan(url, verbose=False, output_file=None):
    print("Launching WordPress scanner...")
    scan_output_file = output_file or 'wpscan_output.txt'
    try:
        result = subprocess.Popen(['wpscan', '--url', url, '--detection-mode', 'passive'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        with open(scan_output_file, 'w') as file:
            for line in result.stdout:
                file.write(line)
                if verbose:
                    print(line, end='', flush=True)
        result.wait()
        with open(scan_output_file, 'r') as file:
            scan_results = file.read()
        return scan_results
    except Exception as e:
        logging.error(f"Error running WPScan: {e}")
        return None

def run_droopescan(url, cms_type, verbose=False):
    print("Launching Droopescan...")
    original_directory = os.getcwd()
    os.chdir('droopescan')
    scan_output_file = 'droopescan_output.txt'
    try:
        result = subprocess.Popen(['./droopescan', 'scan', cms_type, '-u', url], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        with open(scan_output_file, 'w') as file:
            for line in result.stdout:
                file.write(line)
                if verbose:
                    print(line, end='', flush=True)
        result.wait()
        with open(scan_output_file, 'r') as file:
            scan_results = file.read()
        return scan_results
    except Exception as e:
        logging.error(f"Error running DroopeScan: {e}")
        return None
    finally:
        os.chdir(original_directory)

def get_versions_from_scan_results(scan_results):
    versions = re.findall(r'(\d+\.\d+\.\d+)', scan_results)
    return versions

def search_cves_for_versions(versions, cpe_name_base):
    print("Searching for CVEs...")
    headers = {"apiKey": API_KEY}
    cves_found = []
    for version in versions:
        cpe_name = f"{cpe_name_base}:{version}"
        search_url = f"{NVD_API_URL}?cpeName={cpe_name}&resultsPerPage=20"
        try:
            response = requests.get(search_url, headers=headers)
            if response.status_code == 200:
                cves = response.json().get('vulnerabilities', [])
                if cves:
                    logging.info(f"Found CVEs for version {version}: {', '.join(cve['cve']['id'] for cve in cves)}")
                    cves_found.extend(cve['cve']['id'] for cve in cves)
                else:
                    logging.info(f"No CVEs found for version {version}")
            else:
                logging.error(f"Failed to retrieve CVEs for version {version}")
        except requests.RequestException as e:
            logging.error(f"Failed to retrieve CVEs for version {version}: {e}")
    return cves_found

def generate_pdf(formatted_results, url, cms, cves):
    pdf_file_path = 'scan_output.pdf'
    doc = SimpleDocTemplate(pdf_file_path, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph(f"Scan Results for {url} ({cms.capitalize()}):", styles['Title']))
    elements.append(Paragraph(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    
    for line in formatted_results.split('\n'):
        elements.append(Paragraph(line, styles['Normal']))
    
    if cves:
        elements.append(Paragraph("\nCVEs Found:", styles['Title']))
        for cve in cves:
            elements.append(Paragraph(cve, styles['Normal']))
    else:
        elements.append(Paragraph("\nNo CVEs Found", styles['Normal']))

    doc.build(elements)
    print(f"PDF report generated: {pdf_file_path}")
    logging.info(f"PDF report generated: {pdf_file_path}")

def generate_html(formatted_results, url, cms, cves):
    env = Environment(loader=FileSystemLoader('.'))
    template = env.get_template('report_template.html')
    html_content = template.render(url=url, cms=cms, date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'), results=formatted_results, cves=cves)
    html_file_path = 'scan_output.html'
    with open(html_file_path, 'w') as f:
        f.write(html_content)
    print(f"HTML report generated: {html_file_path}")
    logging.info(f"HTML report generated: {html_file_path}")

def run_scan(url, cms, verbose, scan_output_file):
    if cms == 'joomla':
        return run_joomscan(url, verbose, scan_output_file)
    elif cms == 'wordpress':
        return run_wpscan(url, verbose, scan_output_file)
    elif cms in ['silverstripe', 'drupal']:
        return run_droopescan(url, cms, verbose)
    else:
        logging.error(f"Unsupported CMS: {cms}")
        return None

def print_banner():
    banner = """
    __  ___ ___  _____        _____   __   ____  ____   ____     ___  ____  
   /  ]|   |   |/ ___/       / ___/  /  ] /    ||    \ |    \   /  _]|    \ 
  /  / | _   _ (   \_  _____(   \_  /  / |  o  ||  _  ||  _  | /  [_ |  D  )
 /  /  |  \_/  |\__  ||     |\__  |/  /  |     ||  |  ||  |  ||    _]|    / 
/   \_ |   |   |/  \ ||_____|/  \ /   \_ |  _  ||  |  ||  |  ||   [_ |    \ 
\     ||   |   |\    |       \    \     ||  |  ||  |  ||  |  ||     ||  .  \\
 \____||___|___| \___|        \___|\____||__|__||__|__||__|__||_____||__|\_|
 
  CMS Scanner: Detects and scans Joomla, WordPress, SilverStripe, and Drupal.


                                    BY JMO






















    """
    print(banner)
    logging.info("Printed banner.")

def main():
    args = parse_arguments()
    
    print_banner()
    url = args.url
    verbose = args.verbose
    output_format = args.output

    cms = detect_cms(url)
    if not cms:
        print("Unknown CMS or unable to detect CMS.")
        return
    logging.info(f"{cms.capitalize()} detected at {url}")
    print(f"{cms.capitalize()} detected.")
    
    if verbose:
        logging.info("Verbose mode activated.")
        print("Verbose mode activated.")

    scan_output_file = 'scan_output.txt'
    formatted_results = run_scan(url, cms, verbose, scan_output_file)

    if formatted_results:
        print("Scan completed successfully.")
        logging.info("Scan completed successfully.")
    else:
        print("Scan failed.")
        logging.error("Scan failed.")
        return

    versions = get_versions_from_scan_results(formatted_results)
    if versions:
        cpe_name_base = f"cpe:2.3:a:{cms}"  # Adjust this according to your CMS type
        cves_found = search_cves_for_versions(versions, cpe_name_base)
        if cves_found:
            cves_output = "\nCVEs Found:\n" + "\n".join(cves_found)
        else:
            cves_output = "\nNo CVEs Found"
    else:
        cves_found = []
        cves_output = "\nNo version information found."

    if output_format == 'pdf':
        generate_pdf(formatted_results + cves_output, url, cms, cves_found)
    elif output_format == 'html':
        generate_html(formatted_results + cves_output, url, cms, cves_found)
    else:
        with open('scan_output.txt', 'w') as f:
            f.write(formatted_results + cves_output)
        print("Scan Results:")
        print(formatted_results)
        print(cves_output)

if __name__ == '__main__':
    main()
