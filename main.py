import os
import argparse
import logging
from logging_config import setup_logging
from cms_detector import detect_cms
from config_loader import load_config
from scanner_utils import analyze_scan_results
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph
from config_loader import load_cpe_dictionary
from jinja2 import Environment, FileSystemLoader
import subprocess
import re
from scanner_utils import extract_cves
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

def search_cves_for_services(scan_results):
    analyzed_results = analyze_scan_results(scan_results)
    all_cves = set()
    for service, details in analyzed_results.items():
        if details['cves']:
            all_cves.update(details['cves'])
    
    if all_cves:
        print("CVEs found:")
        for cve in sorted(all_cves):  # Sort for consistent output
            print(cve)
    else:
        print("No CVEs found.")
    return analyzed_results

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

    analyzed_results = search_cves_for_services(formatted_results)
    
    all_cves = set()
    for service, details in analyzed_results.items():
        if details['cves']:
            all_cves.update(details['cves'])

    if all_cves:
        print("CVEs found:")
        for cve in sorted(all_cves):  # Sort for consistent output
            print(cve)
    else:
        print("No CVEs found.")

    if output_format == 'pdf':
        generate_pdf(formatted_results, url, cms, list(all_cves))
    elif output_format == 'html':
        generate_html(formatted_results, url, cms, list(all_cves))
    else:
        with open('scan_output.txt', 'w') as f:
            f.write(formatted_results)
        print("Scan Results:")
        print(formatted_results)

if __name__ == '__main__':
    main()
