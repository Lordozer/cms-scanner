import os
import requests
import subprocess
import re
import json
import logging
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph
from datetime import datetime
from logging_config import setup_logging

setup_logging()

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

def load_config():
    with open('config.json', 'r') as config_file:
        return json.load(config_file)

config = load_config()

def detect_cms(url):
    try:
        if check_joomla(url):
            return 'joomla'
        elif check_wordpress(url):
            return 'wordpress'
        elif check_silverstripe(url):
            return 'silverstripe'
        elif check_drupal(url):
            return 'drupal'
        else:
            return None
    except Exception as e:
        logging.error(f"Error detecting CMS: {e}")
        return None

def check_joomla(url):
    try:
        response = requests.get(url)
        if response.status_code != 200:
            return False
        joomla_indicators = ['content="Joomla!', 'Joomla', 'index.php?option=com_', '/media/system/js/']
        if any(indicator in response.text for indicator in joomla_indicators):
            return True
        common_files = config['joomla']['common_files']
        for file in common_files:
            check_url = url.rstrip('/') + '/' + file
            file_response = requests.head(check_url)
            if file_response.status_code == 200:
                return True
    except requests.RequestException as e:
        logging.error(f"Error checking Joomla for {url}: {e}")
    return False

def check_wordpress(url):
    try:
        response = requests.get(url)
        if response.status_code != 200:
            return False
        wordpress_indicators = ['wp-content', 'WordPress', 'wp-includes', '?ver=', 'wp-json']
        if any(indicator in response.text for indicator in wordpress_indicators):
            return True
        common_files = config['wordpress']['common_files']
        for file in common_files:
            check_url = url.rstrip('/') + '/' + file
            file_response = requests.head(check_url)
            if file_response.status_code == 200:
                return True
    except requests.RequestException as e:
        logging.error(f"Error checking WordPress for {url}: {e}")
    return False

def check_silverstripe(url):
    try:
        response = requests.get(url)
        if response.status_code != 200:
            return False
        if 'SilverStripe' in response.text or 'SilverStripe' in response.headers.get('X-Powered-By', ''):
            return True
        common_files = config['silverstripe']['common_files']
        for file in common_files:
            check_url = url.rstrip('/') + '/' + file
            file_response = requests.head(check_url)
            if file_response.status_code == 200:
                return True
    except requests.RequestException as e:
        logging.error(f"Error checking SilverStripe for {url}: {e}")
    return False

def check_drupal(url):
    try:
        response = requests.get(url)
        if response.status_code != 200:
            return False
        if 'Drupal' in response.text or 'Drupal' in response.headers.get('X-Generator', ''):
            return True
        common_files = config['drupal']['common_files']
        for file in common_files:
            check_url = url.rstrip('/') + '/' + file
            file_response = requests.head(check_url)
            if file_response.status_code == 200:
                return True
    except requests.RequestException as e:
        logging.error(f"Error checking Drupal for {url}: {e}")
    return False

def run_joomscan(url, verbose=False, output_file=None):
    scan_output_file = output_file or 'joomscan_output.txt'
    try:
        result = subprocess.Popen(['joomscan', '-u', url], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        with open(scan_output_file, 'w') as file:
            for line in result.stdout:
                file.write(line)
                if verbose:
                    print(line, end='')
        result.wait()
        with open(scan_output_file, 'r') as file:
            scan_results = file.read()
        return scan_results
    except Exception as e:
        logging.error(f"Error running JoomScan: {e}")
        return None

def run_wpscan(url, verbose=False, output_file=None):
    scan_output_file = output_file or 'wpscan_output.txt'
    try:
        result = subprocess.Popen(['wpscan', '--url', url, '--detection-mode', 'passive'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if output_file:
            with open(scan_output_file, 'w') as file:
                for line in result.stdout:
                    file.write(line)
                    if verbose:
                        print(line, end='')
        else:
            for line in result.stdout:
                if verbose:
                    print(line, end='')
        result.wait()
        with open(scan_output_file, 'r') as file:
            scan_results = file.read()
        return scan_results
    except Exception as e:
        logging.error(f"Error running WPScan: {e}")
        return None

def run_droopescan(url, cms_type, verbose=False):
    original_directory = os.getcwd()
    os.chdir('droopescan')
    scan_output_file = 'droopescan_output.txt'
    try:
        result = subprocess.Popen(['./droopescan', 'scan', cms_type, '-u', url], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        with open(scan_output_file, 'w') as file:
            for line in result.stdout:
                file.write(line)
                if verbose:
                    print(line, end='')
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

def search_cves_for_versions(versions):
    cves_found = []
    for version in versions:
        search_url = f"https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword={version}"
        try:
            response = requests.get(search_url)
            if response.status_code == 200:
                cves = re.findall(r'CVE-\d{4}-\d{4,7}', response.text)
                if cves:
                    logging.info(f"Found CVEs for version {version}: {', '.join(cves)}")
                    cves_found.extend(cves)
                else:
                    logging.info(f"No CVEs found for version {version}")
            else:
                logging.error(f"Failed to retrieve CVEs for version {version}")
        except requests.RequestException as e:
            logging.error(f"Failed to retrieve CVEs for version {version}: {e}")
    return cves_found

def generate_pdf(formatted_results, url, cms):
    pdf_file_path = 'scan_output.pdf'
    doc = SimpleDocTemplate(pdf_file_path, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph(f"Scan Results for {url} ({cms.capitalize()}):", styles['Title']))
    elements.append(Paragraph(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    
    for line in formatted_results.split('\n'):
        elements.append(Paragraph(line, styles['Normal']))

    doc.build(elements)
    print(f"PDF report generated: {pdf_file_path}")
    logging.info(f"PDF report generated: {pdf_file_path}")

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

def main():
    print_banner()
    url = input("Enter the URL of the site to scan: ").strip()
    cms = detect_cms(url)
    if not cms:
        print("Unknown CMS or unable to detect CMS.")
        return
    logging.info(f"{cms.capitalize()} detected at {url}")
    print(f"{cms.capitalize()} detected.")
    verbose_mode = input("Do you want verbose mode? (yes/no): ").strip().lower() == 'yes'
    if verbose_mode:
        logging.info("Verbose mode activated.")
        print("Verbose mode activated.")

    scan_output_file = 'scan_output.txt'
    formatted_results = run_scan(url, cms, verbose_mode, scan_output_file)

    if formatted_results:
        print("Scan completed successfully.")
        logging.info("Scan completed successfully.")
    else:
        print("Scan failed.")
        logging.error("Scan failed.")
        return

    print_to_pdf = input("Do you want to generate a PDF report? (yes/no): ").strip().lower() == 'yes'

    if print_to_pdf:
        generate_pdf(formatted_results, url, cms)
    else:
        with open('scan_output.txt', 'w') as f:
            f.write(formatted_results)

        print("Scan Results:")
        print(formatted_results)

        versions = get_versions_from_scan_results(formatted_results)
        if versions:
            cves_found = search_cves_for_versions(versions)
            if cves_found:
                print("\nCVEs Found:")
                print("\n".join(cves_found))
            else:
                print("\nNo CVEs Found")
        else:
            print("\nNo version information found.")

if __name__ == '__main__':
    main()
 
