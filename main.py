import os
import argparse
import logging
from logging_config import setup_logging
from cms_detector import detect_cms
from config_loader import load_config
from scanner_utils import analyze_scan_results, extract_cves, search_cpe
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from config_loader import load_cpe_dictionary
from jinja2 import Environment, FileSystemLoader
import subprocess
import re
from tqdm import tqdm
import platform
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Disable SSL warnings for requests
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Set up logging
setup_logging()

def parse_arguments():
    """
    Parses command-line arguments for the CMS vulnerability scanner.

    :return: Parsed arguments
    """
    parser = argparse.ArgumentParser(description='CMS Vulnerability Scanner')
    parser.add_argument('-u', '--url', required=True, help='The URL of the site to scan')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose mode')
    parser.add_argument('-o', '--output', choices=['pdf', 'html', 'text'], default='text', help='Output format')
    parser.add_argument('--no-verify-ssl', action='store_true', help='Bypass SSL certificate verification')
    return parser.parse_args()

def prompt_for_cms_choice():
    """
    Prompts the user to manually specify the CMS if desired.

    :return: The specified CMS or None if not specified
    """
    choice = input("Do you want to specify the CMS manually? (yes/no): ").strip().lower()
    if choice == 'yes':
        cms = input("Please specify the CMS (joomla, wordpress, silverstripe, drupal, typo3, aem, vbscan, moodle, oscommerce, coldfusion, jboss, oracle_e_business, phpbb, php_nuke, dotnetnuke, umbraco, prestashop, opencart, magento): ").strip().lower()
        if cms not in ['joomla', 'wordpress', 'silverstripe', 'drupal', 'typo3', 'aem', 'vbscan', 'moodle', 'oscommerce', 'coldfusion', 'jboss', 'oracle_e_business', 'phpbb', 'php_nuke', 'dotnetnuke', 'umbraco', 'prestashop', 'opencart', 'magento']:
            print("Invalid CMS specified. Exiting.")
            exit(1)
        return cms
    elif choice == 'no':
        return None
    else:
        print("Invalid choice. Please enter 'yes' or 'no'.")
        return prompt_for_cms_choice()

def run_nmap_scan(url, verbose=False, output_file=None, verify_ssl=True):
    """
    Runs an Nmap scan on the given URL.

    :param url: The URL to scan
    :param verbose: Whether to enable verbose output
    :param output_file: The file to save the scan results
    :param verify_ssl: Whether to verify SSL certificates
    :return: The scan results as a string
    """
    print("Launching Nmap scan...")
    scan_output_file = output_file or 'nmap_output.txt'
    try:
        domain = url.replace('https://', '').replace('http://', '').strip('/')
        nmap_command = ['nmap', '-p-', '-A', domain]
        result = subprocess.Popen(nmap_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
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
        logging.error(f"Error running Nmap: {e}")
    return None

def run_joomscan(url, verbose=False, output_file=None, verify_ssl=True):
    """
    Runs the Joomla scanner on the given URL.

    :param url: The URL to scan
    :param verbose: Whether to enable verbose output
    :param output_file: The file to save the scan results
    :param verify_ssl: Whether to verify SSL certificates
    :return: The scan results as a string
    """
    print("Launching Joomla scanner...")
    scan_output_file = output_file or 'joomscan_output.txt'
    try:
        if platform.system().lower() == 'linux' and 'kali' in platform.release().lower():
            # Use the pre-installed command for Kali Linux
            result = subprocess.Popen(['joomscan', '--url', url], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        else:
            # Use the perl command for other distributions
            original_directory = os.getcwd()
            os.chdir('joomscan')
            joomscan_command = ['perl', 'joomscan.pl', '--url', url]
            result = subprocess.Popen(joomscan_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            os.chdir(original_directory)

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

def run_wpscan(url, verbose=False, output_file=None, verify_ssl=True):
    """
    Runs the WordPress scanner on the given URL.

    :param url: The URL to scan
    :param verbose: Whether to enable verbose output
    :param output_file: The file to save the scan results
    :param verify_ssl: Whether to verify SSL certificates
    :return: The scan results as a string
    """
    print("Launching WordPress scanner...")
    scan_output_file = output_file or 'wpscan_output.txt'
    try:
        wpscan_command = ['wpscan', '--url', url, '--detection-mode', 'passive']
        result = subprocess.Popen(wpscan_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
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

def run_droopescan(url, cms_type, verbose=False, verify_ssl=True):
    """
    Runs Droopescan on the given URL for the specified CMS type.

    :param url: The URL to scan
    :param cms_type: The type of CMS (drupal, silverstripe)
    :param verbose: Whether to enable verbose output
    :param verify_ssl: Whether to verify SSL certificates
    :return: The scan results as a string
    """
    print("Launching Droopescan...")
    original_directory = os.getcwd()
    os.chdir('droopescan')
    scan_output_file = 'droopescan_output.txt'
    try:
        droopescan_command = ['./droopescan', 'scan', cms_type, '-u', url]
        result = subprocess.Popen(droopescan_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
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

def run_typo3scan(url, verbose=False, output_file=None, verify_ssl=True):
    """
    Runs the Typo3 scanner on the given URL.

    :param url: The URL to scan
    :param verbose: Whether to enable verbose output
    :param output_file: The file to save the scan results
    :param verify_ssl: Whether to verify SSL certificates
    :return: The scan results as a string
    """
    print("Launching Typo3 scanner...")
    original_directory = os.getcwd()
    os.chdir('Typo3Scan')
    scan_output_file = output_file or 'typo3scan_output.txt'
    try:
        typo3scan_command = ['python3', 'typo3scan.py', '-d', url, '--vuln']
        result = subprocess.Popen(typo3scan_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
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
        logging.error(f"Error running Typo3Scan: {e}")
        return None
    finally:
        os.chdir(original_directory)

def run_aemscan(url, verbose=False, output_file=None, verify_ssl=True):
    """
    Runs the AEM scanner on the given URL.

    :param url: The URL to scan
    :param verbose: Whether to enable verbose output
    :param output_file: The file to save the scan results
    :param verify_ssl: Whether to verify SSL certificates
    :return: The scan results as a string
    """
    print("Launching AEM scanner...")
    original_directory = os.getcwd()
    os.chdir('aemscan')
    scan_output_file = output_file or 'aemscan_output.txt'
    try:
        aemscan_command = ['aemscan', url]
        result = subprocess.Popen(aemscan_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
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
        logging.error(f"Error running AEMScan: {e}")
        return None
    finally:
        os.chdir(original_directory)

def run_vbscan(url, verbose=False, output_file=None, verify_ssl=True):
    """
    Runs the VB scanner on the given URL.

    :param url: The URL to scan
    :param verbose: Whether to enable verbose output
    :param output_file: The file to save the scan results
    :param verify_ssl: Whether to verify SSL certificates
    :return: The scan results as a string
    """
    print("Launching VB scanner...")
    original_directory = os.getcwd()
    os.chdir('vbscan')
    scan_output_file = output_file or 'vbscan_output.txt'
    try:
        vbscan_command = ['./vbscan.pl', url]
        result = subprocess.Popen(vbscan_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
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
        logging.error(f"Error running VBScan: {e}")
        return None
    finally:
        os.chdir(original_directory)

def run_badmoodle(url, verbose=False, output_file=None, verify_ssl=True):
    """
    Runs the Moodle scanner on the given URL.

    :param url: The URL to scan
    :param verbose: Whether to enable verbose output
    :param output_file: The file to save the scan results
    :param verify_ssl: Whether to verify SSL certificates
    :return: The scan results as a string
    """
    print("Launching badmoodle scanner...")
    original_directory = os.getcwd()
    os.chdir('badmoodle')
    scan_output_file = output_file or 'badmoodle_output.txt'
    try:
        badmoodle_command = ['./badmoodle.py', '-u', url, '-l', '2']
        result = subprocess.Popen(badmoodle_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
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
        logging.error(f"Error running badmoodle: {e}")
        return None
    finally:
        os.chdir(original_directory)

def search_cves_for_services(scan_results):
    """
    Searches for CVEs related to services found in the scan results.

    :param scan_results: The scan results
    :return: A dictionary of analyzed results
    """
    analyzed_results = analyze_scan_results(scan_results)
    all_cves = set()
    for service, details in analyzed_results.items():
        if details['cves']:
            all_cves.update(details['cves'])
    return analyzed_results

def generate_pdf(formatted_results, url, cms, cves):
    """
    Generates a PDF report of the scan results.

    :param formatted_results: The formatted scan results
    :param url: The URL of the scanned site
    :param cms: The detected CMS
    :param cves: A list of detected CVEs
    """
    pdf_file_path = 'scan_output.pdf'
    doc = SimpleDocTemplate(pdf_file_path, pagesize=letter)
    styles = getSampleStyleSheet()
    custom_style = ParagraphStyle(
        'Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=12,
        spaceAfter=10,
    )
    title_style = ParagraphStyle(
        'Title',
        parent=styles['Title'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        spaceAfter=12,
    )

    elements = []

    elements.append(Paragraph(f"Scan Results for {url} ({cms.capitalize()}):", title_style))
    elements.append(Paragraph(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))

    elements.append(Spacer(1, 12))
    elements.append(Paragraph("Scan Results:", title_style))

    for line in formatted_results.split('\n'):
        elements.append(Paragraph(line, custom_style))

    if cves:
        elements.append(Spacer(1, 12))
        elements.append(Paragraph("CVEs Found:", title_style))
        data = [['CVE ID']]
        for cve in cves:
            data.append([cve])
        table = Table(data, colWidths=[4.0 * 72])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ]))
        elements.append(table)
    else:
        elements.append(Spacer(1, 12))
        elements.append(Paragraph("No CVEs Found", styles['Normal']))

    doc.build(elements)
    print(f"PDF report generated: {pdf_file_path}")
    logging.info(f"PDF report generated: {pdf_file_path}")

def generate_html(formatted_results, url, cms, cves):
    """
    Generates an HTML report of the scan results.

    :param formatted_results: The formatted scan results
    :param url: The URL of the scanned site
    :param cms: The detected CMS
    :param cves: A list of detected CVEs
    """
    env = Environment(loader=FileSystemLoader('.'))
    template = env.get_template('report_template.html')
    html_content = template.render(url=url, cms=cms, date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'), results=formatted_results, cves=cves)
    html_file_path = 'scan_output.html'
    with open(html_file_path, 'w') as f:
        f.write(html_content)
    print(f"HTML report generated: {html_file_path}")
    logging.info(f"HTML report generated: {html_file_path}")

def run_scan(url, cms, verbose, scan_output_file, verify_ssl=True):
    """
    Runs the appropriate scanner based on the detected CMS.

    :param url: The URL to scan
    :param cms: The detected CMS
    :param verbose: Whether to enable verbose output
    :param scan_output_file: The file to save the scan results
    :param verify_ssl: Whether to verify SSL certificates
    :return: The scan results as a string
    """
    if cms == 'joomla':
        return run_joomscan(url, verbose, scan_output_file, verify_ssl)
    elif cms == 'wordpress':
        return run_wpscan(url, verbose, scan_output_file, verify_ssl)
    elif cms == 'typo3':
        return run_typo3scan(url, verbose, scan_output_file, verify_ssl)
    elif cms == 'aem':
        return run_aemscan(url, verbose, scan_output_file, verify_ssl)
    elif cms == 'vbscan':
        return run_vbscan(url, verbose, scan_output_file, verify_ssl)
    elif cms == 'moodle':
        return run_badmoodle(url, verbose, scan_output_file, verify_ssl)
    elif cms in ['oscommerce', 'coldfusion', 'jboss', 'oracle_e_business', 'phpbb', 'php_nuke', 'dotnetnuke', 'umbraco', 'prestashop', 'opencart', 'magento']:
        return run_nmap_scan(url, verbose, scan_output_file, verify_ssl)
    elif cms in ['silverstripe', 'drupal']:
        return run_droopescan(url, cms, verbose, verify_ssl)
    elif cms == 'nmap':
        return run_nmap_scan(url, verbose, scan_output_file, verify_ssl)
    else:
        logging.error(f"Unsupported CMS: {cms}")
        return None

def print_banner():
    """
    Prints the tool banner.
    """
    banner = """
    __  ___ ___  _____        _____   __   ____  ____   ____     ___  ____  
   /  ]|   |   |/ ___/       / ___/  /  ] /    ||    \ |    \   /  _]|    \ 
  /  / | _   _ (   \_  _____(   \_  /  / |  o  ||  _  ||  _  | /  [_ |  D  )
 /  /  |  \_/  |\__  ||     |\__  |/  /  |     ||  |  ||  |  ||    _]|    / 
/   \_ |   |   |/  \ ||_____|/  \ /   \_ |  _  ||  |  ||  |  ||   [_ |    \ 
\     ||   |   |\    |       \    \     ||  |  ||  |  ||  |  ||     ||  .  \\
 \____||___|___| \___|        \___|\____||__|__||__|__||__|__||_____||__|\_|
 
  CMS Scanner: Detects and scans Joomla, WordPress, SilverStripe, Drupal, Typo3, AEM, VBulletin, Moodle, Oscommerce, Coldfusion, Jboss, Oracle E-Business, Phpbb, Php-nuke, Dotnetnuke, Umbraco, Prestashop, Opencart, Magento.

                                    BY JMO

"""
    print(banner)
    logging.info("Printed banner.")

def main():
    """
    The main function to run the CMS vulnerability scanner.
    """
    args = parse_arguments()
    print_banner()
    url = args.url
    verbose = args.verbose
    output_format = args.output
    verify_ssl = not args.no_verify_ssl

    # Prompt for CMS choice
    cms = prompt_for_cms_choice()

    if not cms:
        cms = detect_cms(url, verify_ssl)
        if cms:
            print(f"Detected CMS: {cms}")
            logging.info(f"Detected CMS: {cms}")
        else:
            print("Unknown CMS or unable to detect CMS. Running Nmap scan as fallback.")
            logging.info("Unknown CMS or unable to detect CMS. Running Nmap scan as fallback.")
            cms = 'nmap'

    if verbose:
        logging.info("Verbose mode activated.")
        print("Verbose mode activated.")

    scan_output_file = 'scan_output.txt'
    formatted_results = run_scan(url, cms, verbose, scan_output_file, verify_ssl)

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
