import os
import requests
import subprocess
import re
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph

def print_banner():
    print("    __  ___ ___  _____        _____   __   ____  ____   ____     ___  ____  ")
    print("   /  ]|   |   |/ ___/       / ___/  /  ] /    ||    \ |    \   /  _]|    \\ ")
    print("  /  / | _   _ (   \\_  _____(   \\_  /  / |  o  ||  _  ||  _  | /  [_ |  D  )")
    print(" /  /  |  \\_/  |\\__  ||     |\\__  |/  /  |     ||  |  ||  |  ||    _]|    / ")
    print("/   \\_ |   |   |/  \\ ||_____|/  \\ /   \\_ |  _  ||  |  ||  |  ||   [_ |    \\")
    print("\\     ||   |   |\\    |       \\    \\     ||  |  ||  |  ||  |  ||     ||  .  \\")
    print(" \\____||___|___| \\___|        \\___|\\____||__|__||__|__||__|__||_____||__|\\_\\")
    print("\nCMS Scanner: Detects and scans Joomla, WordPress, SilverStripe, and Drupal for vulnerabilities.")
    print("\n\n                                    BY JMO")
    print("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n")

def detect_cms(url):
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

def check_joomla(url):
    try:
        response = requests.get(url)
        if response.status_code != 200:
            return False
        if 'content="Joomla!' in response.text:
            return True
        if 'Joomla' in response.headers.get('X-Generator', ''):
            return True
        if 'index.php?option=com_' in response.text:
            return True
        if '/media/system/js/' in response.text:
            return True
        common_files = [
            'administrator/manifests/files/joomla.xml',
            'administrator/templates/system/css/system.css',
            'media/system/js/mootools-core.js',
            'libraries/cms/version/version.php',
            'libraries/cms/version/version.php-dist'
        ]
        for file in common_files:
            check_url = url.rstrip('/') + '/' + file
            file_response = requests.head(check_url)
            if file_response.status_code == 200:
                return True
        version_header = response.headers.get('X-Platform-Version', '')
        if version_header:
            return True
        js_files = [
            'media/system/js/core.js',
            'media/system/js/mootools-more.js'
        ]
        for js_file in js_files:
            check_js_url = url.rstrip('/') + '/' + js_file
            js_response = requests.get(check_js_url)
            if js_response.status_code == 200 and 'Joomla' in js_response.text:
                return True
    except requests.RequestException:
        pass
    return False

def check_wordpress(url):
    try:
        response = requests.get(url)
        if response.status_code != 200:
            return False
        if 'wp-content' in response.text:
            return True
        if 'WordPress' in response.headers.get('X-Generator', ''):
            return True
        if 'wp-includes' in response.text:
            return True
        if '?ver=' in response.text:
            return True
        if 'wp-json' in response.text:
            return True
        common_files = [
            'wp-login.php',
            'wp-admin/',
            'wp-includes/'
        ]
        for file in common_files:
            check_url = url.rstrip('/') + '/' + file
            file_response = requests.head(check_url)
            if file_response.status_code == 200:
                return True
    except requests.RequestException:
        pass
    return False

def check_silverstripe(url):
    try:
        response = requests.get(url)
        if response.status_code != 200:
            return False
        if 'SilverStripe' in response.text:
            return True
        if 'SilverStripe' in response.headers.get('X-Powered-By', ''):
            return True
        common_files = [
            'cms/css/silverstripe.css',
            'framework/css/silverstripe.css',
            'assets/_combinedfiles/',
            'Security/login'
        ]
        for file in common_files:
            check_url = url.rstrip('/') + '/' + file
            file_response = requests.head(check_url)
            if file_response.status_code == 200:
                return True
    except requests.RequestException:
        pass
    return False

def check_drupal(url):
    try:
        response = requests.get(url)
        if response.status_code != 200:
            return False
        if 'Drupal' in response.text:
            return True
        if 'Drupal' in response.headers.get('X-Generator', ''):
            return True
        common_files = [
            'core/misc/drupal.js',
            'sites/default/settings.php',
            'misc/drupal.js',
            'modules/system/system.module'
        ]
        for file in common_files:
            check_url = url.rstrip('/') + '/' + file
            file_response = requests.head(check_url)
            if file_response.status_code == 200:
                return True
    except requests.RequestException:
        pass
    return False

def run_joomscan(url, verbose=False):
    scan_output_file = 'joomscan_output.txt'
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

def run_wpscan(url, verbose=False, output_file=None):
    result = subprocess.Popen(['wpscan', '--url', url, '--detection-mode', 'passive'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if output_file:
        with open(output_file, 'w') as file:
            for line in result.stdout:
                print(line, end='')
                file.write(line)
    if verbose:
        for line in result.stdout:
            print(line, end='')
    result.wait()
    return result.stdout

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
                print(f"Search successful. Extracted CVEs for version {version}:")
            else:
                print(f"Failed to retrieve CVEs for version {version}")
        except requests.RequestException:
            print(f"Failed to retrieve CVEs for version {version}")

    return cves_found

def generate_pdf(formatted_results):
    pdf_file_path = 'scan_output.pdf'
    doc = SimpleDocTemplate(pdf_file_path, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("Scan Results:", styles['Title']))

    for line in formatted_results.split('\n'):
        elements.append(Paragraph(line, styles['Normal']))

    doc.build(elements)
    print(f"PDF report generated: {pdf_file_path}")

def main():
    print_banner()
    url = input("Enter the URL of the site to scan: ").strip()
    cms = detect_cms(url)
    if not cms:
        print("Unknown CMS or unable to detect CMS.")
        return
    print(f"{cms.capitalize()} detected.")
    verbose_mode = input("Do you want verbose mode? (yes/no): ").strip().lower() == 'yes'
    if verbose_mode:
        print("Verbose mode activated.")

    cves_found = []  # Initialize cves_found variable here
    scan_output_file = 'scan_output.txt'  # Define a file to store scan output

    if cms == 'joomla':
        print("Running JoomScan...")
        scan_results = run_joomscan(url, verbose_mode, scan_output_file)
        with open(scan_output_file, 'r') as file:
            formatted_results = file.read()
    elif cms == 'wordpress':
        print("Running WPScan...")
        scan_results = run_wpscan(url, verbose_mode, scan_output_file)
        with open(scan_output_file, 'r') as file:
            formatted_results = file.read()
    elif cms in ['silverstripe', 'drupal']:
        print(f"Running DroopScan for {cms.capitalize()}...")
        scan_results = run_droopescan(url, cms, verbose_mode)
        formatted_results = scan_results
        # Check if scan_results is a file object
        if hasattr(scan_results, 'read'):
            # If it's a file object, read its content
            with open(scan_output_file, 'r') as file:
                formatted_results = file.read()
        # Retrieve versions from scan_results
        versions = get_versions_from_scan_results(formatted_results)
        if versions:
            # Search for CVEs related to detected versions
            cves_found = search_cves_for_versions(versions)
            if cves_found:
                formatted_results += "\n\nCVEs found for detected versions:\n"
                formatted_results += "\n".join(cves_found)
            else:
                formatted_results += "\n\nNo CVEs found for detected versions."

    print_to_pdf = input("Do you want to generate a PDF report? (yes/no): ").strip().lower() == 'yes'

    if print_to_pdf:
        generate_pdf(formatted_results)
    else:
        # Write the scan output to a text file
        with open('scan_output.txt', 'w') as f:
            f.write(formatted_results)

        print("Scan Results:")
        print(formatted_results)

        # Print CVEs found after scan results
        if cves_found:
            print("\nCVEs Found:")
            print("\n".join(cves_found))
        else:
            print("\nNo CVEs Found")

if __name__ == '__main__':
    main()
