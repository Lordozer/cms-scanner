import requests
import concurrent.futures
import logging
import subprocess
import re
import os
import time
from tqdm import tqdm

def make_request(url, method='GET', headers=None, timeout=10, verify_ssl=True):
    """
    Makes an HTTP request to the given URL.

    :param url: The URL to request
    :param method: The HTTP method to use (default: 'GET')
    :param headers: Optional headers to include in the request
    :param timeout: The request timeout in seconds (default: 10)
    :param verify_ssl: Whether to verify SSL certificates (default: True)
    :return: The response object or None if the request failed
    """
    try:
        if method == 'GET':
            response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True, verify=verify_ssl)
        elif method == 'HEAD':
            response = requests.head(url, headers=headers, timeout=timeout, allow_redirects=True, verify=verify_ssl)
        response.raise_for_status()
        return response
    except requests.RequestException as e:
        logging.error(f"Request to {url} failed: {e}")
        return None

def check_common_files(url, cms, config, verify_ssl=True):
    """
    Checks for common files associated with a CMS.

    :param url: The URL to scan
    :param cms: The CMS name
    :param config: The configuration dictionary
    :param verify_ssl: Whether to verify SSL certificates
    :return: True if any common file is found, False otherwise
    """
    common_files = config[cms]['common_files']
    headers = {'User-Agent': 'Mozilla/5.0 (compatible; CMS-Scanner/1.0)'}

    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_file = {executor.submit(make_request, url.rstrip('/') + '/' + file, method='HEAD', headers=headers, verify_ssl=verify_ssl): file for file in common_files}
        for future in concurrent.futures.as_completed(future_to_file):
            try:
                response = future.result()
                if response and response.status_code == 200:
                    logging.info(f"Found common file for {cms}: {future_to_file[future]}")
                    return True
            except Exception as e:
                logging.error(f"Error checking {file} for {cms}: {e}")
    return False

def load_cpe_dictionary(file_path='official-cpe-dictionary_v2.3.xml'):
    """
    Loads the CPE (Common Platform Enumeration) dictionary from an XML file.

    :param file_path: The path to the CPE dictionary file
    :return: A list of CPE dictionary lines
    :raises FileNotFoundError: If the CPE dictionary file is not found
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"{file_path} not found")

    with open(file_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()

    return lines

def search_cpe(service, version, cpe_lines):
    """
    Searches for CPE entries matching the given service and version.

    :param service: The service name
    :param version: The service version
    :param cpe_lines: The list of CPE dictionary lines
    :return: A list of matched CPE names
    """
    matched_cpes = []
    pattern = re.compile(r'<cpe-23:cpe23-item name="(cpe:2\.3:[^"]+)"')
    for line in cpe_lines:
        if line.strip().startswith('<cpe-23:cpe23-item name="'):
            match = pattern.search(line)
            if match and service.lower() in line.lower() and version in line:
                matched_cpes.append(match.group(1))
    return matched_cpes

def extract_cves(cpe_name):
    """
    Extracts CVEs related to a given CPE name.

    :param cpe_name: The CPE name
    :return: A list of CVE IDs
    """
    try:
        response = subprocess.check_output(
            f"curl -s 'https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe_name}' | jq -r '.vulnerabilities[].cve.id' 2>/dev/null",
            shell=True
        )
        cves = response.decode('utf-8').splitlines()
        return cves
    except subprocess.CalledProcessError as e:
        if "Invalid numeric literal" in str(e):
            time.sleep(15)
            return extract_cves(cpe_name)  # Retry after waiting
        else:
            logging.error(f"Error extracting CVEs for {cpe_name}: {e}")
            return []

def extract_services_and_versions(scan_results):
    """
    Extracts services and versions from scan results.

    :param scan_results: The scan results
    :return: A dictionary of services and their versions
    """
    exclude_services = {'version', 'document', 'plugin', 'manager'}
    services = {}

    regex_patterns = {
        'wpscan': [
            r'\|\s+-\s([^\s]+)\s+([\d\.]+)',  # Matches "| - plugin 1.2.3"
            r'\[\+\] ([^:]+): ([\d\.]+)',  # Matches "[+] plugin: 1.2.3"
            r'Version: ([\d\.]+)'  # Matches "Version: 1.2.3"
        ],
        'joomscan': [
            r'Joomla! ([\d\.]+)',  # Matches "Joomla! 1.2.3"
            r'ver ([\d\.]+)',  # Matches "ver 1.2.3"
        ],
        'droopescan': [
            r'Possible version\(s\):\s+([\d\.\-rc]+)',  # Matches "Possible version(s): 1.2.3"
            r'(\w+)\s+\(version:\s([\d\.]+)'  # Matches "service (version: 1.2.3)"
        ],
        'typo3scan': [
            r'Identified Version:\s+([\d\.]+)',  # Matches "Identified Version: 10.4.37"
            r'Extension Title:\s+([^\n]+)',  # Matches "Extension Title: VHS: Fluid ViewHelpers"
            r'Extension Url:\s+([^\n]+)'  # Matches "Extension Url: https://www.example.com/typo3conf/ext/vhs"
        ],
        'aemscan': [
            r'AEM Version: ([\d\.]+)',  # Matches "AEM Version: 6.5.0"
            r'Component: ([^\n]+)',  # Matches "Component: some-component"
            r'Vulnerability: ([^\n]+)'  # Matches "Vulnerability: some-vulnerability"
        ],
        'vbscan': [
            r'vBulletin ([\d\.]+)',  # Matches "vBulletin 3.7.6"
            r'\[+\] ([^\n]+)',  # Matches "[++] some output"
        ],
        'nmap': [
            r'(\d+)/\w+\s+open\s+([\w\-]+)\s+([\d\.]+)',  # Matches "80/tcp open http 1.1"
            r'(\d+)/\w+\s+open\s+([\w\-]+)\s+([\w\-]+)'  # Matches "80/tcp open http Apache httpd 2.4.7"
        ]
    }

    def add_service(service, version):
        service = service.lower()
        if service not in exclude_services:
            services[service] = {'version': version}

    current_tool = None
    for line in scan_results.split('\n'):
        if "WPScan" in line:
            current_tool = 'wpscan'
        elif "OWASP JoomScan" in line:
            current_tool = 'joomscan'
        elif "Droopescan" in line:
            current_tool = 'droopescan'
        elif "TYPO3" in line:
            current_tool = 'typo3scan'
        elif "AEM Version" in line:
            current_tool = 'aemscan'
        elif "OWASP VBScan" in line:
            current_tool = 'vbscan'
        elif "Nmap" in line:
            current_tool = 'nmap'

        if current_tool:
            for pattern in regex_patterns[current_tool]:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    if current_tool == 'wpscan':
                        if len(match.groups()) == 2:
                            service, version = match.groups()
                            add_service(service, version)
                        elif len(match.groups()) == 1:
                            version = match.group(1)
                            service = 'wordpress'
                            add_service(service, version)
                    elif current_tool == 'joomscan':
                        if len(match.groups()) == 1:
                            version = match.group(1)
                            service = 'joomla'
                            add_service(service, version)
                    elif current_tool == 'droopescan':
                        if len(match.groups()) == 2:
                            service, version = match.groups()
                            add_service(service, version)
                    elif current_tool == 'typo3scan':
                        if len(match.groups()) == 1:
                            version = match.group(1)
                            service = 'typo3'
                            add_service(service, version)
                    elif current_tool == 'aemscan':
                        if len(match.groups()) == 1:
                            version = match.group(1)
                            service = 'aem'
                            add_service(service, version)
                    elif current_tool == 'vbscan':
                        if len(match.groups()) == 1:
                            version = match.group(1)
                            service = 'vbulletin'
                            add_service(service, version)
                    elif current_tool == 'nmap':
                        if len(match.groups()) == 3:
                            port, service, version = match.groups()
                            add_service(service, version)

    return services

def analyze_scan_results(scan_results):
    """
    Analyzes scan results to extract services, versions, and associated CVEs.

    :param scan_results: The scan results
    :return: A dictionary of detected services and their CVEs
    """
    cpe_lines = load_cpe_dictionary()
    services = extract_services_and_versions(scan_results)
    detected_services = {}
    print("Fetching CVEs...")
    total_cpes = sum(len(search_cpe(service, details['version'], cpe_lines)) for service, details in services.items())
    with tqdm(total=total_cpes, desc="Progress", unit="cpe") as pbar:
        for service, details in services.items():
            version = details.get('version', 'unknown')
            cpes = search_cpe(service, version, cpe_lines)
            all_cves = set()  # Use a set to avoid duplicates
            for cpe in cpes:
                cves = extract_cves(cpe)
                all_cves.update(cves)
                pbar.update(1)
            detected_services[service] = {
                'version': version,
                'cpes': cpes,
                'cves': list(all_cves)  # Convert set back to list
            }
    return detected_services
