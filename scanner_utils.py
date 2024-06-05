import requests
import concurrent.futures
import logging
import subprocess
import re
import os
import time
from tqdm import tqdm

def make_request(url, method='GET', headers=None, timeout=10):
    try:
        if method == 'GET':
            response = requests.get(url, headers=headers, timeout=timeout)
        elif method == 'HEAD':
            response = requests.head(url, headers=headers, timeout=timeout)
        response.raise_for_status()
        return response
    except requests.RequestException as e:
        logging.error(f"Request to {url} failed: {e}")
        return None

def check_common_files(url, cms, config):
    common_files = config[cms]['common_files']
    headers = {'User-Agent': 'Mozilla/5.0 (compatible; CMS-Scanner/1.0)'}

    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_file = {executor.submit(make_request, url.rstrip('/') + '/' + file, method='HEAD', headers=headers): file for file in common_files}
        for future in concurrent.futures.as_completed(future_to_file):
            try:
                response = future.result()
                if response and response.status_code == 200:
                    return True
            except Exception as e:
                logging.error(f"Error checking {file} for {cms}: {e}")
    return False

def load_cpe_dictionary(file_path='official-cpe-dictionary_v2.3.xml'):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"{file_path} not found")
    
    with open(file_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()
    
    return lines

def search_cpe(service, version, cpe_lines):
    matched_cpes = []
    pattern = re.compile(r'<cpe-23:cpe23-item name="(cpe:2\.3:[^"]+)"')
    for line in cpe_lines:
        if line.strip().startswith('<cpe-23:cpe23-item name="'):
            match = pattern.search(line)
            if match and service.lower() in line.lower() and version in line:
                matched_cpes.append(match.group(1))
    return matched_cpes

def extract_cves(cpe_name):
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
    exclude_services = {'version', 'document', 'plugin', 'manager'}
    services = {}
    regex_patterns = [
        r'(\w+)[\s/-]+v?(\d+\.\d+\.\d+)',         # Matches "service 1.2.3" or "service-v1.2.3"
        r'(\w+)\s*:\s*v?(\d+\.\d+\.\d+)',         # Matches "service: 1.2.3" or "service: v1.2.3"
        r'(\w+)\s+version\s+v?(\d+\.\d+\.\d+)',   # Matches "service version 1.2.3"
        r'(\w+)\s+v?(\d+\.\d+)',                  # Matches "service 1.2" or "service v1.2"
    ]

    for pattern in regex_patterns:
        for line in scan_results.split('\n'):
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                service = match.group(1).lower()
                if service in exclude_services:
                    continue
                version = match.group(2)
                services[service] = {'version': version}
    return services

def analyze_scan_results(scan_results):
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
