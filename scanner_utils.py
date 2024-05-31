import requests
import concurrent.futures
import logging

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
