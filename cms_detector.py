import logging
from scanner_utils import make_request, check_common_files
from config_loader import load_config
import concurrent.futures

config = load_config()

def detect_cms(url):
    try:
        cms_checks = {
            'joomla': check_joomla,
            'wordpress': check_wordpress,
            'silverstripe': check_silverstripe,
            'drupal': check_drupal
        }

        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_to_cms = {executor.submit(check_function, url): cms for cms, check_function in cms_checks.items()}
            for future in concurrent.futures.as_completed(future_to_cms):
                cms = future_to_cms[future]
                if future.result():
                    return cms
        return None
    except Exception as e:
        logging.error(f"Error detecting CMS: {e}")
        return None

def check_joomla(url):
    joomla_indicators = ['content="Joomla!', 'Joomla', 'index.php?option=com_', '/media/system/js/']
    return check_cms(url, joomla_indicators, 'joomla')

def check_wordpress(url):
    wordpress_indicators = ['wp-content', 'WordPress', 'wp-includes', '?ver=', 'wp-json']
    return check_cms(url, wordpress_indicators, 'wordpress')

def check_silverstripe(url):
    silverstripe_indicators = ['SilverStripe', 'Security/login', 'cms/', 'framework/']
    return check_cms(url, silverstripe_indicators, 'silverstripe')

def check_drupal(url):
    drupal_indicators = ['Drupal', 'X-Generator']
    return check_cms(url, drupal_indicators, 'drupal')

def check_cms(url, indicators, cms):
    try:
        response = make_request(url, headers={'User-Agent': 'Mozilla/5.0 (compatible; CMS-Scanner/1.0)'})
        if not response:
            return False
        if any(indicator in response.text for indicator in indicators) or any(indicator in response.headers.get('X-Powered-By', '') for indicator in indicators):
            return True
        return check_common_files(url, cms, config)
    except Exception as e:
        logging.error(f"Error checking {cms} for {url}: {e}")
        return False

