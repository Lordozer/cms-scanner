import requests
from bs4 import BeautifulSoup
import logging
from scanner_utils import make_request, check_common_files
from config_loader import load_config
import concurrent.futures

config = load_config()

CMS_PRIORITIES = {
    'wordpress': 1,
    'joomla': 2,
    'drupal': 3,
    'magento': 4,
    'silverstripe': 5,
    'typo3': 6,
    'aem': 7,
    'vbscan': 8,
    'moodle': 9,
    'oscommerce': 10,
    'coldfusion': 11,
    'jboss': 12,
    'oracle_e_business': 13,
    'phpbb': 14,
    'php_nuke': 15,
    'dotnetnuke': 16,
    'umbraco': 17,
    'prestashop': 18,
    'opencart': 19
}

def detect_cms(url, verify_ssl=True):
    try:
        cms_checks = {
            'joomla': check_joomla,
            'wordpress': check_wordpress,
            'silverstripe': check_silverstripe,
            'drupal': check_drupal,
            'typo3': check_typo3,
            'aem': check_aem,
            'vbscan': check_vbscan,
            'moodle': check_moodle,
            'oscommerce': check_oscommerce,
            'coldfusion': check_coldfusion,
            'jboss': check_jboss,
            'oracle_e_business': check_oracle_e_business,
            'phpbb': check_phpbb,
            'php_nuke': check_php_nuke,
            'dotnetnuke': check_dotnetnuke,
            'umbraco': check_umbraco,
            'prestashop': check_prestashop,
            'opencart': check_opencart,
            'magento': check_magento
        }

        detected_cms = []
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_to_cms = {executor.submit(check_function, url, verify_ssl): cms for cms, check_function in cms_checks.items()}
            for future in concurrent.futures.as_completed(future_to_cms):
                cms = future_to_cms[future]
                try:
                    if future.result():
                        logging.info(f"Detected CMS: {cms}")
                        detected_cms.append(cms)
                except Exception as e:
                    logging.error(f"Error detecting {cms}: {e}")

        if detected_cms:
            detected_cms.sort(key=lambda cms: CMS_PRIORITIES.get(cms, float('inf')))
            logging.info(f"Detected CMSs in order of priority: {detected_cms}")
            return detected_cms[0]
        else:
            logging.info("No CMS detected")
            return None
    except Exception as e:
        logging.error(f"Error detecting CMS: {e}")
        return None

def check_joomla(url, verify_ssl=True):
    joomla_indicators = ['content="Joomla!', 'Joomla', 'index.php?option=com_', '/media/system/js/']
    return check_cms(url, joomla_indicators, 'joomla', verify_ssl)

def check_wordpress(url, verify_ssl=True):
    wordpress_indicators = ['wp-content', 'WordPress', 'wp-includes', '?ver=', 'wp-json']
    return check_cms(url, wordpress_indicators, 'wordpress', verify_ssl)

def check_silverstripe(url, verify_ssl=True):
    silverstripe_indicators = ['SilverStripe', 'Security/login', 'cms/', 'framework/']
    return check_cms(url, silverstripe_indicators, 'silverstripe', verify_ssl)

def check_drupal(url, verify_ssl=True):
    drupal_indicators = ['Drupal', 'X-Generator']
    return check_cms(url, drupal_indicators, 'drupal', verify_ssl)

def check_typo3(url, verify_ssl=True):
    typo3_indicators = ['typo3', 'TYPO3']
    return check_cms(url, typo3_indicators, 'typo3', verify_ssl)

def check_aem(url, verify_ssl=True):
    aem_indicators = ['AEM', 'Adobe Experience Manager']
    return check_cms(url, aem_indicators, 'aem', verify_ssl)

def check_vbscan(url, verify_ssl=True):
    vbscan_indicators = ['vBulletin', 'vBSEO']
    return check_cms(url, vbscan_indicators, 'vbscan', verify_ssl)

def check_moodle(url, verify_ssl=True):
    moodle_indicators = ['Moodle']
    return check_cms(url, moodle_indicators, 'moodle', verify_ssl)

def check_oscommerce(url, verify_ssl=True):
    oscommerce_indicators = ['osCommerce', 'oscommerce']
    return check_cms(url, oscommerce_indicators, 'oscommerce', verify_ssl)

def check_coldfusion(url, verify_ssl=True):
    coldfusion_indicators = ['ColdFusion']
    return check_cms(url, coldfusion_indicators, 'coldfusion', verify_ssl)

def check_jboss(url, verify_ssl=True):
    jboss_indicators = ['JBoss']
    return check_cms(url, jboss_indicators, 'jboss', verify_ssl)

def check_oracle_e_business(url, verify_ssl=True):
    oracle_indicators = ['Oracle E-Business', 'Oracle']
    return check_cms(url, oracle_indicators, 'oracle_e_business', verify_ssl)

def check_phpbb(url, verify_ssl=True):
    phpbb_indicators = ['phpBB']
    return check_cms(url, phpbb_indicators, 'phpbb', verify_ssl)

def check_php_nuke(url, verify_ssl=True):
    phpnuke_indicators = ['PHP-Nuke', 'phpnuke']
    return check_cms(url, phpnuke_indicators, 'php_nuke', verify_ssl)

def check_dotnetnuke(url, verify_ssl=True):
    dotnetnuke_indicators = ['DotNetNuke', 'DNN']
    return check_cms(url, dotnetnuke_indicators, 'dotnetnuke', verify_ssl)

def check_umbraco(url, verify_ssl=True):
    umbraco_indicators = ['Umbraco']
    return check_cms(url, umbraco_indicators, 'umbraco', verify_ssl)

def check_prestashop(url, verify_ssl=True):
    prestashop_indicators = ['PrestaShop']
    return check_cms(url, prestashop_indicators, 'prestashop', verify_ssl)

def check_opencart(url, verify_ssl=True):
    opencart_indicators = ['OpenCart']
    return check_cms(url, opencart_indicators, 'opencart', verify_ssl)

def check_magento(url, verify_ssl=True):
    magento_indicators = ['Magento']
    return check_cms(url, magento_indicators, 'magento', verify_ssl)

def check_cms(url, indicators, cms, verify_ssl=True):
    try:
        response = make_request(url, headers={'User-Agent': 'Mozilla/5.0 (compatible; CMS-Scanner/1.0)'}, verify_ssl=verify_ssl)
        if not response:
            return False
        if any(indicator in response.text for indicator in indicators) or any(indicator in response.headers.get('X-Powered-By', '') for indicator in indicators):
            logging.info(f"Detected {cms} by indicators")
            return True
        result = check_common_files(url, cms, config, verify_ssl)
        if result:
            logging.info(f"Detected {cms} by common files")
        return result
    except Exception as e:
        logging.error(f"Error checking {cms} for {url}: {e}")
        return False
