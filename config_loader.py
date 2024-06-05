import json
import logging
import os
from xml.etree import ElementTree as ET

def load_config(file_path='config.json'):
    try:
        with open(file_path, 'r') as config_file:
            return json.load(config_file)
    except Exception as e:
        logging.error(f"Failed to load config: {e}")
        return None

def load_cpe_dictionary():
    cpe_dict_path = 'official-cpe-dictionary_v2.3.xml'
    if not os.path.exists(cpe_dict_path):
        raise FileNotFoundError(f"{cpe_dict_path} not found")
    
    tree = ET.parse(cpe_dict_path)
    root = tree.getroot()
    cpe_dict = {}
    
    for cpe_item in root.findall('.//{http://cpe.mitre.org/dictionary/2.0}cpe-item'):
        name = cpe_item.get('name')
        if name.startswith("cpe:2.3"):
            title = cpe_item.find('.//{http://scap.nist.gov/schema/cpe-extension/2.3}title').text
            cpe_dict[title] = name
    
    return cpe_dict

def search_cpe(service, version, cpe_dict):
    matched_cpes = []
    for title, name in cpe_dict.items():
        if service.lower() in title.lower() and version in title:
            matched_cpes.append(name)
    return matched_cpes
