import json
import logging

def load_config(file_path='config.json'):
    try:
        with open(file_path, 'r') as config_file:
            return json.load(config_file)
    except Exception as e:
        logging.error(f"Failed to load config: {e}")
        return None
