import logging
from logging.handlers import RotatingFileHandler

def setup_logging():
    handler = RotatingFileHandler('scanner.log', maxBytes=1000000, backupCount=3)
    logging.basicConfig(
        handlers=[handler],
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(module)s - %(message)s'
    )
