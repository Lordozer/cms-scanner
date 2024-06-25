import logging
from logging.handlers import RotatingFileHandler

def setup_logging():
    """
    Sets up logging configuration with rotating file handler.
    Logs are written to 'scanner.log' with a maximum size of 1MB and 3 backup files.
    """
    handler = RotatingFileHandler('scanner.log', maxBytes=1000000, backupCount=3)
    logging.basicConfig(
        handlers=[handler],
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(module)s - %(message)s'
    )
