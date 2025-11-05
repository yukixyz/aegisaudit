from pathlib import Path
import logging
from logging.handlers import RotatingFileHandler

LOG_DIR = Path("logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)

def get_logger(name: str = "inspector_safe"):
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    console.setFormatter(formatter)
    file_handler = RotatingFileHandler(LOG_DIR / "audit.log", maxBytes=5_000_000, backupCount=5)
    file_handler.setFormatter(formatter)
    logger.addHandler(console)
    logger.addHandler(file_handler)
    return logger
