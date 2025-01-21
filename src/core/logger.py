import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from src.core.config import configs


def setup_root_logger() -> None:
    logger = logging.getLogger("")
    if logger.hasHandlers():
        logger.handlers.clear()

    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    console = logging.StreamHandler()
    console.setFormatter(formatter)

    filepath = Path(configs.logger_filename)
    if not Path.exists(filepath):
        filepath.parent.mkdir(parents=True, exist_ok=True)
        filepath.open("w").close()

    file = RotatingFileHandler(
        filename=configs.logger_filename,
        mode=configs.logger_mod,
        maxBytes=configs.logger_maxbytes,
        backupCount=configs.logger_backup_count,
    )
    file.setFormatter(formatter)
    logger.addHandler(console)
    logger.addHandler(file)
    logger.setLevel(logging.INFO)

    logging.getLogger("backoff").addHandler(logging.StreamHandler())
