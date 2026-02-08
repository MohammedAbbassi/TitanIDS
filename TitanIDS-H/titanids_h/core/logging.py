from __future__ import annotations
import logging
import os

def setup_logger(log_file: str = "logs/app.log", console: bool = True) -> logging.Logger:
    logger = logging.getLogger("TitanIDS-H")
    logger.setLevel(logging.INFO)
    if logger.hasHandlers():
        logger.handlers.clear()
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(fh)
    if console:
        try:
            from rich.logging import RichHandler
            ch = RichHandler(rich_tracebacks=False, markup=True)
            logger.addHandler(ch)
        except Exception:
            ch = logging.StreamHandler()
            ch.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
            logger.addHandler(ch)
    return logger
