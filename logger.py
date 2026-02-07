import logging
import sys
from typing import Optional
from rich.logging import RichHandler

def setup_logger(log_file: str, console_output: bool = True) -> logging.Logger:
    """
    Configure logging to write to a file and optionally to the console using Rich.
    
    Args:
        log_file: Path to the log file.
        console_output: Whether to print logs to stdout as well.
    """
    # Create a custom logger
    logger = logging.getLogger("IDS_Logger")
    logger.setLevel(logging.INFO)
    
    # Clear existing handlers to avoid duplicates
    if logger.hasHandlers():
        logger.handlers.clear()

    # Create formatters
    file_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    # File Handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    # Console Handler (Optional)
    if console_output:
        # RichHandler provides beautiful colored logs by default
        console_handler = RichHandler(rich_tracebacks=True, markup=True)
        logger.addHandler(console_handler)
        
    return logger

def get_logger() -> logging.Logger:
    """Get the configured logger instance."""
    return logging.getLogger("IDS_Logger")
