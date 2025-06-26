# Reusable logging setup

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from datetime import datetime
from typing import Union

def setup_logger(
    name: str = "net_automation",
    log_dir: str = "logs",
    level: Union[int, str] = logging.INFO,
    max_bytes: int = 5 * 1024 * 1024,  # 5MB
    backup_count: int = 3
) -> logging.Logger:
    """
    Creates and returns a reusable logger with optional rotation.
    Logs are saved with timestamped filenames under the specified directory.

    Args:
        name: Logger name
        log_dir: Directory to save logs
        level: Log level (int or string like 'DEBUG')
        max_bytes: Max size of log file before rotating
        backup_count: Number of rotated logs to keep

    Returns:
        Configured logging.Logger instance
    """
    if isinstance(level, str):
        level = getattr(logging, level.upper(), logging.INFO)

    log_dir_path = Path(log_dir)
    log_dir_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir_path / f"{name}_{timestamp}.log"

    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.propagate = False

    if not logger.handlers:
        file_handler = RotatingFileHandler(
            log_file, maxBytes=max_bytes, backupCount=backup_count
        )
        file_handler.setLevel(level)

        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)

        formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s', "%Y-%m-%d %H:%M:%S")
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

    return logger

#1: Imports & Setup

# - Import logging and RotatingFileHandler
# - Import Path for log directory management
# - Import datetime for timestamped filenames
# - Support both int and str log levels

#2: Handle Log Level

# - If level is string (e.g., "DEBUG"), convert to logging constant
# - Default fallback to INFO

#3: Create Directory

# - Create log directory if not exists using Path().mkdir()

#4: Setup Timestamped Log File

# - Create log file name with current timestamp
# - Use RotatingFileHandler with maxBytes and backupCount

#5: Logger Configuration

# - Prevent double logging with propagate = False
# - Add file and console handlers
# - Set common formatter for both

#6: Return Logger

# - Return reusable logger instance

