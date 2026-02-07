"""Central logging setup used across the AI shield project."""

from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path


def configure_logging(log_level: str = "INFO", log_dir: str = "logs") -> None:
    """Configure root logging with console and rotating file handlers.

    Args:
        log_level: Log level string (DEBUG, INFO, WARNING, ERROR, CRITICAL).
        log_dir: Directory used to persist project log files.
    """
    level = getattr(logging, log_level.upper(), logging.INFO)
    Path(log_dir).mkdir(parents=True, exist_ok=True)

    root_logger = logging.getLogger()
    if root_logger.handlers:
        return

    root_logger.setLevel(level)
    formatter = logging.Formatter(
        "%(asctime)s | %(name)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    file_handler = RotatingFileHandler(
        os.path.join(log_dir, "ai_shield.log"),
        maxBytes=1_000_000,
        backupCount=5,
    )
    file_handler.setFormatter(formatter)

    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)
