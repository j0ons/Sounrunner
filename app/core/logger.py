"""Logging setup for assessment sessions."""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path


def configure_logger(log_dir: Path, level: str = "INFO") -> logging.Logger:
    """Configure session logger with detailed file logs and quiet console errors."""

    log_dir.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("soun_runner")
    logger.setLevel(level)
    logger.handlers.clear()
    logger.propagate = False

    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    file_handler = RotatingFileHandler(
        log_dir / "runner.log",
        maxBytes=2_000_000,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(level)
    logger.addHandler(file_handler)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.setLevel("ERROR")
    logger.addHandler(console_handler)

    return logger
