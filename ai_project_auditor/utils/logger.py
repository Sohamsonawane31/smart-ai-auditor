"""
Structured logging module for AI Project Auditor V2.
"""

import logging
import sys

_LOGGER_NAME = "ai_project_auditor"


def setup_logger(verbose: bool = False) -> logging.Logger:
    """Configure and return the root auditor logger."""
    logger = logging.getLogger(_LOGGER_NAME)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Avoid duplicate handlers if called multiple times
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging.DEBUG if verbose else logging.INFO)
        formatter = logging.Formatter(
            fmt="[%(levelname)s] %(message)s" if not verbose else "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger


def get_logger() -> logging.Logger:
    """Retrieve the application logger."""
    return logging.getLogger(_LOGGER_NAME)
