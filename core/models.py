"""Shared core enums and models."""

from enum import Enum


class Verdict(str, Enum):
    """Supported top-level review outcomes."""

    APPROVE = "APPROVE"
    NEEDS_DISCUSSION = "NEEDS_DISCUSSION"
    REQUEST_CHANGES = "REQUEST_CHANGES"
