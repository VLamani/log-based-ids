from abc import ABC, abstractmethod
from typing import Optional

from src.ids.models import Alert, Event


class BaseDetector(ABC):
    """Common interface for all intrusion detection rules."""

    def __init__(self, threshold: int, window_seconds: int):
        if threshold <= 0:
            raise ValueError("threshold must be greater than zero")

        if window_seconds <= 0:
            raise ValueError("window_seconds must be greater than zero")

        self.threshold = threshold
        self.window_seconds = window_seconds

    @abstractmethod
    def process(self, event: Event) -> Optional[Alert]:
        """Process an event and return an alert when a rule triggers."""
        raise NotImplementedError
