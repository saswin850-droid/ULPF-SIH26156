"""
Base interface every parser must implement.

This is the whole point of "plug-and-play onboarding" (requirement e):
adding a new log source means writing one class with two methods and
registering it. Nothing else in the system needs to change.
"""

from abc import ABC, abstractmethod
from .schema import NormalizedEvent


class BaseParser(ABC):
    name: str = "base"
    version: str = "0.1"

    @abstractmethod
    def can_parse(self, raw_line: str) -> bool:
        """Return True if this parser recognizes the line's format.
        Should be cheap — this gets called on every registered parser
        for every unclassified line until one claims it."""
        raise NotImplementedError

    @abstractmethod
    def parse(self, raw_line: str) -> NormalizedEvent:
        """Parse the line into a NormalizedEvent. Only called after
        can_parse() returned True for this parser."""
        raise NotImplementedError
