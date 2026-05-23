from abc import ABC, abstractmethod
from pathlib import Path


class LLMProvider(ABC):
    @abstractmethod
    def review(self, *, file_path: Path, context: str) -> dict:
        """Deep-dive review of file_path given prior-stage evidence context.

        Returns a dict with keys: verdict ("ALLOW"|"BLOCK"), confidence (0-1),
        reasoning (str), indicators (list[str]), functions_reviewed (list[str]).
        """
