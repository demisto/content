from CommonServerPython import *
from typing import Any, Dict, List


class AlertItem:
    def __init__(self, row: dict):
        self.row = row
        pass

    def __getitem__(self, key: str) -> Any:
        if hasattr(self.row, key):
            return getattr(self.row, key)
        raise KeyError(f"{key} not found in AlertItem")

    def to_dict(self) -> Dict[str, Any]:
        return self.row