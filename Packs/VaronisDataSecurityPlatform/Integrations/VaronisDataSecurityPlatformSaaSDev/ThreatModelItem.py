from CommonServerPython import Any, Dict, List, Optional


from typing import Any, Dict, List


class ThreatModelItem:
    def __init__(self):
        self.Id: Optional[str] = None
        self.Name: Optional[List[str]] = None
        self.Category: Optional[str] = None
        self.Severity: Optional[str] = None
        self.Source: Optional[str] = None

    def __getitem__(self, key: str) -> Any:
        if hasattr(self, key):
            return getattr(self, key)
        raise KeyError(f"{key} not found in EventItem")

    def to_dict(self) -> Dict[str, Any]:
        return {key: value for key, value in self.__dict__.items() if value is not None}