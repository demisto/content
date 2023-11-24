from CommonServerPython import Any, Dict, List, Optional, datetime


from typing import Any, Dict, List


class AlertItem:
    def __init__(self, row: dict):
        self.row = row
        # self.ID: str = None
        # self.Name: str = None
        # self.Time: datetime = None
        # self.Severity: str = None
        # self.SeverityId: int = None
        # self.Category: str = None
        # self.Country: Optional[List[str]] = None
        # self.State: Optional[List[str]] = None
        # self.Status: str = None
        # self.StatusId: int = None
        # self.CloseReason: str = None
        # self.BlacklistLocation: Optional[bool] = None
        # self.AbnormalLocation: Optional[List[str]] = None
        # self.NumOfAlertedEvents: int = None
        # self.UserName: Optional[List[str]] = None
        # self.SamAccountName: Optional[List[str]] = None
        # self.PrivilegedAccountType: Optional[List[str]] = None
        # self.ContainMaliciousExternalIP: Optional[bool] = None
        # self.IPThreatTypes: Optional[List[str]] = None
        # self.Asset: Optional[List[str]] = None
        # self.AssetContainsFlaggedData: Optional[List[Optional[bool]]] = None
        # self.AssetContainsSensitiveData: Optional[List[Optional[bool]]] = None
        # self.Platform: Optional[List[str]] = None
        # self.FileServerOrDomain: Optional[List[str]] = None
        # self.EventUTC: Optional[datetime] = None
        # self.DeviceName: Optional[List[str]] = None
        # self.IngestTime: datetime = None

        # self.Url: str = None
        pass

    def __getitem__(self, key: str) -> Any:
        if hasattr(self.row, key):
            return getattr(self.row, key)
        raise KeyError(f"{key} not found in AlertItem")

    def to_dict(self) -> Dict[str, Any]:
        return self.row
        