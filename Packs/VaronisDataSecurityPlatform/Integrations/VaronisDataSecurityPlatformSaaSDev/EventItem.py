from CommonServerPython import Any, Dict, List, Optional, datetime


from typing import Any, Dict, List


class EventItem:
    def __init__(self, row: dict):
        self.row = row
        # self.Id: Optional[str] = None
        # self.AlertId: Optional[List[str]] = None
        # self.Type: Optional[str] = None
        # self.TimeUTC: Optional[datetime] = None
        # self.Status: Optional[str] = None
        # self.Description: Optional[str] = None
        # self.Country: Optional[str] = None
        # self.State: Optional[str] = None
        # self.BlacklistedLocation: Optional[bool] = None
        # self.EventOperation: Optional[str] = None
        # self.ByUserAccount: Optional[str] = None
        # self.ByUserAccountType: Optional[str] = None
        # self.ByUserAccountDomain: Optional[str] = None
        # self.BySamAccountName: Optional[str] = None
        # self.Filer: Optional[str] = None
        # self.Platform: Optional[str] = None
        # self.SourceIP: Optional[str] = None
        # self.ExternalIP: Optional[str] = None
        # self.DestinationIP: Optional[str] = None
        # self.SourceDevice: Optional[str] = None
        # self.DestinationDevice: Optional[str] = None
        # self.IsDisabledAccount: Optional[bool] = None
        # self.IsLockoutAccount: Optional[bool] = None
        # self.IsStaleAccount: Optional[bool] = None
        # self.IsMaliciousIP: Optional[bool] = None
        # self.ExternalIPThreatTypes: Optional[List[str]] = None
        # self.ExternalIPReputation: Optional[str] = None
        # self.OnObjectName: Optional[str] = None
        # self.OnObjectType: Optional[str] = None
        # self.OnSamAccountName: Optional[str] = None
        # self.IsSensitive: Optional[bool] = None
        # self.OnAccountIsDisabled: Optional[bool] = None
        # self.OnAccountIsLockout: Optional[bool] = None
        # self.Path: Optional[str] = None

    def __getitem__(self, key: str) -> Any:
        if hasattr(self.row, key):
            return getattr(self.row, key)
        raise KeyError(f"{key} not found in AlertItem")

    def to_dict(self) -> Dict[str, Any]:
        return self.row