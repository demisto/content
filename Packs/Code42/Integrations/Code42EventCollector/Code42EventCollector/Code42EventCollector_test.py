import pytest

from CommonServerPython import *

from unittest.mock import MagicMock


class HttpRequestsMocker:

    def __init__(self, num_of_events: int):
        self.num_of_events = num_of_events
        self.num_of_calls = 0

    def valid_http_request_side_effect(self, method: str, url_suffix: str = "", params: Dict | None = None, **kwargs):
        if method == "GET" and url_suffix == "/api/v2/reports":
            start_date = params.get("start-date")
            events = create_events(1, amount_of_events=self.num_of_events, start_date=start_date)
            return create_mocked_response(events)
        if method == "POST" and kwargs.get("full_url") == "https://auth.cybelangel.com/oauth/token":
            return {"access_token": "new_access_token"}
        return None