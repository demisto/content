from CommonServerPython import fileResult

import functools
import json

from .triage_reporter import TriageReporter


class TriageReport:
    """Class representing a Triage report by an end-user of a suspicious message"""

    def __init__(self, attrs):
        self.attrs = attrs

    @property
    def id(self):
        return self.attrs["id"]

    @property
    def date(self):
        return self.attrs.get("created_at")

    @property
    def category_name(self):
        pass

    @property
    def severity(self):
        pass

    @property
    def report_body(self):
        return self.attrs.get("report_body")

    @property
    @functools.lru_cache()
    def reporter(self):
        return TriageReporter(self.attrs["reporter_id"])

    def to_json(self):
        """Flatten the Reporter object to a set of `reporter_` prefixed attributes"""
        return {
            **self.attrs,
            **{f"reporter_{k}": v for k, v in self.reporter.attrs},
        }

    @property
    @functools.lru_cache()
    def attachment(self):
        # TODO case-insensitive?
        if "HTML" in self.report_body:
            html_attachment = fileResult(
                filename=f"{self.id}-report.html", data=self.report_body.encode()
            )
            attachment = {
                "path": html_attachment.get("FileID"),
                "name": html_attachment.get("FileName"),
            }
            return attachment

        return None

    @classmethod
    def from_json(cls, json_str):
        return cls(json.loads(json_str))
