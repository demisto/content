from CommonServerPython import fileResult

import functools
import json

from .triage_instance import TRIAGE_INSTANCE
from .triage_reporter import TriageReporter


TERSE_FIELDS = [
    'id',
    'cluster_id',
    'reporter_id',
    'location',
    'created_at',
    'reported_at',
    'report_subject',
    'report_body',
    'md5',
    'sha256',
    'category_id',
    'match_priority',
    'tags',
    'email_attachments',
]


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
        return {
            1: 'Non-Malicious',
            2: 'Spam',
            3: 'Crimeware',
            4: 'Advanced Threats',
            5: 'Phishing Simulation',
            # TODO is this still complete?
        }.get(self.attrs["category_id"], "Unknown")

    @property
    def severity(self):
        # Demisto's severity levels are 4 - Critical, 3 - High, 2 - Medium, 1 - Low, 0 - Unknown
        return {
            1: 1,  # non malicious -> low
            2: 0,  # spam -> unknown
            3: 2,  # crimeware -> medium
            4: 2,  # advanced threats -> medium
            5: 1,  # phishing simulation -> low
        }.get(self.attrs["category_id"], 0)

    @property
    def report_body(self):
        return self.attrs.get("report_body")

    @property
    @functools.lru_cache()
    def reporter(self):
        return TriageReporter(self.attrs["reporter_id"])

    @property
    def terse_attrs(self):
        return {key: self.attrs[key] for key in self.attrs.keys() & TERSE_FIELDS}

    def to_json(self):
        """Flatten the Reporter object to a set of `reporter_` prefixed attributes"""
        return {
            **self.attrs,
            **{f"reporter_{k}": v for k, v in self.reporter.attrs.items()},
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

    @classmethod
    def from_id(cls, report_id):
        return cls(TRIAGE_INSTANCE.request(f"reports/{report_id}"))
