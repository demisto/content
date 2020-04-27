from .triage_instance import TRIAGE_INSTANCE


class TriageReporter:
    """Class representing an end user who has reported a suspicious message"""

    def __init__(self, reporter_id):
        """Fetch data for the first matching reporter from Triage"""
        matching_reporters = TRIAGE_INSTANCE.request(f"reporters/{reporter_id}")

        if matching_reporters:
            self.attrs = matching_reporters[0]
        else:
            self.attrs = {}

    def exists(self):
        return bool(self.attrs)
