import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import uuid

STANDARD_TIME_ZONE = "Europe/Berlin"

ICAL_DATA = """
BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Palo Alto Networks/XSOAR
BEGIN:VEVENT
UID:{UID}
ORGANIZER;CN=XSOAR:MAILTO:noreply@xsoar
DTSTART;TZID={START_TIME_ZONE}:{START_YEAR}{START_MONTH}{START_DAY}T{START_HOUR}{START_MINUTE}00Z
DTEND;TZID={START_TIME_ZONE}:{END_YEAR}{END_MONTH}{END_DAY}T{END_HOUR}{END_MINUTE}00Z
SUMMARY:{TITLE}
DESCRIPTION:{DESCRIPTION}
URL:{URL}
END:VEVENT
END:VCALENDAR
"""


def _find_incident_url() -> str:
    incident = demisto.incident()
    if incident:
        server_url = demisto.executeCommand("GetServerURL", {})[0].get('Contents')
        return f"{server_url}/#/Custom/caseinfoid/{incident.get('id')}"
    else:
        return ""


def _uid() -> str:
    incident = demisto.incident()
    if incident:
        return f"xsoar_ical_{incident.get('id')}"
    else:
        return str(uuid.uuid4())


def _date_components(date: str):
    str_components = date.split("/")
    if len(str_components[0]) != 4:
        raise ValueError(f"Year must be 4 digits, received {str_components[0]}")
    return int(str_components[0]), int(str_components[1]), int(str_components[2])


def _time_components(time: str):
    str_components = time.split(":")
    return int(str_components[0]), int(str_components[1])


def _create_ical(title: str, start_date: str, start_time: str, end_date: str, end_time: str, description: str = "", url: str = "", uid: str = "", start_time_zone: str = STANDARD_TIME_ZONE, end_time_zone: str = STANDARD_TIME_ZONE) -> str:  # noqa: E501
    start_year, start_month, start_day = _date_components(date=start_date)
    end_year, end_month, end_day = _date_components(date=end_date)
    start_hour, start_minute = _time_components(time=start_time)
    end_hour, end_minute = _time_components(time=end_time)
    if len(uid) == 0:
        uid = _uid()
    if len(url) == 0:
        url = _find_incident_url()
    ical_string = ICAL_DATA.format(START_YEAR=start_year,
                                   START_MONTH=start_month,
                                   START_DAY=start_day,
                                   START_HOUR=start_hour,
                                   START_MINUTE=start_minute,
                                   END_YEAR=end_year,
                                   END_MONTH=end_month,
                                   END_DAY=end_day,
                                   END_HOUR=end_hour,
                                   END_MINUTE=end_minute,
                                   TITLE=title,
                                   DESCRIPTION=description,
                                   URL=url,
                                   UID=uid,
                                   START_TIME_ZONE=start_time_zone,
                                   END_TIME_ZONE=end_time_zone)
    return ical_string


def main():
    title = demisto.args().get("title")
    start_date = demisto.args().get("start_date")
    start_time = demisto.args().get("start_time")
    start_time_zone = demisto.args().get("start_time_zone", STANDARD_TIME_ZONE)
    end_date = demisto.args().get("end_date")
    end_time = demisto.args().get("end_time")
    end_time_zone = demisto.args().get("end_time_zone", STANDARD_TIME_ZONE)
    description = demisto.args().get("description", "")
    url = demisto.args().get("url", "")
    uid = demisto.args().get("uid", "")

    ical_string = _create_ical(title=title, start_date=start_date, start_time=start_time, end_date=end_date, end_time=end_time, description=description, url=url, uid=uid, start_time_zone=start_time_zone, end_time_zone=end_time_zone)  # noqa: E501
    file_entry = fileResult(
        filename="xsoar.ics",
        data=ical_string,
        file_type=EntryType.ENTRY_INFO_FILE,
    )

    return_results(file_entry)


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
