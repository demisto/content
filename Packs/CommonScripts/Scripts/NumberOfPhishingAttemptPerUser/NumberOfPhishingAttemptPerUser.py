from typing import Tuple

from CommonServerPython import *


def get_default_from_date(date_range: str) -> str:
    """
    Gets a range string (eg. 30 days) and return a date string in the relevant Demisto query format.
    :param date_range: string
        Range (eg. 2 months) to create the date string from
    :return: string
        Date string in the relevant Demisto query format, e.g: 2016-01-02T15:04:05Z.
    """
    from_date, _ = parse_date_range(date_range=date_range)
    str_from_date = from_date.strftime('%Y-%m-%dT%H:%M:%SZ')
    return str_from_date


def get_relevant_incidents(email_to, email_from, from_date) -> Tuple[int, int]:
    """
    Gets a email to and from addresses, and a date from string.
    :param email_to: string
        email to address
    :param email_from: string
        email from address
    :param from_date: string
        Date string in the relevant Demisto query format
    :return: int, int
        number of relevant to and from incidents
    """
    resp = demisto.executeCommand("getIncidents",
                                  {"query": f"email_to:{email_to} --status:Closed fromdate: {from_date}"})
    if isError(resp[0]):
        raise Exception(resp)
    email_to_total = demisto.get(resp[0], "Contents.total")

    resp = demisto.executeCommand("getIncidents",
                                  {"query": f"email_from:{email_from} --status:Closed fromdate: {from_date}"})
    if isError(resp[0]):
        raise Exception(resp)
    email_from_total = demisto.get(resp[0], "Contents.total")

    return email_to_total, email_from_total


def create_widget_entry(email_to, email_from, email_to_total, email_from_total) -> dict:
    """
    Gets a email to and from addresses, and a to and from total incidents number.
    :param email_to: string
        email to address
    :param email_from: string
        email from address
    :param email_to_total: int
        email to relevant total incidents
    :param email_from_total: int
        email from relevant total incidents
    :return: data
        the relevant bar table
    """
    data = {
        "Type": 17,
        "ContentsFormat": "bar",
        "Contents": {
            "stats": [
                {
                    "data": [
                        email_to_total
                    ],
                    "groups": None,
                    "name": str(email_to),
                    "label": f"To: {str(email_to)}",
                    "color": "rgb(255, 23, 68)"
                },
                {
                    "data": [
                        email_from_total
                    ],
                    "groups": None,
                    "name": str(email_from),
                    "label": f"From: {str(email_from)}",
                    "color": "rgb(255, 144, 0)"
                }
            ],
            "params": {
                "layout": "vertical"
            }
        }
    }

    return data


def main():
    try:
        # Get current incident data
        email_to = demisto.get(demisto.incidents()[0], 'CustomFields.email_to')
        email_from = demisto.get(demisto.incidents()[0], 'CustomFields.email_from')
        if not (email_to and email_from):
            demisto.results("None")
        else:
            default_from_date = get_default_from_date('30 days')
            email_to_total, email_from_total = get_relevant_incidents(email_to, email_from, default_from_date)
            data = create_widget_entry(email_to, email_from, email_to_total, email_from_total)
            demisto.results(data)
    except Exception as err:
        return_error(str(err))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
