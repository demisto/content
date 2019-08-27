import demistomock as demisto
from CommonServerPython import *
import json
from datetime import datetime


def get_datetime_object(wanted_date):
    """ Convert a string that is representing a date into a datetime object.

    Args:
        wanted_date(string): representation of a date.

    Returns:
        datetime. representation of a date.
    """
    if '+' in wanted_date[-6:] or '-' in wanted_date[-6:]:
        new_required_date = datetime.strptime(wanted_date[:-6], '%Y-%m-%dT%H:%M:%S.%f')

    else:
        new_required_date = datetime.strptime(wanted_date, '%Y-%m-%dT%H:%M:%SZ')

    return new_required_date


def calclulate_week_amount(from_date, to_date, now_time):
    if to_date - from_date > to_date - to_date:
        week_amount = (to_date - from_date).days / 7 + 1
    else:
        week_amount = (now_time - from_date.date()).days / 7 + 1

    return week_amount


def calc_incidents_counter(now_time, res, week_amount):
    incidents_count = {}  # type: dict
    incidents = res[0]['Contents']['data']
    for incident in incidents:
        created = incident.get('created')
        created, timezone = created.split('+')

        if timezone:
            # We need to decrease the timezone from the time to get UTC
            multiplication_param = -1
        else:
            # We need to increase the timezone from the time to get UTC
            created, timezone = created.rsplit('-', 1)
            multiplication_param = 1

        created_at = datetime.strptime(created, '%Y-%m-%dT%H:%M:%S.%f')
        created_at = created_at + multiplication_param * timedelta(hours=int(timezone[:2]), minutes=int(timezone[3:]))

        for i in range(week_amount):
            if (now_time - timedelta(weeks=1 * (i - 1), days=now_time.weekday())) > created_at.date() >= \
                    (now_time - timedelta(weeks=1 * i, days=now_time.weekday())):
                incidents_count[i] = incidents_count.get(i, 0) + 1

    return incidents_count


def main():
    res = demisto.executeCommand("getIncidents", {
        'query': '-category:job',
        "fromdate": demisto.args().get("from"),
        "todate": demisto.args().get("to")
    })

    from_date = get_datetime_object(demisto.args().get("from"))
    to_date = get_datetime_object(demisto.args().get("to"))
    now_time = datetime.now().date()

    week_amount = calclulate_week_amount(from_date, to_date, now_time)

    incidents_count = calc_incidents_counter(now_time, res, week_amount)

    data = []  # type: list
    for key in sorted(incidents_count.keys()):
        incident_dict = {
            "name": (now_time - timedelta(weeks=key, days=now_time.weekday())).strftime("%Y-%m-%d"),
            "data": [incidents_count[key]],
            "groups": [{
                "name": "Unclassified",
                "data": [incidents_count[key]]
            }]
        }
        data.insert(0, incident_dict)

    demisto.results(json.dumps(data))


if __name__ == '__main__':
    main()
