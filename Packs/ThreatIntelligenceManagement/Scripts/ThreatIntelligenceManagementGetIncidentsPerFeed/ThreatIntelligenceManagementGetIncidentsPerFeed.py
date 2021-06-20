import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


def get_default_from_date(date_range: str) -> str:
    """
    Gets a range string (eg. 30 days) and return a date string in the relevant Demisto query format.
    :param date_range: string
        Range (eg. 2 months) to create the date string from
    :return: string
        Date string in the relevant Demisto query format.
    """
    from_date, _ = parse_date_range(date_range=date_range)
    str_from_date = from_date.strftime('%Y-%m-%dT%H:%M:%SZ')
    return str_from_date


def get_all_incidents(from_date: str) -> list:
    """
    Query all incidents starting a given date.
    :param from_date: string
        The date to query incidents from.
    :return: list
        List of incidents.
    """
    command_res = demisto.executeCommand('getIncidents', {'fromdate': from_date})
    if is_error(command_res):
        return_error(f'Error executing "getIncidents fromdate: {from_date}":\n{command_res}')
    contents = command_res[0]['Contents']
    incidents = contents['data']
    size = len(incidents)
    total = contents['total']
    page = 1

    while total > size:
        command_res = demisto.executeCommand('getIncidents', {'fromdate': from_date, 'page': page})
        if is_error(command_res):
            return_error(f'Error executing "getIncidents fromdate: {from_date}":\n{command_res}')
        contents = command_res[0]['Contents']
        new_incidents = contents['data']
        incidents += new_incidents
        size = len(incidents)
        page += 1

    return incidents


def get_feeds_for_incident(incident_id: int) -> set:
    """
    Retrieves a list feeds based on indicators that appear in a given incident.
    :param incident_id: int
        Incident ID to query by.
    :return: set
        List of feeds that have indicators in the given incident.
    """
    indicator_query = f'sourceBrands:*Feed* and incident.id:{incident_id}'
    search_indicators = IndicatorsSearcher()
    fetched_iocs = search_indicators.search_indicators_by_version(query=indicator_query).get('iocs')
    feeds = set()
    for indicator in fetched_iocs:
        source_brands = indicator.get('sourceBrands')
        for brand in source_brands:
            if 'Feed' in brand:
                feeds.add(brand)
    return feeds


def sum_number_of_feeds_for_an_incident(incident_id: int, feed_counter: dict):
    """
    Counts the number of feeds that are related to a given incident (due to indicators that appear in the incident)
    :param incident_id: int
        the incident ID to count the feeds for.
    :param feed_counter: dict
        The general dictionary that holds all the sums.
    """
    feeds = get_feeds_for_incident(incident_id)
    for feed in feeds:
        feed_counter[feed] = feed_counter.get(feed, 0) + 1


def get_incidents_per_feed(from_date: str) -> dict:
    """
    Counts the number of feeds that are related to all incidents created since a given date (due to indicators that
    appear in the incident)
    :param from_date: string
        The date to starty query incidents from.
    :return: dict
        Dictionary with feeds as keys and related incident count as values
    """
    all_incidents = get_all_incidents(from_date)
    feed_counter: dict = {}
    for incident in all_incidents:
        incident_id = incident.get('investigationId')
        sum_number_of_feeds_for_an_incident(incident_id, feed_counter)
    return feed_counter


def main():
    default_from_date = get_default_from_date('30 days')
    from_date = demisto.args().get('from', default_from_date)
    data = get_incidents_per_feed(from_date)
    demisto.results({
        'total': len(data),
        'data': [{
            'Feed Name': key,
            'Number Of Incidents': val
        } for key, val in data.items()]})


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
