import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

def get_default_from_date(date_range):
    from_date, _ = parse_date_range(date_range=date_range)
    str_from_date = from_date.strftime('%Y-%m-%dT%H:%M:%SZ')
    return str_from_date


def get_all_incidents(from_date):
    # from_date = '2020-03-26T00:00:00Z'
    cmd_res = demisto.executeCommand("getIncidents", {"fromdate": from_date})[0]['Contents']['data']
    # print(json.dumps(cmd_res))
    return cmd_res


def get_feeds_for_incident(incident_id):
    indicator_query = f'sourceBrands:*Feed* incident.id:{incident_id}'
    fetched_iocs = demisto.searchIndicators(query=indicator_query).get('iocs')
    feeds = set()
    for indicator in fetched_iocs:
        source_brands = indicator.get('sourceBrands')
        [feeds.add(brand) for brand in source_brands if 'Feed' in brand]
    return feeds


def sum_number_of_feeds_for_an_incident(incident_id, feed_counter):
    feeds = get_feeds_for_incident(incident_id)
    for feed in feeds:
        feed_counter[feed] = feed_counter.get(feed, 0) + 1


def get_incidents_per_feed(from_date):
    all_incidents = get_all_incidents(from_date)
    feed_counter = {}
    for incident in all_incidents:
        incident_id = incident.get('investigationId')
        sum_number_of_feeds_for_an_incident(incident_id, feed_counter)
    return feed_counter


# fetched_iocs = demisto.searchIndicators(query='sourceBrands:*Feed* incident.id:*')['iocs']
# demisto.results({'iocs': fetched_iocs})
# feed_counter = {}
# sum_number_of_feeds_for_an_incident('87217', feed_counter)

default_from_date = get_default_from_date('30 days')
from_date = demisto.args().get('from', default_from_date)
data = get_incidents_per_feed(from_date)
demisto.results({
    'total': len(data),
    'data': [{
        'Feed Name': key,
        'Number Of Incidents': val
    } for key, val in data.items()]})
demisto.results('Done')
