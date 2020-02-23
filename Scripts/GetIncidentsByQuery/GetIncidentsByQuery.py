from CommonServerPython import *
import pickle
import re
import uuid
from datetime import datetime, timedelta
from dateutil import parser


def parse_datetime(datetime_str):
    try:
        return parser.parse(datetime_str).isoformat()
    except Exception:
        return datetime_str


def parse_relative_time(datetime_str):
    try:
        res = re.search("([0-9]+) (minutes|hours|days|weeks|months|years) ago", datetime_str)
        if res:
            number = int(res.group(1))
            unit = res.group(2)
            if unit == 'years':
                unit = 'days'
                number *= 365
            elif unit == 'months':
                number *= 43800
                unit = 'minutes'

            kargs = {}
            kargs[unit] = int(number)
            result = datetime.now() - timedelta(**kargs)
            return result

    except Exception:
        return datetime_str


def get_context(incident_id):
    res = demisto.executeCommand("getContext", {'id': incident_id})
    try:
        return res[0]['Contents'].get('context') or {}
    except Exception:
        return {}


def build_incidents_query(extra_query, incident_types, time_field, from_date, to_date, non_empty_fields):
    query_parts = []
    if extra_query:
        query_parts.append(extra_query)
    if incident_types:
        types_part = "type:(%s)" % " ".join(map(lambda x: '"%s"' % x.strip(), incident_types.split(",")))
        query_parts.append(types_part)
    if from_date:
        from_part = '%s:>="%s"' % (time_field, parse_datetime(from_date))
        query_parts.append(from_part)
    if to_date:
        to_part = '%s:<"%s"' % (time_field, parse_datetime(to_date))
        query_parts.append(to_part)
    if non_empty_fields:
        non_empty_fields_part = " and ".join(map(lambda x: "%s:*" % x, non_empty_fields.split(",")))
        query_parts.append(non_empty_fields_part)
    if len(query_parts) == 0:
        return_error("Incidents query is empty - please fill one of the arguments")
    query = " and ".join(map(lambda x: "(%s)" % x, query_parts))

    return query


def get_incidents(query, time_field, size, from_date):
    args = {"query": query, "size": size, "sort": time_field}
    if time_field == "created" and from_date:
        from_datetime = None
        try:
            from_datetime = parser.parse(from_date)
        except Exception:
            pass
        if from_datetime is None and from_date.strip().endswith("ago"):
            from_datetime = parse_relative_time(from_date)
        if from_datetime:
            args['from'] = from_datetime.isoformat()
    res = demisto.executeCommand("getIncidents", args)
    if res[0]['Type'] == entryTypes['error']:
        error_message = str(res[0]['Contents'])
        return_error("Failed to get incidents by query: %s error: %s" % (query, error_message))
    incident_list = res[0]['Contents'].get('data') or []
    return incident_list


def get_comma_sep_list(value):
    return map(lambda x: x.strip(), value.split(","))


def main():
    # fetch query
    query = build_incidents_query(demisto.args().get('query'),
                                  demisto.args().get('incidentTypes'),
                                  demisto.args()['timeField'],
                                  demisto.args().get('fromDate'),
                                  demisto.args().get('toDate'),
                                  demisto.args().get('NonEmptyFields'))

    incident_list = get_incidents(query, demisto.args()['timeField'],
                                  int(demisto.args()['limit']),
                                  demisto.args().get('fromDate'))
    fields_to_populate = demisto.args().get('populateFields')
    if fields_to_populate:
        fields_to_populate = get_comma_sep_list(fields_to_populate)
        fields_to_populate += get_comma_sep_list(demisto.args().get('NonEmptyFields', ''))
        fields_to_populate = set([x for x in fields_to_populate if x])
    include_context = demisto.args()['includeContext'] == 'true'
    # extend incidents fields \ context
    new_incident_list = []
    for i in incident_list:
        # we flat the custom field to the incident structure, like in the context
        custom_fields = i.get('CustomFields', {}) or {}
        i.update(custom_fields)
        if include_context:
            i['context'] = get_context(i['id'])

        if fields_to_populate and len(fields_to_populate) > 0:
            i = {k: v for k, v in i.items() if k in fields_to_populate}
        new_incident_list.append(i)

    incident_list = new_incident_list

    # output
    file_name = str(uuid.uuid4())

    output_format = demisto.args()['outputFormat']
    if output_format == 'pickle':
        data_encoded = pickle.dumps(incident_list)
    elif output_format == 'json':
        data_encoded = json.dumps(incident_list)
    else:
        return_error("Invalid output format: %s" % output_format)
    entry = fileResult(file_name, data_encoded)
    entry['Contents'] = incident_list
    entry['HumanReadable'] = "Fetched %d incidents successfully by the query: %s" % (len(incident_list), query)
    entry['EntryContext'] = {
        'GetIncidentsByQuery': {
            'Filename': file_name,
            'FileFormat': output_format,
        }
    }
    return entry


if __name__ in ['__builtin__', '__main__']:
    entry = main()
    demisto.results(entry)
