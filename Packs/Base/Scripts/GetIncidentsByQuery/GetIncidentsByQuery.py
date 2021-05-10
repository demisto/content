from CommonServerPython import *

import pickle
import uuid
from dateutil import parser

PREFIXES_TO_REMOVE = ['incident.']
PAGE_SIZE = int(demisto.args().get('pageSize', 500))
PYTHON_MAGIC = "$$##"


def parse_datetime(datetime_str):
    try:
        return parser.parse(datetime_str).isoformat()
    except Exception:
        return datetime_str


def parse_relative_time(datetime_str):
    if datetime_str:
        datetime_str = datetime_str.lower()
        try:
            res = re.search("([0-9]+) (minute|minutes|hour|hours|day|days|week|weeks|month|months|year|years) ago",
                            datetime_str)
            if res:
                number = int(res.group(1))
                unit = res.group(2)
                if unit in ['minute', 'hour', 'day', 'week', 'month', 'year']:
                    unit += "s"
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
            return None


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
        types = ['"{}"'.format(x.strip()) if '*' not in x else '{}'.format(x.strip())
                 for x in incident_types.split(",")]
        types_part = "type:({})".format(' '.join(types))
        query_parts.append(types_part)
    if from_date:
        from_part = '%s:>="%s"' % (time_field, parse_datetime(from_date))
        query_parts.append(from_part)
    if to_date:
        to_part = '%s:<"%s"' % (time_field, parse_datetime(to_date))
        query_parts.append(to_part)
    if len(non_empty_fields) > 0:
        non_empty_fields_part = " and ".join("{}:*".format(x) for x in non_empty_fields)
        query_parts.append(non_empty_fields_part)
    if len(query_parts) == 0:
        raise Exception("Incidents query is empty - please fill one of the arguments")
    query = " and ".join('({})'.format(x) for x in query_parts)
    return query


def handle_incident(inc, fields_to_populate, include_context):
    # we flat the custom field to the incident structure, like in the context
    custom_fields = inc.get('CustomFields', {}) or {}
    inc.update(custom_fields)
    if fields_to_populate and len(fields_to_populate) > 0:
        inc = {k: v for k, v in inc.items() if k in fields_to_populate}
    if include_context:
        inc['context'] = get_context(inc['id'])
    return inc


def is_incident_contains_python_magic(inc):
    return PYTHON_MAGIC in json.dumps(inc)


def get_fields_to_populate_arg(fields_to_populate):
    incidents_fields_to_populate = []
    for field in fields_to_populate:
        if "." in field:
            # handle complex field case
            incidents_fields_to_populate.append(field[:field.find(".")])
        else:
            incidents_fields_to_populate.append(field)
    return ",".join(incidents_fields_to_populate)


def get_incidents_by_page(args, page, fields_to_populate, include_context):
    args['page'] = page
    if is_demisto_version_ge('6.2.0') and len(fields_to_populate) > 0:
        args['populateFields'] = get_fields_to_populate_arg(fields_to_populate)
    res = demisto.executeCommand("getIncidents", args)
    if res[0]['Contents'].get('data') is None:
        return []
    if is_error(res):
        error_message = get_error(res)
        raise Exception("Failed to get incidents by query args: %s error: %s" % (args, error_message))
    incidents = res[0]['Contents'].get('data') or []

    parsed_incidents = []
    for inc in incidents:
        new_incident = handle_incident(inc, fields_to_populate, include_context)
        if is_incident_contains_python_magic(new_incident):
            demisto.debug("Warning: skip incident [id:%s] that contains python magic" % str(inc['id']))
            continue
        parsed_incidents.append(new_incident)
    return parsed_incidents


def get_demisto_datetme_format(date_string):
    if date_string:
        date_object = None
        # try to parse date string
        try:
            date_object = parser.parse(date_string)
        except Exception:
            pass
        # try to parse relative time
        if date_object is None and date_string.strip().endswith("ago"):
            date_object = parse_relative_time(date_string)

        if date_object:
            return date_object.astimezone().isoformat('T')
        else:
            return None


def get_incidents(query, time_field, size, from_date, to_date, fields_to_populate, include_context):
    query_size = min(PAGE_SIZE, size)
    args = {"query": query, "size": query_size, "sort": "%s.%s" % (time_field, "desc")}
    # apply only when created time field
    if time_field == 'created':
        if from_date:
            from_datetime = get_demisto_datetme_format(from_date)
            if from_datetime:
                args['fromdate'] = from_datetime
            else:
                demisto.results("did not set from date due to a wrong format: " + from_date)

        if to_date:
            to_datetime = get_demisto_datetme_format(to_date)
            if to_datetime:
                args['todate'] = to_datetime
            else:
                demisto.results("did not set to date due to a wrong format: " + from_date)

    incident_list = []  # type: ignore
    page = 0
    while len(incident_list) < size:
        incidents = get_incidents_by_page(args, page, fields_to_populate, include_context)
        if not incidents:
            break
        incident_list += incidents
        page += 1
    return incident_list[:size]


def get_comma_sep_list(value):
    return map(lambda x: x.strip(), value.split(","))


def preprocess_incidents_fields_list(incidents_fields):
    res = []
    for field in incidents_fields:
        field = field.strip()
        for prefix in PREFIXES_TO_REMOVE:
            if field.startswith(prefix):
                field = field[len(prefix):]
            res.append(field)
    return res


def main():
    try:
        # fetch query
        d_args = dict(demisto.args())
        for arg_name in ['NonEmptyFields', 'populateFields']:
            split_argument_list = get_comma_sep_list(d_args.get(arg_name, ''))
            split_argument_list = [x for x in split_argument_list if len(x) > 0]
            d_args[arg_name] = preprocess_incidents_fields_list(split_argument_list)
        query = build_incidents_query(d_args.get('query'),
                                      d_args.get('incidentTypes'),
                                      d_args['timeField'],
                                      d_args.get('fromDate'),
                                      d_args.get('toDate'),
                                      d_args.get('NonEmptyFields'))
        fields_to_populate = d_args.get('populateFields')  # type: ignore
        if len(fields_to_populate) > 0:  # type: ignore
            fields_to_populate += d_args['NonEmptyFields']
            fields_to_populate.append('id')
            fields_to_populate = set([x for x in fields_to_populate if x])  # type: ignore
        include_context = d_args['includeContext'] == 'true'
        incidents = get_incidents(query, d_args['timeField'],
                                  int(d_args['limit']),
                                  d_args.get('fromDate'),
                                  d_args.get('toDate'),
                                  fields_to_populate,
                                  include_context)

        # output
        file_name = str(uuid.uuid4())
        output_format = d_args['outputFormat']
        if output_format == 'pickle':
            data_encoded = pickle.dumps(incidents, protocol=2)
        elif output_format == 'json':
            data_encoded = json.dumps(incidents)  # type: ignore
        else:
            raise Exception("Invalid output format: %s" % output_format)

        entry = fileResult(file_name, data_encoded)
        entry['Contents'] = incidents
        entry['HumanReadable'] = "Fetched %d incidents successfully by the query: %s" % (len(incidents), query)
        entry['EntryContext'] = {
            'GetIncidentsByQuery': {
                'Filename': file_name,
                'FileFormat': output_format,
            }
        }
        return entry
    except Exception as e:
        return_error(str(e))


if __name__ in ['builtins', '__main__']:
    entry = main()
    demisto.results(entry)
