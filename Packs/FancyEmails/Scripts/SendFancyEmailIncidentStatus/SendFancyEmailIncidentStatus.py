import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

args = demisto.args()
incident = demisto.incident()
incident_headers = argToList(args.get('incident_headers'))
incident_fields = argToList(args.get('incident_fields'))
include_notes = argToBoolean(args.get('include_notes'))
banner = args.get('banner')
indicator_query = args.get('indicator_query', False)
custom_css = args.get('custom_css', '')
indicator_table_params = {
    'query': indicator_query,
    'name': args.get('indicator_table_name'),
    'use_alt_link': args.get('use_alt_link'),
    'max_name_chars': args.get('max_name_chars')
}


def make_indicator_table():
    contents = demisto.executeCommand('MakeFancyEmailIndicatorTable', indicator_table_params)[0]
    return demisto.get(contents, 'Contents.html', '')


def check_headers_and_fields_for_equal_length():
    try:
        assert len(incident_headers) == len(incident_fields)
    except AssertionError:
        raise Exception('incident_headers and incident_fields must have the same number of items')


def merge_headers_and_fields():
    """[header1, header2] + [field1, field2] -> [(header1, field1), (header2, field2)]"""
    check_headers_and_fields_for_equal_length()
    return zip(incident_headers, incident_fields)


def extract_field(field):
    standard_field = demisto.get(incident, field, None)
    custom_field = demisto.get(incident, f'CustomFields.{field}', field)
    if standard_field:
        return standard_field
    return custom_field


def make_link_to_incident(value):
    return f'<a href="{demisto.demistoUrls().get("investigation")}">{value}</a>'


headers_and_fields = merge_headers_and_fields()


def transform_incident_to_table_format():
    row_object = {}
    for header, field in headers_and_fields:
        value = extract_field(field)
        if field == 'id':
            value = make_link_to_incident(value)
        row_object[header] = value
    return row_object


def make_incident_table():
    incident_table = transform_incident_to_table_format()

    incident_table = demisto.executeCommand('fancy-email-make-table', {
        'header': incident_headers,
        'items': [incident_table],
        'name': 'Incident Details',
        'vertical_table': 'True'
    }
    )[0]
    return demisto.get(incident_table, 'Contents.html', '')


def make_notes_table():
    notes_table = demisto.executeCommand('MakeFancyEmailNotesTable', {})[0]['Contents']
    if isinstance(notes_table, dict):
        return notes_table.get('html', '')
    return ''


indicator_table = make_indicator_table() if indicator_query else ''
incident_table = make_incident_table()
notes_table = make_notes_table() if include_notes else ''

body = incident_table + notes_table + indicator_table
params = {'body': body, 'header': incident.get('name'), 'banner': banner, 'custom_css': custom_css}
email_html = demisto.executeCommand(
    'fancy-email-make-email', params)[0]["Contents"]['html']

args['htmlBody'] = email_html


demisto.executeCommand('send-mail', args)
