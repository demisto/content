import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

args = demisto.args()
incident = demisto.incident()
incident_headers = argToList(args.get('incident_headers'))
incident_fields = argToList(args.get('incident_fields'))


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
    custom_field = demisto.get(incident, f'CustomField.{field}')
    if standard_field:
        return standard_field
    return custom_field


headers_and_fields = merge_headers_and_fields()


def transform_incident_to_table_format():
    row_object = {}
    for header, field in headers_and_fields:
        row_object[header] = extract_field(field)
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


return_results(make_incident_table())
