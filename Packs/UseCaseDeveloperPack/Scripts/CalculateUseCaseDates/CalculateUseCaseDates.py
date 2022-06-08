import traceback
from datetime import timedelta
from math import ceil
from typing import Any, Dict

import demistomock as demisto  # noqa: F401
import pytz
from CommonServerPython import *  # noqa: F401
from dateutil.parser import parse


def first_business_day(input_date):
    date_offset = timedelta(days=0)

    if input_date.isoweekday() == 6:
        date_offset = timedelta(days=2)
    elif input_date.isoweekday() == 7:
        date_offset = timedelta(days=1)

    return date_offset


def get_dates(start_date_obj, days):

    date_offset = first_business_day(start_date_obj)
    begin_date = start_date_obj + date_offset
    end_date = begin_date + timedelta(days)

    return begin_date.isoformat(), end_date.isoformat()


def calculate_dates(start_date, incident_id, complexity, field_filter):

    SIMPLE_MODIFIER = .5
    STANDARD_MODIFIER = 1
    COMPLEX_MODIFIER = 1.5
    HIGHLY_COMPLEX_MODIFIER = 2

    base_row = {}

    if complexity == "Simple":
        modifier = SIMPLE_MODIFIER
    elif complexity == "Complex":
        modifier = COMPLEX_MODIFIER
    elif complexity == "HighlyComplex":
        modifier = HIGHLY_COMPLEX_MODIFIER
    else:
        modifier = STANDARD_MODIFIER

    eastern = pytz.timezone('US/Eastern')
    start_date_off = (parse(start_date)).replace(tzinfo=eastern)
    start_date_obj = start_date_off.date()

    # Eval Dates
    if 'evaluation' in field_filter:
        begin, end = get_dates(start_date_obj, 14)
        base_row['evaluationstart'] = begin
        base_row['evaluationend'] = end

    # Customer Consult Dates
    if 'consult' in field_filter:
        if 'evaluationend' in base_row:
            start_date_obj = parse(base_row['evaluationend']) + timedelta(days=1)
        begin, end = get_dates(start_date_obj, 14)
        base_row['customerconsultstart'] = begin
        base_row['customerconsultend'] = end

    # Development Dates
    if 'development' in field_filter:
        if 'customerconsultend' in base_row:
            start_date_obj = parse(base_row['customerconsultend']) + timedelta(days=1)
        begin, end = get_dates(start_date_obj, ceil(30 * modifier))
        base_row['developmentstart'] = begin
        base_row['developmentend'] = end

    # User Acceptance Testing Dates
    if 'useracceptance' in field_filter:
        if 'developmentend' in base_row:
            start_date_obj = parse(base_row['developmentend']) + timedelta(days=1)
        begin, end = get_dates(start_date_obj, ceil(14 * modifier))
        base_row['useracceptancetestingstart'] = begin
        base_row['useracceptancetestingend'] = end

    # Reporting Dates
    if 'reporting' in field_filter:
        if 'useracceptancetestingend' in base_row:
            start_date_obj = parse(base_row['useracceptancetestingend']) + timedelta(days=1)
        begin, end = get_dates(start_date_obj, ceil(4 * modifier))
        base_row['reportingstart'] = begin
        base_row['reportingend'] = end

    # Deployment Dates
    if 'deployment' in field_filter:
        if 'reportingend' in base_row:
            start_date_obj = parse(base_row['reportingend']) + timedelta(days=1)
        begin, end = get_dates(start_date_obj, ceil(4 * modifier))
        base_row['deploymentstart'] = begin
        base_row['deploymentend'] = end

    # Verify Dates
    if 'verify' in field_filter:
        if 'deploymentend' in base_row:
            start_date_obj = parse(base_row['deploymentend']) + timedelta(days=1)
        begin, end = get_dates(start_date_obj, ceil(14 * modifier))
        base_row['verifystart'] = begin
        base_row['verifyend'] = end

    return base_row


def calculate_command(args: Dict[str, Any]) -> CommandResults:

    start_date = args.get('start_date')
    incident_id = args.get('incident_id')
    complexity = args.get('complexity')
    field_filter = args.get('filter')
    append = args.get('append', "true")

    if not incident_id:
        incident_id = demisto.incident().get('id')

    if not start_date:
        raise ValueError('start_date not specified')

    # Call the standalone function and get the raw response
    new_row = calculate_dates(start_date, incident_id, complexity, field_filter)

    # Add row if this is not the first calculation
    try:
        currentValue = demisto.incidents()[-1]["CustomFields"]["processdevelopmentdates"]
    except Exception as ex:
        demisto.setContext("incident.processdevelopmentdates", None)
        currentValue = None

    if currentValue is None:
        currentValue = new_row
    elif append == 'false':
        currentValue = new_row
    else:
        currentValue.append(new_row)

    val = json.dumps({"processdevelopmentdates": currentValue})

    demisto.executeCommand("setIncident", {'customFields': val})
    return val


def main():
    try:
        # TODO: replace the invoked command function with yours
        return_results(calculate_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute CalculateUseCaseDates. Error: {str(ex)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
