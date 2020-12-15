import csv
import itertools
from pathlib import Path
from time import perf_counter as timer

import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401

# disable insecure warnings
urllib3.disable_warnings()

REGEX = OrderedDict()
REGEX['IP'] = ipv4Regex
REGEX['Domain'] = r'([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}'
REGEX['Email'] = emailRegex
REGEX['URL'] = urlRegex
REGEX['File'] = r'\b[a-fA-F\d]{64}|[a-fA-F\d]{40}|[a-fA-F\d]{32}|[a-fA-F\d]{128}\b'

TYPE_TO_FILENAME = OrderedDict()
TYPE_TO_FILENAME['IP'] = 'ips.csv'
TYPE_TO_FILENAME['Domain'] = 'domains.csv'
TYPE_TO_FILENAME['File'] = 'hashes.csv'


def create_run_info(batches=[], total_indicators=0, total_feed_time=0):
    return {
        "batches": batches,
        "total_indicators": total_indicators,
        "total_feed_time": total_feed_time
    }


def create_batch(size=None, time=None):
    return {
        "size": size,
        "time": time
    }


def get_indicator_type(item):
    for indicator_type, pattern in REGEX.items():
        if re.match(pattern, str(item)):
            return indicator_type
    return ''


def build_iterator(f, fieldnames, dialect):
    csvreader = csv.DictReader(
        f,
        fieldnames=fieldnames,
        **dialect
    )
    return csvreader


def good_batch(iterable, size):
    it = iter(iterable)
    while True:
        chunk = tuple(itertools.islice(it, size))
        if not chunk:
            break
        yield chunk


def generate_dbotscore(indicator, indicator_type):
    the_hash = hash(indicator)
    last_digit = abs(the_hash) % 10
    if last_digit < 5:
        score = 1
    elif last_digit < 8:
        score = 2
    else:
        score = 3
    return {
        "Indicator": indicator,
        "Type": indicator_type,
        "Vendor": "Bar Saar",
        "Score": score
    }


def main():
    if demisto.command() == 'fetch-indicators':
        indicators = []
        indicator_types = argToList(demisto.params().get('indicator_type'))

        if not indicator_types:
            indicator_types = ['IP']
        demisto.info(f'starting feed with types {indicator_types}')
        demisto.info(f'starting feed with types {len(indicator_types)} size')
        for indicator_type in indicator_types:
            csv_file = TYPE_TO_FILENAME[indicator_type]
            indicators_csv_file = open(Path('/perf/' + csv_file), newline='')
            fieldnames = argToList(demisto.params().get('fieldnames'))
            dialect = {
                'delimiter': demisto.params().get('delimiter', ','),
                'doublequote': demisto.params().get('doublequote', True),
                'escapechar': demisto.params().get('escapechar', None),
                'quotechar': demisto.params().get('quotechar', '"'),
                'skipinitialspace': demisto.params().get('skipinitialspace', False)
            }
            iterator = build_iterator(indicators_csv_file, fieldnames, dialect)
            for item in iterator:
                if 'indicator' in item:
                    raw_json = dict(item)
                    raw_json['value'] = indicator = item.get('indicator')
                    raw_json['type'] = indicator_type
                    indicators.append({
                        "value": indicator,
                        "type": indicator_type,
                        "rawJSON": raw_json,
                    })
                else:
                    raise Exception(INDICATOR_COLUMN_ERROR)

            batch_size = int(demisto.params().get('batch_size'))
            batches = []
            feed_start = timer()
            indicators = indicators[:int(demisto.params().get('amount_inidcators'))]
            demisto.info(f'starting feed of {len(indicators)} size')
            for b in good_batch(indicators, batch_size):
                batch_start = timer()
                demisto.createIndicators(b)
                batch_end = timer()
                batch_time = batch_end - batch_start
                batch_info = create_batch(len(b), batch_time)
                batches.append(batch_info)
            feed_end = timer()
            demisto.info('finished feed')
            feed_total_time = feed_end - feed_start
            run_info = create_run_info(batches, len(indicators), feed_total_time)
            incidents = [{"name": demisto.params().get('incidents_name'), "type": "Access", "details": json.dumps(run_info)}]
            demisto.createIncidents(incidents)
            integ_context = demisto.getIntegrationContext() or {}
            runs = integ_context.get('runs') or []
            runs.append(run_info)
            integ_context['runs'] = runs
            integ_context['indicators'] = indicators
            demisto.setIntegrationContext(integ_context)
    elif demisto.command() == 'random-score-indicators':
        indicators = argToList(demisto.args().get('indicators')) or []
        dbot_scores = [generate_dbotscore(i, get_indicator_type(i)) for i in indicators]
        ec = {}
        ec['DBotScore'] = dbot_scores
        md = tableToMarkdown("Indicator DBot Score", ec["DBotScore"])
        demisto.results({
            "Type": entryTypes["note"],
            "ContentsFormat": formats["json"],
            "Contents": ec,
            "HumanReadable": md,
            "EntryContext": ec
        })


# python2 uses __builtin__ python3 uses builtin s
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
