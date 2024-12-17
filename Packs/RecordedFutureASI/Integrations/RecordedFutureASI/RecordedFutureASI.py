import demistomock as demisto
from CommonServerUserPython import *  # noqa
from CommonServerPython import *

import time
import urllib3
import traceback
from abc import ABC
from datetime import datetime
from collections import defaultdict
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()

''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%d %H:%M:%S'
DEFAULT_HOST_LIMIT = 200
DEFAULT_MIN_SEVERITY = 'Moderate'
CRITICALITY_TITLES = {
    'informational': 'Informational',
    'moderate': 'Moderate',
    'high': 'Critical'
}
SEVERITY_MAPPINGS = {
    'informational': IncidentSeverity.LOW,
    'moderate': IncidentSeverity.MEDIUM,
    'high': IncidentSeverity.CRITICAL
}
MIN_SEVERITY_MAPPING = {
    'Informational': 'high,moderate,informational',
    'Moderate': 'high,moderate',
    'Critical': 'high'
}

''' CLIENT CLASS '''


class Client(BaseClient):
    def __init__(self, *args,
                 project_id: str = None,
                 min_severity: str = DEFAULT_MIN_SEVERITY,
                 host_incident_limit: int = DEFAULT_HOST_LIMIT,
                 **kwargs):
        """
        Client subclass to handle API calls to the ASI API

        :param project_id: the project_id to scope the API calls to
        :param min_severity: the minimum rule severity to check for changes
        :param host_incident_limit: the max number of host incidents to return
        """
        super().__init__(*args, **kwargs)
        self.project_id = project_id
        self.min_severity = min_severity
        self.host_incident_limit = host_incident_limit

    def get_project_issues(self, snapshot: str) -> dict:
        """
        Gets all the issues triggered for a particular snapshot

        NOTE :: This endpoint does not support filtering and will need to do it in function

        :param snapshot: date string formatted in DATE_FORMAT
        :return: Dict with a data key that is an array of issues
        """
        return self._http_request(
            method='GET',
            url_suffix=f'/rules/{self.project_id}/{snapshot}/issues'
        )

    def get_recent_issues(self, last_run: str | int) -> dict:
        """
        Lookup the added issues after a certain date

        :param last_run: can be a timestamp or a snapshot in DATE_FORMAT
        :return: Dict with a data key that is an array of diffs between snapshots
        """
        return self._http_request(
            method='GET',
            url_suffix=f'/rules/history/{self.project_id}/activity?'
                       f'rule_action=added&'
                       f'start={last_run}&'
                       f'classification={MIN_SEVERITY_MAPPING[self.min_severity]}'
        )

    def get_recent_issues_by_host(self, last_run: str | int) -> dict:
        """
        Lookup the hosts that have added issues after a certain date by host

        :param last_run: can be a timestamp or a snapshot in DATE_FORMAT
        :return: Dict with a data key that is an array of diffs between snapshots
        """
        return self._http_request(
            method='GET',
            url_suffix=f'/rules/history/{self.project_id}/activity/by_host/compare?'
                       f'rule_action=added&'
                       f'last_checked={last_run}&'
                       f'classification={MIN_SEVERITY_MAPPING[self.min_severity]}&'
                       f'limit={self.host_incident_limit}'
        )


''' HELPER FUNCTIONS '''


class IncidentBuilder:
    def __init__(self, min_severity: str, snapshot: Optional[str], last_checked: int = 0):
        """
        Class to standardize each API response and build the rawJSON for the Incident type

        :param min_severity: option selected by the user when setting up the Pack
        :param snapshot: snapshot that the risks came from
        :param last_checked: the timestamp since incidents were last checked for
        """
        self.min_severity = min_severity
        self.snapshot = snapshot
        self.last_checked = last_checked
        self.incident_created_time = 0 if not snapshot else datetime.strptime(snapshot, DATE_FORMAT).timestamp()
        self.incident_created_time_ms = self.incident_created_time * 1000

    def parse_rule(self, rule: dict) -> Optional[dict]:
        """
        Takes a rule from the ASI API and formats it into a better format for XSOAR

        :return: optionally a transformed Dict (None if rule gets filtered out)
        """
        raise NotImplementedError

    def parse_rules(self, rules: list[dict]) -> list[dict]:
        """
        Given an array of rules, parse out relevant info and filter out ones to skip

        :param rules: list of rules from ASI API
        :return: list of transformed Dict to get built as Incidents
        """
        transformed = []

        # NOTE :: to prevent duplicates, we are only adding incidents with creation_time > last fetched incident
        if self.incident_created_time <= self.last_checked:
            return []

        for rule in rules:
            parsed_rule = self.parse_rule(rule)

            if parsed_rule is None:
                continue

            # NOTE :: Some endpoints don't support filtering and will need to do it in function
            if parsed_rule['classification'] not in MIN_SEVERITY_MAPPING[self.min_severity]:
                continue

            transformed.append(parsed_rule)
        return transformed

    def build_incident(self, parsed_rule: dict) -> dict:
        """
        Takes a standardized rule and builds an incident from it

        :param parsed_rule: standardized rule from ASI API
        :return: XSOAR Incident format
        """
        raise NotImplementedError

    def build_incidents(self, parsed_rules: list[dict]) -> list[dict]:
        """
        Takes in parsed_rules and formats them as XSOAR Incident

        :param parsed_rules: parsed rules
        :return: list of Incident
        """
        return [self.build_incident(issue) for issue in parsed_rules]

    @staticmethod
    def _format_references(refs: list[str]) -> str:
        """
        Formats references as bulleted Long Text

        :param refs: list of reference links
        :return: bulleted list
        """
        return '\n\n'.join([f'◦ {r}' for r in refs])

    @staticmethod
    def _use_severity_titles(rules: list[dict]) -> list[dict]:
        """
        Swap out classifications to use CRITICALITY_TITLES instead

        :param rules: list of parsed rules
        :return: mutated rules
        """
        for r in rules:
            r['classification'] = CRITICALITY_TITLES[r['classification']]
        return rules


class ByHostIncidentBuilder(IncidentBuilder, ABC):
    def __init__(self, host: str, risk_score: int, previous_score: int, previous_snapshot: Optional[str],
                 min_severity: str, snapshot: Optional[str], last_checked: int = 0):
        """
        Incident type where issues are grouped by hosts

        :param host: the host that changed (ip or domain)
        :param risk_score: the current score of the host
        :param previous_score: the previous score
        :param previous_snapshot: the last scanned snapshot
        :param min_severity: the min_severity configured by the user
        :param snapshot: the current snapshot
        :param last_checked: the last time the api was polled for changes
        """
        super().__init__(min_severity, snapshot, last_checked=last_checked)
        self.host = host
        self.risk_score = risk_score
        self.previous_snapshot = previous_snapshot
        self.previous_score = previous_score or 0

    def parse_rule(self, rule: dict) -> Optional[dict]:
        return {
            'name': rule['name'],
            'details': rule['description'],
            'classification': rule['classification'],
            'references': self._format_references(rule.get('rule_metadata', {}).get('references', [])),
            'metadata': rule.get('rule_metadata', {}).get('target', rule.get('rule_metadata', {}).get('additional'))
        }


class ByIssueIncident(IncidentBuilder):
    def parse_rule(self, rule: dict) -> Optional[dict]:
        hosts = self._build_examples(rule['example_entities'].get('domains', [])) + \
            self._build_examples(rule['example_entities'].get('ips', []))
        return {
            'name': rule['name'],
            'details': rule['description'],
            'classification': rule['classification'],
            'entity_counts': rule.get('rule_metadata', {}).get('entity_counts', {}),
            'references': self._format_references(rule.get('rule_metadata', {}).get('references', [])),
            'hosts': hosts
        }

    def build_incident(self, parsed_rule: dict) -> dict:
        count_copy = '\n\nThis rule triggered for '
        entity_counts = parsed_rule.pop('entity_counts')
        examples = parsed_rule.pop('hosts', [])
        domain_count = entity_counts.get('domains')
        ip_count = entity_counts.get('ips')
        if domain_count and ip_count:
            count_copy += f'{domain_count} domains and {ip_count} IPs.'
        elif domain_count:
            count_copy += f'{domain_count} domains.'
        else:
            count_copy += f'{ip_count} IPs.'

        return {
            'severity': SEVERITY_MAPPINGS[parsed_rule['classification']],
            'name': parsed_rule['name'],
            'rawJSON': json.dumps({
                'triggered_rule': parsed_rule['name'],
                'rules': self._use_severity_titles([parsed_rule]),
                'affected_hosts': examples,
                '_incident_type': 'by_issue'
            }),
            'details': parsed_rule['details'] + count_copy,
            'occurred': timestamp_to_datestring(self.incident_created_time_ms)
        }

    @staticmethod
    def _build_examples(examples: list[dict]) -> list[dict]:
        """
        Parses out useful info from list of examples

        :param examples: list of entity
        :return: list of parsed fields
        """
        return [{'id': e['example'], 'metadata': e.get('target') or e.get('additional')} for e in examples]


class ByHostIncident(ByHostIncidentBuilder):
    def build_incident(self, parsed_rule: dict) -> dict:
        raise NotImplementedError('Cannot use this method for this type of issue. Use build_grouped_incident instead')

    def build_grouped_incident(self, parsed_rules: list[dict]) -> dict:
        """
        ByHost incidents group all rules into a single incident

        :param parsed_rules: list of parsed rules
        :return: single incident
        """
        by_classification = self._group_by_classification(parsed_rules)
        title, severity = self._incident_title_and_severity(by_classification)
        details = self._incident_description(by_classification, len(parsed_rules))

        return {
            'name': title,
            'host': self.host,
            'details': details,
            'occurred': timestamp_to_datestring(self.incident_created_time_ms),
            'rawJSON': json.dumps({
                '_incident_type': 'by_host',
                'affected_hosts': [{'id': self.host, 'metadata': ''}],
                'rules': self._use_severity_titles(sorted(parsed_rules,
                                                          key=lambda r: SEVERITY_MAPPINGS[r['classification']],
                                                          reverse=True))
            }),
            'severity': severity
        }

    def build_incidents(self, parsed_rules: list[dict]) -> list[dict]:
        """
        Takes in parsed_rules and formats them as XSOAR Incident

        :param parsed_rules: parsed rules
        :return: list of Incident
        """
        return [self.build_grouped_incident(parsed_rules)]

    @staticmethod
    def _group_by_classification(rules: list[dict]) -> dict[str, list[dict]]:
        """
        Groups rules by their classification

        :param rules: list of parsed rules
        :return: dict by classification
        """
        by_classification = defaultdict(list)
        for rule in rules:
            by_classification[rule['classification']].append(rule)
        return by_classification

    def _incident_title_and_severity(self, by_classification: dict[str, list[dict]]) -> tuple[str, int]:
        """
        Generates a title for the incident

        :param by_classification: rules grouped by classification
        :return: title, severity
        """
        if by_classification['high']:
            severity = SEVERITY_MAPPINGS['high']
        elif by_classification['moderate']:
            severity = SEVERITY_MAPPINGS['moderate']
        else:
            severity = SEVERITY_MAPPINGS['informational']
        title = f'Attack Surface Risk Increase: {self.host} ' \
                f'({self.previous_score} --> {self.risk_score})'
        return title, severity

    def _incident_description(self, by_classification: dict[str, list[dict]], added_rule_count: int) -> str:
        """
        Builds description for the incident

        :param by_classification: rules grouped by classification
        :param added_rule_count: how many rules were added?
        :return: description
        """
        summary = f'Summary for host "{self.host}":\n----------------------------\n'
        risk_score_diff = self.risk_score - self.previous_score
        change_symbol = '+' if risk_score_diff > 0 else '-'
        change_statement = f'{change_symbol}{abs(risk_score_diff)} from last Risk Score at {self.previous_snapshot}'
        summary += f'    {self.risk_score} Risk Score ' + (
            '(first score)' if not self.previous_score else f'({change_statement})') + '\n'
        summary += f'    {added_rule_count} New Risks ('
        rule_counts = []
        for criticality, rules in by_classification.items():
            if rules:
                rule_counts.append(f'{len(rules)} {CRITICALITY_TITLES[criticality]}')
        summary += ', '.join(rule_counts)
        summary += ')'
        return summary


class ByHostByIssueIncident(ByHostIncidentBuilder):
    def build_incident(self, parsed_rule: dict) -> dict:
        return {
            'severity': SEVERITY_MAPPINGS[parsed_rule['classification']],
            'name': f'{parsed_rule["name"]} [{self.host}]',
            'rawJSON': json.dumps({
                'host': self.host,
                'triggered_rule': parsed_rule['name'],
                'rules': self._use_severity_titles([parsed_rule]),
                'affected_hosts': [{'id': self.host, 'metadata': parsed_rule['metadata']}],
                '_incident_type': 'by_host_by_issue'
            }),
            'details': parsed_rule['details'],
            'occurred': timestamp_to_datestring(self.incident_created_time_ms)
        }


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """
    Tests that the client can authenticate and pulls issues correctly

    :param client: Client
    :return: 'ok' if everything works otherwise raise an Exception
    """
    try:
        client.get_project_issues('recent')
    except DemistoException as e:
        if 'Forbidden' in str(e):
            return 'Authorization Error: make sure API Key is correctly set'
        else:
            raise e
    return 'ok'


def _fetch_project_incidents(client: Client) -> tuple[list[dict], int]:
    """
    Fetches the most recent set of issues for a project to initialize incidents

    :param client: Client
    :return: list of incidents, total possible incidents
    """
    issues_resp = client.get_project_issues(snapshot='recent')
    recent_snapshot = issues_resp.get('meta', {}).get('snapshot')
    incident_builder = ByIssueIncident(client.min_severity, recent_snapshot)

    parsed_rules = incident_builder.parse_rules(issues_resp.get('data', []))
    if not parsed_rules:
        return [], 0

    return incident_builder.build_incidents(parsed_rules), len(parsed_rules)


def _fetch_recent_incidents_by_host(client: Client, start_timestamp: int,
                                    expand_incidents: bool) -> tuple[list[dict], int]:
    """
    Fetch recent incidents after a certain timestamp grouped by hosts that changed

    :param client: Client
    :param start_timestamp: the timestamp to find new issues afterwards (usually the last_fetch)
    :param expand_incidents: whether to use ByHostIncident or ByHostByIssueIncident
    :return: list of incidents, total possible incidents
    """
    issues_resp = client.get_recent_issues_by_host(last_run=start_timestamp)

    # Initialize an empty list of incidents to return
    # Each incident is a dict with a string as a key
    incidents: list[dict[str, Any]] = []

    for diff in issues_resp.get('data', []):
        diff_snapshot = diff.get('snapshot')
        build_cls = ByHostByIssueIncident if expand_incidents else ByHostIncident
        incident_builder = build_cls(
            diff['id'], diff['risk_score'], diff['previous_risk_score'], diff['previous_snapshot'],
            client.min_severity, diff_snapshot, last_checked=start_timestamp)
        parsed_rules = incident_builder.parse_rules(diff.get('added_rules', []))
        if not parsed_rules:
            continue
        incidents.extend(incident_builder.build_incidents(parsed_rules))

    return incidents, issues_resp.get('meta', {}).get('counts', {}).get('hosts', {}).get('total', 0)


def _fetch_recent_incidents(client: Client, start_timestamp: int) -> tuple[list[dict], int]:
    """
    Fetch recent incidents after a certain timestamp

    :param client: Client
    :param start_timestamp: the timestamp to find new issues afterwards (usually the last_fetch)
    :return: list of incidents, total number of incidents
    """
    issues_resp = client.get_recent_issues(last_run=start_timestamp)

    # Initialize an empty list of incidents to return
    # Each incident is a dict with a string as a key
    incidents: list[dict[str, Any]] = []

    for diff in issues_resp.get('data', []):
        diff_snapshot = diff.get('snapshot')
        incident_builder = ByIssueIncident(client.min_severity, diff_snapshot, last_checked=start_timestamp)
        parsed_rules = incident_builder.parse_rules(diff.get('added_rules', []))
        if not parsed_rules:
            continue
        incidents.extend(incident_builder.build_incidents(parsed_rules))

    return incidents, len(incidents)


def fetch_incidents(client: Client, last_run: dict[str, int], is_by_host: bool,
                    expand_issues: bool) -> tuple[dict[str, int], list[dict]]:
    """
    This function retrieves new alerts every interval (default is 24 hours).

    :param client: Client
    :param last_run: dict with one key (last_fetch) that was when the integration last pulled incidents
    :param is_by_host: are incidents being grouped by host?
    :param expand_issues: whether to expand host groupings by each issue as well
    :return: the new last_run and a list of incidents
    """

    # Get the last fetch time, if exists
    # last_run is a dict with a single key, called last_fetch
    last_fetch = last_run.get('last_fetch', None)

    if not is_by_host:
        if last_fetch is None:
            incidents, total = _fetch_project_incidents(client)
        else:
            incidents, total = _fetch_recent_incidents(client, last_fetch)
    else:
        incidents, total = _fetch_recent_incidents_by_host(client, last_fetch or 0, expand_issues)

    incident_limit = client.host_incident_limit
    # NOTE :: Some APIs limit the number of results return, and we're also expanding issues on client side
    #         so need to check both total possible results and total processed results
    max_count = max(len(incidents), total)
    if max_count > incident_limit:
        # NOTE :: Make sure the highest severity incidents aren't trimmed
        incidents = sorted(incidents, key=lambda i: i['severity'], reverse=True)
        if len(incidents) >= incident_limit:
            # NOTE :: Need to add an incident warning of the limit being hit so trimming incidents to limit (minus 1)
            trim = max(incident_limit - 1, 0)
            incidents = incidents[:trim]
        incidents.append({
            'name': f'❗Attack Surface Intelligence: {max_count}+ Changes',
            'details': f'This Incident was created because Recorded Future Attack Surface Intelligence found '
                       f'additional incidents beyond the configured XSOAR limit of {incident_limit} or beyond the'
                       f' maximum allowed by the Risk Rules API.\n'
                       f'Please review additional changes within the ASI Portal.',
            'occurred': timestamp_to_datestring(int(time.time()) * 1000),
            'severity': IncidentSeverity.LOW
        })

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {'last_fetch': int(time.time())}
    return next_run, incidents


''' MAIN FUNCTION '''


def main() -> None:
    params = demisto.params()
    api_key = params.get("credentials", {}).get("password") or params.get("apikey")
    if not api_key:
        return_error('Please provide a valid API token')
    project_id = params.get("project_id")
    is_by_host = params.get('issue_grouping') == 'By Host'
    expand_issues = params.get('expand_issues', False)
    incident_limit = int(params.get('max_fetch', DEFAULT_HOST_LIMIT))
    min_severity = params.get('min_severity', DEFAULT_MIN_SEVERITY)

    # get the service API url
    base_url = 'https://api.securitytrails.com/v1/asi'
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    try:
        headers = {
            'APIKEY': api_key
        }
        client = Client(
            base_url=base_url,
            project_id=project_id,
            min_severity=min_severity,
            host_incident_limit=incident_limit,
            verify=True,
            headers=headers)

        command_args = demisto.args()
        if command == 'test-module':
            return_results(test_module(client))
        elif command == 'asi-project-issues-fetch':
            next_run, incidents = fetch_incidents(
                client=client,
                last_run={'last_fetch': int(command_args.get('issues_start', 0))},
                is_by_host=command_args.get('group_by_host', 'false') == 'true',
                expand_issues=command_args.get('expand_issues', 'false') == 'true'
            )
            demisto.incidents(incidents)
        elif command == 'fetch-incidents':
            next_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                is_by_host=is_by_host,
                expand_issues=expand_issues
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
