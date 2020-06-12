"""Recorded Future Integration for Demisto."""
import demistomock as demisto
import requests
from datetime import datetime
from typing import Dict, Any, List, Tuple
from urllib import parse

try:
    from CommonServerPython import Common, CommandResults, DemistoException, \
        formats, BaseClient, return_results, tableToMarkdown, entryTypes, \
        createContext, return_error, parse_date_range, DBotScoreType
except ModuleNotFoundError:
    pass

# disable insecure warnings
requests.packages.urllib3.disable_warnings()  # pylint:disable=no-member


class Client(BaseClient):

    def entity_lookup(self, entities: List[str],
                      entity_type: str) -> Dict[str, Any]:
        """Entity lookup."""
        if entity_type == 'file':
            entity_type = 'hash'
        elif entity_type == 'cve':
            entity_type = 'vulnerability'
        return self._http_request(method='post', url_suffix='soar/enrichment',
                                  json_data={entity_type: entities},
                                  timeout=120)

    def entity_enrich(self, entity: str, entity_type: str,
                      fields: List[str] = None) -> Dict[str, Any]:
        """Entity enrich."""
        intel_map = {
            'ip': ['entity', 'risk', 'timestamps', 'threatLists', 'intelCard',
                   'metrics', 'location', 'relatedEntities', 'riskyCIDRIPs'],
            'domain': ['entity', 'risk', 'timestamps', 'threatLists',
                       'intelCard', 'metrics', 'relatedEntities'],
            'hash': ['entity', 'risk', 'timestamps', 'threatLists',
                     "intelCard", 'metrics', 'hashAlgorithm',
                     'relatedEntities'],
            'vulnerability': ['entity', 'risk', 'timestamps', 'threatLists',
                              'intelCard', 'metrics', 'cvss', 'nvdDescription',
                              'relatedEntities'],
            'url': ['entity', 'risk', 'timestamps', 'metrics',
                    'relatedEntities']
        }
        if entity_type == 'url':
            entity = parse.quote_plus(entity)
        elif entity_type == 'file':
            entity_type = 'hash'
        elif entity_type == 'cve':
            entity_type = 'vulnerability'
        cmd_url = '%s/%s' % (entity_type, entity.strip())
        req_fields = ','.join(intel_map[entity_type]) if not fields else fields
        params = {'fields': req_fields}
        return self._http_request(method='get', url_suffix=cmd_url,
                                  params=params, timeout=30)

    def get_alert_rules(self, rule_name: str,
                        limit: int) -> Dict[str, Any]:
        """Get Alert Rules."""
        params: Dict[str, Any] = {}
        if rule_name:
            params['freetext'] = rule_name.strip()
        if limit:
            params['limit'] = limit
        return self._http_request(method='get', url_suffix='alert/rule',
                                  params=params, timeout=30)

    def get_alerts(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Get Alerts."""
        return self._http_request(method='get', url_suffix='alert/search',
                                  params=params, timeout=30)

    def get_triage(self, entities: Dict[str, List],
                   context: str) -> Dict[str, Any]:
        """SOAR triage lookup."""
        return self._http_request(method='post',
                                  url_suffix='soar/triage/contexts/%s'
                                             '?format=phantom' % context,
                                  json_data=entities, timeout=30)


def translate_score(score: int, threshold: int) -> int:
    """Translate Recorded Future score to DBot score."""
    if score >= threshold:
        return Common.DBotScore.BAD
    elif score >= 5:
        return Common.DBotScore.SUSPICIOUS
    else:
        return Common.DBotScore.NONE


def determine_hash(hash_value: str) -> str:
    """Determine hash type by length."""
    hash_length = len(hash_value)
    if hash_length == 128:
        return 'SHA512'
    elif hash_length == 64:
        return 'SHA256'
    elif hash_length == 40:
        return 'SHA1'
    elif hash_length == 32:
        return 'MD5'
    elif hash_length == 8:
        return 'CRC32'
    else:
        return 'CTPH'


def level_to_criticality(level: int) -> str:
    """Translate level integer to Criticality string."""
    if level >= 4:
        return 'Very Malicious'
    elif level >= 3:
        return 'Malicious'
    elif level >= 2:
        return 'Suspicious'
    elif level >= 1:
        return "Informational"
    return 'Unknown'


def rf_type_to_xsoar_type(entity_type: str) -> str:
    if entity_type == 'IpAddress':
        return 'ip'
    elif entity_type == 'Hash':
        return 'file'
    elif entity_type == 'URL':
        return 'url'
    elif entity_type == 'CyberVulnerability':
        return 'cve'
    elif entity_type == 'InternetDomainName':
        return 'domain'
    raise DemistoException('Unknown Recorded Future '
                           'entity type: %s' % entity_type)


def prettify_time(time_string: str) -> str:
    """Fix timestamps to a better format."""
    if time_string:
        parsed = datetime.strptime(time_string, "%Y-%m-%dT%H:%M:%S.%fZ")
        return datetime.strftime(parsed, "%Y-%m-%d %H:%M:%S")
    else:
        return 'N/A'


def create_indicator(entity: str, entity_type: str,
                     score: int, description: str,
                     location: Dict[str, Any] = {}) -> Common.Indicator:
    """Create an Indicator object."""
    thresholds = {'file': int(demisto.params().get('file_threshold', 65)),
                  'ip': int(demisto.params().get('ip_threshold', 65)),
                  'domain': int(demisto.params().get('domain_threshold', 65)),
                  'url': int(demisto.params().get('url_threshold', 65)),
                  'cve': int(demisto.params().get('cve_threshold', 65))}
    dbot_score = translate_score(score, thresholds[entity_type])
    dbot_description = 'Score above %s' % thresholds[entity_type] \
        if dbot_score == Common.DBotScore.BAD else None
    if entity_type == 'ip':
        return Common.IP(entity,
                         Common.DBotScore(entity, DBotScoreType.IP,
                                          'Recorded Future', dbot_score,
                                          dbot_description),
                         asn=location.get('asn', None),
                         geo_country=location.get('location',
                                                  {}).get('country', None))
    elif entity_type == 'domain':
        return Common.Domain(entity,
                             Common.DBotScore(entity, DBotScoreType.DOMAIN,
                                              'Recorded Future', dbot_score,
                                              dbot_description))
    elif entity_type == 'file':
        entity = entity
        dbot_obj = Common.DBotScore(entity, DBotScoreType.FILE,
                                    'Recorded Future', dbot_score,
                                    dbot_description)
        hash_type = determine_hash(entity)
        if hash_type == 'MD5':
            return Common.File(dbot_obj, md5=entity)
        elif hash_type == 'SHA1':
            return Common.File(dbot_obj, sha1=entity)
        elif hash_type == 'SHA256':
            return Common.File(dbot_obj, sha256=entity)
        elif hash_type == 'SHA512':
            return Common.File(dbot_obj, sha512=entity)
        else:
            return Common.File(dbot_obj)
    elif entity_type == 'cve':
        return Common.CVE(entity, '', '', '', description)
    elif entity_type == 'url':
        return Common.URL(entity,
                          Common.DBotScore(entity, DBotScoreType.URL,
                                           'Recorded Future', dbot_score,
                                           dbot_description))
    else:
        raise Exception('Could not create indicator for this '
                        'type of entity: %s' % entity_type)


def get_output_prefix(entity_type: str) -> str:
    if entity_type in ['cve', 'vulnerability']:
        return 'RecordedFuture.CVE'
    elif entity_type == 'ip':
        return 'RecordedFuture.IP'
    elif entity_type == 'domain':
        return 'RecordedFuture.Domain'
    elif entity_type == 'url':
        return 'RecordedFuture.URL'
    elif entity_type in ['file', 'vulnerability']:
        return 'RecordedFuture.File'
    else:
        raise Exception('Unknown entity type: %s' % entity_type)

#####################
#    Actions        #
#####################


def lookup_command(client: Client, entities: List[str],
                   entity_type: str) -> CommandResults:
    """Entity lookup command."""
    entity_data = client.entity_lookup(entities, entity_type)
    indicators, context = build_rep_context(entity_data, entity_type)
    return CommandResults(outputs_prefix=get_output_prefix(entity_type),
                          outputs=context, raw_response=entity_data,
                          readable_output=build_rep_markdown(entity_data,
                                                             entity_type),
                          outputs_key_field='name', indicators=indicators)


def build_rep_markdown(entity_data: Dict[str, Any], entity_type: str) -> str:
    """Build Reputation Markdown."""
    if entity_data and ('error' not in entity_data):
        markdown = []
        entity_title = entity_type.upper() \
            if entity_type in ['ip', 'url', 'cve'] else entity_type.title()
        for ent in entity_data['data']['results']:
            try:
                evidence = ent['risk']['rule']['evidence']
            except KeyError:
                evidence = {}
            markdown.append('\n'.join(
                ['### Recorded Future %s reputation for %s'
                 % (entity_title, ent['entity']['name']),
                 'Risk score: %s' % int(ent['risk']['score']),
                 'Risk Summary: %s out of %s Risk Rules currently observed'
                 % (ent['risk']['rule']['count'],
                    ent['risk']['rule']['maxCount']),
                 'Criticality: %s\n'
                 % level_to_criticality(ent['risk']['level'])]))
            if ent['entity'].get('description', None):
                markdown.append('NVD Vulnerability Description: %s\n'
                                % ent['entity']['description'])
            if ent['entity'].get('id', None):
                markdown.append('[Intelligence Card]'
                                '(https://app.recordedfuture.com'
                                '/live/sc/entity/%s)\n' % ent['entity']['id'])

            if evidence:
                evid_table = [{'Rule': detail['rule'],
                               'Criticality':
                                   level_to_criticality(detail['level']),
                               'Evidence': detail['description'],
                               'Timestamp': prettify_time(detail['timestamp']),
                               'Level': detail['level']}
                              for x, detail in evidence.items()]
                evid_table.sort(key=lambda x: x.get('Level'), reverse=True)
                markdown.append(tableToMarkdown('Risk Rules Triggered',
                                                evid_table,
                                                ['Criticality', 'Rule',
                                                 'Evidence', 'Timestamp'],
                                                removeNull=True))
        return '\n'.join(markdown)
    else:
        return 'No records found'


def build_rep_context(entity_data: Dict[str, Any],
                      entity_type: str) -> Tuple[List, List]:
    """Build Reputation Context."""
    if entity_type == 'hash':
        entity_type = 'file'
    elif entity_type == 'vulnerability':
        entity_type = 'cve'
    indicators: List[Common.Indicator] = []
    context = []
    if entity_data and ('error' not in entity_data):
        for ent in entity_data['data']['results']:
            try:
                evidence = ent['risk']['rule']['evidence']
            except KeyError:
                evidence = {}
            context.append({
                'riskScore': ent['risk']['score'],
                'Evidence': [{'rule': y['rule'],
                              'mitigation': y['mitigation'],
                              'description': y['description'],
                              'timestamp': prettify_time(y['timestamp']),
                              'level': y['level'],
                              'ruleid': x}
                             if y.get('mitigation', None) else
                             {'rule': y['rule'],
                              'description': y['description'],
                              'timestamp': prettify_time(y['timestamp']),
                              'level': y['level'],
                              'ruleid': x}
                             for x, y in evidence.items()],
                'riskLevel': ent['risk']['level'],
                'id': ent['entity']['id'],
                'ruleCount': ent['risk']['rule']['count'],
                'maxRules': ent['risk']['rule']['maxCount'],
                'description': ent['entity'].get('description', ''),
                'name': ent['entity']['name']
            })
            indicators.append(
                create_indicator(ent['entity']['name'], entity_type,
                                 ent['risk']['score'], ent['entity'].get(
                        'description', '')))
        return indicators, context
    else:
        return [], []


def triage_command(client: Client,
                   entities: Dict[str, List[str]],
                   context: str) -> CommandResults:
    """Do Auto Triage."""
    context_data = client.get_triage(entities, context)
    output_context, indicators = build_triage_context(context_data)
    return CommandResults(outputs_prefix='RecordedFuture',
                          outputs=output_context,
                          raw_response=context_data,
                          readable_output=build_triage_markdown(context_data,
                                                                context),
                          outputs_key_field='Verdict',
                          indicators=indicators)


def build_triage_markdown(context_data: Dict[str, Any], context: str) -> str:
    """Build Auto Triage output."""
    verdict = 'Suspected Malicious' if context_data['verdict'] \
        else 'Non-malicious'
    md = '\n'.join(['### Recorded Future Threat Assessment with regards to %s'
                    % context, 'Verdict: %s' % verdict, 'Max/Min Score: %s/%s'
                    % (int(context_data['scores']['max']),
                       int(context_data['scores']['min'])), '\n'])
    tables = [md, '### Entities']
    for entity in context_data.get('entities', []):
        header = '\n'.join(['Entity: %s' % entity['name'],
                            'Score: %s' % int(entity['score']),
                            'Rule count: %s out of %s'
                            % (int(entity['rule']['count']),
                               int(entity['rule']['maxCount']))])
        table = [{'Rule Name': x['rule'],
                  'Rule Criticality': level_to_criticality(x['level']),
                  'Rule Timestamp': prettify_time(x['timestamp']),
                  'Rule Description': x['description'],
                  'Level': x['level']}
                 for x in entity['rule']['evidence']]
        table.sort(key=lambda x: x.get('Level'), reverse=True)
        tables.append('\n'.join(
            [header, tableToMarkdown('Evidence', table,
                                     ['Rule Name', 'Rule Criticality',
                                      'Rule Timestamp', 'Rule Description'],
                                     removeNull=True)]))
    return '\n'.join(tables)


def build_triage_context(context_data: Dict[str, Any]) \
        -> Tuple[Dict[str, Any], List]:
    """Build Auto Triage output."""
    context = {
        'context': context_data.get('context', 'Unknown'),
        'verdict': context_data.get('verdict', 'Unknown'),
        'riskScore': context_data['scores']['max'],
        'Entities': [{'id': entity['id'], 'name': entity['name'],
                      'type': entity['type'], 'score': entity['score'],
                      'Evidence': entity['rule']['evidence']}
                     for entity in context_data['entities']]}
    indicators = [create_indicator(entity['name'],
                                   rf_type_to_xsoar_type(entity['type']),
                                   entity['score'], '')
                  for entity in context_data['entities']]
    return context, indicators


def enrich_command(client: Client, entity: str,
                   entity_type: str) -> CommandResults:
    """Enrich command."""
    try:
        entity_data = client.entity_enrich(entity, entity_type)
        markdown = build_intel_markdown(entity_data, entity_type)
        indicators, context = build_intel_context(entity, entity_data,
                                                  entity_type)
        return CommandResults(outputs_prefix=get_output_prefix(entity_type),
                              outputs=context, raw_response=entity_data,
                              readable_output=markdown,
                              outputs_key_field='name', indicators=indicators)
    except DemistoException as err:
        if "404" in str(err):
            return CommandResults(outputs_prefix='', outputs={},
                                  raw_response={},
                                  readable_output='No results found.',
                                  outputs_key_field='')
        else:
            raise err


def build_intel_markdown(entity_data: Dict[str, Any], entity_type: str) -> str:
    """Build Intelligence markdown."""
    if entity_data and ('error' not in entity_data):
        if entity_type == 'hash':
            entity_type = 'file'
        elif entity_type == 'vulnerability':
            entity_type = 'cve'
        entity_title = entity_type.upper() \
            if entity_type in ['ip', 'url', 'cve'] else entity_type.title()
        data = entity_data['data']
        risk = data['risk']
        for hits in data['metrics']:
            if hits['type'] == 'totalHits':
                total_hits = hits['value']
                break
        else:
            total_hits = 0
        markdown = ['### Recorded Future %s Intelligence for %s'
                    % (entity_title, data['entity']['name']),
                    'Risk Score: %s' % risk.get('score', 'N/A'),
                    'Summary: %s' % risk.get('riskSummary', 'N/A'),
                    'Criticality label: %s'
                    % risk.get('criticalityLabel', 'N/A'),
                    'Total references to this entity: %s' % total_hits]
        if entity_type == 'ip':
            markdown.extend(['ASN and Geolocation',
                             'AS Number: %s'
                             % data['location'].get('asn', 'N/A'),
                             'AS Name: %s'
                             % data['location'].get('organization', 'N/A'),
                             'CIDR: %s'
                             % data['location'].get('cidr',
                                                    {}).get('name', 'N/A'),
                             'Geolocation (city): %s'
                             % data['location'].get('location',
                                                    {}).get('city', 'N/A'),
                             'Geolocation (country): %s'
                             % data['location'].get('location',
                                                    {}).get('country', 'N/A')])
        markdown.extend(['First reference collected on: %s'
                         % prettify_time(data['timestamps'].get('firstSeen')),
                         'Latest reference collected on: %s'
                         % prettify_time(data['timestamps'].get('lastSeen'))])
        if data.get('intelCard', None):
            markdown.append('[Intelligence Card](%s)\n' % data['intelCard'])
        else:
            markdown.append('[Intelligence Card]'
                            '(https://app.recordedfuture.com/'
                            'live/sc/entity/%s)\n' % (data['entity']['id']))
        if entity_type == 'cve':
            markdown.append('NVD Summary: %s'
                            % data.get('nvdDescription', 'N/A'))
            if data.get('cvssv3', None):
                cvss = ['CVSSv3 Information',
                        'Attack Vector: %s'
                        % data['cvssv3'].get('attackVector', 'N/A').title(),
                        'Attack Complexity: %s'
                        % data['cvssv3'].get('attackComplexity',
                                             'N/A').title(),
                        'CVSSv3 Score: %s'
                        % data['cvssv3'].get('baseScore', 'N/A'),
                        'Impact Score: %s'
                        % data['cvssv3'].get('impactScore', 'N/A'),
                        'Exploitability Score: %s'
                        % data['cvssv3'].get('exploitabilityScore', 'N/A'),
                        'Availability: %s'
                        % data['cvssv3'].get('availabilityImpact',
                                             'N/A').title(),
                        'Availability Impact: %s'
                        % data['cvssv3'].get('availabilityImpact',
                                             'N/A').title(),
                        'User Interaction: %s'
                        % data['cvssv3'].get('userInteraction', 'N/A').title(),
                        'Privileges Required: %s'
                        % data['cvssv3'].get('privilegesRequired',
                                             'N/A').title(),
                        'Integrity Impact: %s'
                        % data['cvssv3'].get('integrityImpact', 'N/A').title(),
                        'Confidentiality Impact: %s'
                        % data['cvssv3'].get('confidentialityImpact',
                                             'N/A').title(),
                        'Published: %s'
                        % prettify_time(data['cvssv3'].get('created')),
                        'Last Modified: %s'
                        % prettify_time(data['cvssv3'].get('modified'))]
            else:
                cvss = ['CVSS Information',
                        'Access Vector: %s'
                        % data['cvss'].get('accessVector', 'N/A').title(),
                        'Availability: %s'
                        % data['cvss'].get('availability', 'N/A').title(),
                        'CVSS Score: %s' % data['cvss'].get('score', 'N/A'),
                        'Access Complexity: %s'
                        % data['cvss'].get('accessComplexity', 'N/A').title(),
                        'Authentication: %s'
                        % data['cvss'].get('authentication', 'N/A').title(),
                        'Confidentiality: %s'
                        % data['cvss'].get('confidentiality', 'N/A').title(),
                        'Confidentiality: %s'
                        % data['cvss'].get('integrity', 'N/A').title(),
                        'Published: %s'
                        % prettify_time(data['cvss'].get('published')),
                        'Last Modified: %s'
                        % prettify_time(data['cvss'].get('lastModified'))]
            markdown.extend(cvss)
        evidence_table = [{'Rule Criticality': detail.get('criticalityLabel'),
                           'Evidence Summary': detail.get('evidenceString'),
                           'Rule Triggered': detail.get('rule'),
                           'Rule Triggered Time': detail.get('timestamp'),
                           'Criticality': detail.get('criticality'),
                           'Mitigation': detail.get('mitigationString')}
                          for detail in risk['evidenceDetails']]
        evidence_table.sort(key=lambda x: x.get('Criticality'), reverse=True)
        markdown.append(
            tableToMarkdown('Triggered Risk Rules', evidence_table,
                            ['Rule Criticality', 'Rule Triggered',
                             'Evidence Summary', 'Mitigation',
                             'Rule Triggered Time'], removeNull=True))
        threatlist_table = [{'Threat List Name': tl['name'],
                             'Description': tl['description']}
                            for tl in data.get('threatLists', [])]

        markdown.append(tableToMarkdown('Threat Lists', threatlist_table,
                                        ['Threat List Name', 'Description']))
        return '\n'.join(markdown)
    else:
        return 'No records found'


def build_intel_context(entity: str, entity_data: Dict[str, Any],
                        entity_type: str) \
        -> Tuple[List[Common.Indicator], Dict[str, Any]]:
    """Build Intelligence context."""
    if entity_type == 'hash':
        entity_type = 'file'
    elif entity_type == 'vulnerability':
        entity_type = 'cve'
    indicators = []
    if entity_data and ('error' not in entity_data):
        data = entity_data['data']
        indicators.append(
            create_indicator(entity, entity_type, data['risk']['score'],
                             data['entity'].get('description', ''),
                             location=data.get('location', None)))
        indicators.extend([
            create_indicator(x['ip']['name'], 'ip', x['score'],
                             'IP in the same CIDR as %s' % entity)
            for x in data.get('riskyCIDRIPs', [])])
        data.update(data.pop('entity'))
        data.update(data.pop('risk'))
        data.update(data.pop('timestamps'))
        data['relatedEntities'] = handle_related_entities(
            data.pop('relatedEntities'))
    else:
        return [create_indicator(entity, entity_type, 0, '')], {}
    return indicators, data


def handle_related_entities(data: List[Dict[str, Any]]) \
        -> List[Dict[str, Any]]:
    return_data = []
    for related in data:
        return_data.append(
            {related['type']: [{'count': x.get('count', 0),
                                'id': x.get('entity', {}).get('id', ''),
                                'name': x.get('entity', {}).get('name', ''),
                                'type': x.get('entity', {}).get('type', '')}
                               for x in related['entities']]})
    return return_data


def get_alert_rules_command(client: Client, rule_name: str,
                            limit: int) -> Dict[str, Any]:
    """Get Alert Rules Command."""
    response = client.get_alert_rules(rule_name, limit)
    if not response or 'data' not in response:
        demisto.results('No results found')
        return {}
    mapped_rules = [{'name': r.get('title', 'N/A'), 'id': r.get('id', '')}
                    for r in response['data'].get('results', [])]
    if not mapped_rules:
        return {
            'Type': entryTypes['note'],
            'Contents': {}, 'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': 'No results found',
            'EntryContext': {}
        }
    return {
        'Type': entryTypes['note'], 'Contents': response,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Recorded Future Alerting Rules',
                                         mapped_rules, removeNull=True),
        'EntryContext': {
            'RecordedFuture.AlertRule(val.ID === obj.id)':
                createContext(mapped_rules)
        }
    }


def get_alerts_command(client: Client, params: Dict[str, str]) \
        -> Dict[str, Any]:
    """Get Alerts Command."""
    resp = client.get_alerts(params)
    if not resp or 'data' not in resp:
        demisto.results('No results found')
        return {}

    headers = ['Rule', 'Alert Title', 'Triggered',
               'Email', 'Status', 'Assignee']

    mapped_alerts = [{
        'id': a['id'],
        'Alert Title': a.get('title', 'N/A'),
        'name': a.get('title', 'N/A'),
        'triggered': prettify_time(a.get('triggered')),
        'status': a.get('review', {}).get('status'),
        'assignee': a.get('review', {}).get('assignee'),
        'rule': a.get('rule', {}).get('name'),
        'email': a.get('entities', {}).get('EmailAddress'),
        "type": a.get('type')
    } for a in resp['data'].get('results', [])]

    if not mapped_alerts:
        return {
            'Type': entryTypes['note'],
            'Contents': {}, 'ContentsFormat': formats['json'],
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': 'No results found',
            'EntryContext': {}
        }

    return {
        'Type': entryTypes['note'],
        'Contents': resp, 'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable':
            tableToMarkdown('Recorded Future Alerts', mapped_alerts,
                            headers=headers, removeNull=True),
        'EntryContext': {
            'RecordedFuture.Alert(val.ID === obj.id)':
                createContext(mapped_alerts)
        }
    }


def main() -> None:
    """Main method used to run actions."""
    try:
        base_url = demisto.params()['server'][:-1] \
            if demisto.params()['server'].endswith('/') \
            else demisto.params()['server']
        verify_ssl = not demisto.params().get('unsecure', False)
        proxy = demisto.params().get('proxy', False)
        headers = {
            'X-RFToken': demisto.params()['token'],
            'X-RF-User-Agent': 'Cortex_XSOAR/2.0 Cortex_XSOAR_%s'
                               % demisto.demistoVersion()['version']
        }
        client = Client(base_url=base_url, verify=verify_ssl,
                        headers=headers, proxy=proxy)
        command = demisto.command()
        if command == 'test-module':
            try:
                client.entity_lookup(['8.8.8.8'], 'ip')
            except Exception as err:
                return_results('Failed to get response: %s.' % str(err))
            return_results('ok')
        elif command in ['url', 'ip', 'domain', 'file', 'cve']:
            entities = demisto.args().get(command)
            if not type(entities) is list:
                entities = entities.split(',')
            return_results(
                lookup_command(client, entities, command))
        elif command == 'recordedfuture-threat-assessment':
            context = demisto.args().get('context')
            entities = {'ip': [x.strip() for x in
                               demisto.args().get('ip', '').split(',')],
                        'domain': [x.strip() for x
                                   in demisto.args().get('domain',
                                                         '').split(',')],
                        'hash': [x.strip() for x
                                 in demisto.args().get('file', '').split(',')],
                        'url': [x.strip() for x
                                in demisto.args().get('url', '').split(',')],
                        'vulnerability':
                            [x.strip() for x
                             in demisto.args().get('cve', '').split(',')]}
            return_results(triage_command(client, entities, context))
        elif command == 'recordedfuture-alert-rules':
            rule_name = demisto.args().get('rule_name', '')
            limit = demisto.args().get('limit', 10)
            return_results(get_alert_rules_command(client, rule_name, limit))
        elif command == 'recordedfuture-alerts':
            params = {x: demisto.args().get(x) for x in demisto.args()
                      if not x == 'detailed'}
            if params.get('rule_id', None):
                params['alertRule'] = params.pop('rule_id')
            if params.get('offset', None):
                params['from'] = params.pop('offset')
            if params.get('triggered_time', None):
                date, _ = parse_date_range(params['triggered_time'],
                                           date_format='%Y-%m-%d %H:%M:%S')
                params['triggered'] = '[{},)'.format(date)
                params.pop('triggered_time')
            return_results(get_alerts_command(client, params))
        elif command == 'recordedfuture-intelligence':
            return_results(enrich_command(client,
                                          demisto.args().get('entity'),
                                          demisto.args().get('entity_type')))
    except Exception as e:
        return_error('Failed to execute %s command. Error: %s'
                     % (demisto.command(), str(e)))


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
