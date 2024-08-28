import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

import urllib3

# Disable insecure warnings
urllib3.disable_warnings()


FEED_NAME = 'ORKL Feed'


class Client(BaseClient):
    def __init__(self, verify, proxy: bool = False):
        headers = {
            'content-type': 'application/json'
        }
        super().__init__(base_url='https://orkl.eu/api/v1', verify=verify, proxy=proxy, headers=headers)

    def fetch_indicators(self, limit: int = 1000, offset: int = 0, order_by: str = '', order: str = 'desc'):
        params = assign_params(order_by=order_by, limit=limit, offset=offset, order=order)

        return self._http_request(
            method='GET',
            url_suffix='/library/entries',
            params=params
        )


def module_of_testing(client: Client):
    try:
        res = client.fetch_indicators(limit=1)
        if 'data' in res:
            return 'ok'
        else:
            return f'Test Command Error: {res}'
    except DemistoException as error:
        raise error


def create_relationships(feedRel: str, entity_a: str, entity_a_type: str, entity_b: str, entity_b_type: str):
    if entity_b and entity_b_type:
        relationship_entity = EntityRelationship(entity_a=entity_a, entity_a_type=entity_a_type,
                                                 name=EntityRelationship.Relationships.RELATED_TO,
                                                 entity_b=entity_b, entity_b_type=entity_b_type,
                                                 source_reliability=feedRel,
                                                 brand=FEED_NAME)
        demisto.debug(f'Created relationsip between {entity_a} and {entity_b}')
        return relationship_entity.to_indicator()
    else:
        demisto.debug(
            f"WARNING: Relationships will not be created to entity A {entity_a}"
            f" with relationship name {EntityRelationship.Relationships.RELATED_TO}")
        return {}


def get_reports_command(client: Client, limit: int, order_by: str, order: str) -> CommandResults:
    try:
        res = client.fetch_indicators(limit=limit, order_by=order_by, order=order)
        if 'data' in res:
            table = []
            for report in res.get('data'):
                table_content = {}
                table_content['Created At'] = report.get('created_at')

                if len(report.get('title')) > 0:
                    table_content['Report Name'] = report.get('title')
                else:
                    table_content['Report Name'] = report.get('report_names')

                table_content['Threat Actors'] = [actor.get('source_name') for actor in report.get('threat_actors')]
                table_content['Source'] = [source.get('name') for source in report.get('sources')]
                table_content['References'] = report.get('references')

                table.append(table_content)

            return CommandResults(
                readable_output=tableToMarkdown('ORKL Reports', table, headers=['Created At', 'Report Name',
                                                                                'Source', 'References', 'Threat Actors'])
            )

        else:
            raise DemistoException(f'Could not receive data from Orkl. {res}')

    except DemistoException as error:
        raise error


def fetch_indicator_command(client: Client, feed_tags: str, tlp_color: str, limit: int, cRel: str, feedRel: str):
    try:
        res = client.fetch_indicators(limit=limit, order_by='file_creation_date', order='desc')

        last_run = demisto.getLastRun()
        last_fetch = last_run.get('timestamp', 0)

        if 'data' in res:
            demisto.debug('Successfully retrieved Indicators from ORKL.')
            data = res.get('data')
            indicators = []
            for report in data:
                if int(report.get('ts_updated_at')) > last_fetch:
                    indicator = {
                        'type': 'Report',
                        'value': report.get('title') if report.get('title') != "" else report.get('report_names')[0],
                        'service': FEED_NAME,
                        'rawJSON': report,
                        'fields': {
                            'description': report.get('plain_text')
                        }
                    }

                    if feed_tags:
                        indicator['fields']['tags'] = feed_tags
                    if tlp_color:
                        indicator['fields']['trafficlightprotocol'] = tlp_color

                    if len(report.get('references')) > 0:
                        indicator['fields']['publications'] = []
                        for pub in report.get('references'):
                            pub_obj = {
                                'title': 'Reference Report',
                                'source': FEED_NAME,
                                'link': pub
                            }

                            indicator['fields']['publications'].append(pub_obj)

                    indicator['fields']['published'] = report.get('file_creation_date')

                    if len(report.get('threat_actors')) > 0:
                        for actor in report.get('threat_actors'):
                            if actor.get('tools') and len(actor.get('tools')) > 0:
                                for tool in actor.get('tools'):
                                    ind_tool = {
                                        'type': 'Tool',
                                        'value': tool,
                                        'source': FEED_NAME,
                                        'fields': {
                                            'trafficlightprotocol': tlp_color
                                        }
                                    }
                                    indicators.append(ind_tool)

                            ind_actor = {
                                'type': 'Threat Actor',
                                'value': actor.get('main_name'),
                                'source': FEED_NAME,
                                'fields': {
                                    'aliases': actor.get('tools'),
                                    'trafficlightprotocol': tlp_color
                                }
                            }
                            indicators.append(ind_actor)

                            if argToBoolean(cRel):
                                relationships = []
                                demisto.debug('Creating relationships')
                                relationships.append(create_relationships(feedRel, indicator['value'], 'Report',
                                                                          actor.get('main_name'), 'Threat Actor'))

                                indicator['relationships'] = relationships

                    indicators.append(indicator)
                else:
                    break

            demisto.setLastRun({'timestamp': int(data[0].get('ts_updated_at'))})
            return indicators

        else:
            raise DemistoException(f'Could not receive data from Orkl. {res}')

    except DemistoException as error:
        raise error


def main():
    params = demisto.params()

    verify = not demisto.params().get('insecure', False)
    proxy = params.get('proxy', False)

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        client = Client(
            verify=verify,
            proxy=proxy
        )

        if demisto.command() == 'test-module':
            return_results(module_of_testing(client))

        elif demisto.command() == 'fetch-indicators':
            indicators = fetch_indicator_command(
                client,
                params.get('feedTags'),
                params.get('tlp_color'),
                params.get('limit'),
                params.get('createRelationships'),
                params.get('feedReliability')
            )
            for iter_ in batch(indicators, batch_size=20000000):
                demisto.createIndicators(iter_)

        elif demisto.command() == 'orkl-get-reports':
            args = demisto.args()
            return_results(get_reports_command(client, args.get('limit'), args.get('order_by'), args.get('order')))

        else:
            raise NotImplementedError(f'The {demisto.command()} command is not implemented')

    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
