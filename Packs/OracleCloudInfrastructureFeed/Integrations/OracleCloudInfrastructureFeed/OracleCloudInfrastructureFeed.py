import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


import urllib3
from urllib.parse import urlparse

urllib3.disable_warnings()


class Client(BaseClient):

    def build_iterator(self) -> list:
        result = []
        res = self._http_request('GET',
                                 url_suffix='',
                                 full_url=self._base_url,
                                 resp_type='json',
                                 )
        try:
            indicators = []
            for region in res["regions"]:
                for cidr in region['cidrs']:
                    indicators.append(cidr['cidr'])

            for indicator in indicators:
                if indicator_type := auto_detect_indicator_type(indicator):
                    related_indicator = {}
                    if indicator_type == FeedIndicatorType.URL:
                        domain = urlparse(indicator).netloc
                        related_indicator = {
                            'value': domain,
                            'type': FeedIndicatorType.Domain,
                            'relationType': 'hosted-on'
                        }

                    result.append({
                        'value': indicator,
                        'type': indicator_type,
                        'FeedURL': self._base_url,
                        'relations': [related_indicator]
                    })

        except ValueError as err:
            demisto.debug(str(err))
            raise ValueError(f'Could not parse returned data as indicator. \n\nError massage: {err}')
        return result


def test_module(client: Client) -> str:
    fetch_indicators(client, limit=1)
    return 'ok'


def fetch_indicators(client: Client, tlp_color: str | None = None, feed_tags: list = [], limit: int = -1,
                     create_relationships: bool = False) -> list[dict]:
    iterator = client.build_iterator()
    indicators = []
    if limit > 0:
        iterator = iterator[:limit]

    for item in iterator:
        value_ = item.get('value')
        type_ = item.get('type')
        raw_data = {
            'value': value_,
            'type': type_,
        }
        for key, value in item.items():
            raw_data.update({key: value})
        indicator_obj = {
            'value': value_,
            'type': type_,
            'service': 'HelloWorld',
            'fields': {},
            'rawJSON': raw_data
        }

        if feed_tags:
            indicator_obj['fields']['tags'] = feed_tags

        if tlp_color:
            indicator_obj['fields']['trafficlightprotocol'] = tlp_color

        if (relations := item.get('relations')) and create_relationships:
            relationships = []
            for relation in relations:
                if relation:
                    entity_relation = EntityRelationship(
                        name=relation.get('relationType'),
                        entity_a=value_,
                        entity_a_type=type_,
                        entity_b=relation.get('value'),
                        entity_b_type=relation.get('type')
                    )
                    relationships.append(entity_relation.to_indicator())

            indicator_obj['relationships'] = relationships

        indicators.append(indicator_obj)

    return indicators


def get_indicators_command(client: Client,
                           params: dict[str, str],
                           args: dict[str, str]
                           ) -> CommandResults:
    """Wrapper for retrieving indicators from the feed to the war-room.
    Args:
        client: Client object with request
        params: demisto.params()
        args: demisto.args()
    Returns:
        Outputs.
    """
    limit = int(args.get('limit', '10'))
    tlp_color = params.get('tlp_color')
    feed_tags = argToList(params.get('feedTags', ''))
    indicators = fetch_indicators(client, tlp_color, feed_tags, limit)
    human_readable = tableToMarkdown('Indicators from HelloWorld Feed:', indicators,
                                     headers=['value', 'type'], headerTransform=string_to_table_header, removeNull=True)
    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='',
        outputs_key_field='',
        raw_response=indicators,
        outputs={},
    )


def fetch_indicators_command(client: Client, params: dict[str, str]) -> list[dict]:
    feed_tags = argToList(params.get('feedTags', ''))
    tlp_color = params.get('tlp_color')
    create_relationships = argToBoolean(params.get('create_relationships', True))

    indicators = fetch_indicators(client, tlp_color, feed_tags, create_relationships=create_relationships)
    return indicators


def main():
    params = demisto.params()

    base_url = params.get('url')
    insecure = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    command = demisto.command()
    args = demisto.args()
    demisto.debug(f'Command being called is {command}')

    try:
        client = Client(
            base_url=base_url,
            verify=insecure,
            proxy=proxy,
        )

        if command == 'test-module':
            return_results(test_module(client))

        elif command == 'oci-get-indicators':
            return_results(get_indicators_command(client, params, args))

        elif command == 'fetch-indicators':
            indicators = fetch_indicators_command(client, params)
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)

        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    except Exception as e:
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
