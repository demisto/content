import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import urllib3


# Disable insecure warnings.
urllib3.disable_warnings()


class Client(BaseClient):
    def get_detections_str(self, last_analysis_stats: dict):
        if not last_analysis_stats:
            return '0/0'

        malicious = last_analysis_stats['malicious']
        total = last_analysis_stats['harmless'] + \
            last_analysis_stats['suspicious'] + \
            last_analysis_stats['undetected'] + \
            last_analysis_stats['malicious']

        return f'{malicious}/{total}'

    def build_iterator(self, limit: int = 40, job_id: str = '') -> List:
        """Retrieves all entries from the feed.
        Returns:
            A list of objects, containing the indicators.
        """

        result = []
        jobs = self.list_job_matches(limit, job_id)

        try:
            for job in jobs:
                result.append({
                    'data': job,
                    'type': 'file',
                    'FeedURL': self._base_url
                })
        except ValueError as err:
            demisto.debug(str(err))
            raise ValueError(f'Could not parse returned data as indicator. \n\nError message: {err}')
        return result

    def fetch_jobs(self):
        """ Retrieve finished retrohunt jobs. """
        return self._http_request(
            'GET',
            'intelligence/retrohunt_jobs?filter=status:finished'
        )

    def fetch_job_matches(self, job_id: str, limit: int = 40, cursor: str = None) -> dict:
        return self._http_request(
            'GET',
            'intelligence/retrohunt_jobs/{}/matching_files'.format(job_id),
            params=assign_params(limit=min(limit, 40), cursor=cursor)
        )

    def list_job_matches(
            self,
            limit: int = 40,
            job_id: str = ''
    ) -> list:
        """ Retrieve matches for a given retrohunt job (latest by default).
        """
        last_job_id = demisto.getIntegrationContext().get('last_retrohunt_job_id')
        last_job_cursor = demisto.getIntegrationContext().get('last_retrohunt_job_matches_cursor')

        # There is a pending job to be completely processed
        if not job_id and last_job_id and last_job_cursor:
            job_id = last_job_id

        # Look for new jobs and get the latest finished one
        if not job_id:
            jobs = self.fetch_jobs().get('data')

            if len(jobs) == 0:
                return []

            job_id = jobs[0].get('id')
            last_job_id = demisto.getIntegrationContext().get('last_retrohunt_job_id')
            # Ignore already processed job
            if last_job_id == job_id:
                return []

        demisto.setIntegrationContext({'last_retrohunt_job_id': job_id})

        cursor = last_job_cursor
        matches = []

        # Retrieve matches for the latest job until the limit is reached or there are no more matches
        while True:
            response = self.fetch_job_matches(job_id, limit, cursor)
            cursor = response.get('meta', {}).get('cursor')
            matches.extend(response.get('data', []))
            demisto.setIntegrationContext({'last_retrohunt_job_matches_cursor': cursor})
            if len(matches) >= limit or not cursor:
                break

        return matches


def test_module(client: Client, args: dict) -> str:
    client.list_job_matches()
    return 'ok'


def fetch_indicators_command(client: Client,
                             tlp_color: Optional[str] = None,
                             feed_tags: List = [],
                             limit: int = 40,
                             job_id: str = '') -> List[Dict]:
    """Retrieves indicators from the feed
    Args:
        client (Client): Client object with request
        tlp_color (str): Traffic Light Protocol color
        feed_tags (list): tags to assign fetched indicators
        limit (int): limit the results
    Returns:
        Indicators.
    """
    iterator = client.build_iterator(limit, job_id)
    indicators = []
    if limit > 0:
        iterator = iterator[:limit]

    # extract values from iterator
    for item in iterator:
        value_ = item.get('data')
        type_ = FeedIndicatorType.File
        attributes = value_.get('attributes', {})
        raw_data = {
            'value': value_,
            'type': type_,
        }

        # Create indicator object for each value.
        # The object consists of a dictionary with required and optional keys and values, as described blow.
        indicator_obj = {
            # The indicator value.
            'value': attributes['sha256'],
            # The indicator type as defined in Cortex XSOAR.
            # One can use the FeedIndicatorType class under CommonServerPython to populate this field.
            'type': type_,
            # The name of the service supplying this feed.
            'service': 'VirusTotal',
            # A dictionary that maps values to existing indicator fields defined in Cortex XSOAR.
            # One can use this section in order to map custom indicator fields previously defined
            # in Cortex XSOAR to their values.
            'fields': {
                'md5': attributes.get('md5'),
                'sha1': attributes.get('sha1'),
                'sha256': attributes.get('sha256'),
                'ssdeep': attributes.get('ssdeep'),
            },
            # A dictionary of the raw data returned from the feed source about the indicator.
            'rawJSON': raw_data,
            'sha256': attributes['sha256'],
            'detections': client.get_detections_str(attributes.get('last_analysis_stats')),
            'fileType': attributes.get('type_description'),
        }

        if feed_tags:
            indicator_obj['fields']['tags'] = feed_tags

        if tlp_color:
            indicator_obj['fields']['trafficlightprotocol'] = tlp_color

        indicators.append(indicator_obj)

    return indicators


def get_indicators_command(client: Client,
                           params: Dict[str, str],
                           args: Dict[str, str]
                           ) -> CommandResults:
    """Wrapper for retrieving indicators from the feed to the war-room.
    Args:
        client: Client object with request
        params: demisto.params()
        args: demisto.args()
    Returns:
        Outputs.
    """
    limit = int(args.get('limit', params.get('limit', 40)))
    job_id = args.get('job_id', '')
    tlp_color = params.get('tlp_color')
    feed_tags = argToList(params.get('feedTags', ''))
    indicators = fetch_indicators_command(client, tlp_color, feed_tags, limit, job_id)

    human_readable = tableToMarkdown('Indicators from VirusTotal Retrohunt Feed:',
                                     indicators,
                                     headers=[
                                         'sha256',
                                         'detections',
                                         'fileType'],
                                     headerTransform=string_to_table_header,
                                     removeNull=True)

    return CommandResults(
        readable_output=human_readable,
        outputs_prefix='',
        outputs_key_field='',
        raw_response=indicators,
        outputs={},
    )


def reset_last_job_id():
    """
    Reset last job ib from the integration context
    """
    demisto.setIntegrationContext({})
    return CommandResults(readable_output='Fetch history deleted successfully')


def main():
    """
    main function, parses params and runs command functions
    """

    params = demisto.params()

    # If your Client class inherits from BaseClient, SSL verification is
    # handled out of the box by it, just pass ``verify_certificate`` to
    # the Client constructor
    insecure = not params.get('insecure', False)

    # If your Client class inherits from BaseClient, system proxy is handled
    # out of the box by it, just pass ``proxy`` to the Client constructor
    proxy = params.get('proxy', False)

    command = demisto.command()
    args = demisto.args()

    demisto.debug(f'Command being called is {command}')

    try:
        client = Client(
            base_url='https://www.virustotal.com/api/v3/',
            verify=insecure,
            proxy=proxy,
            headers={
                'x-apikey': params['credentials']['password'],
                'x-tool': 'CortexVirusTotalRetrohuntFeed',
            }
        )

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client, {}))

        elif command == 'vt-retrohunt-get-indicators':
            # This is the command that fetches a limited number of indicators
            # from the feed source and displays them in the war room.
            return_results(get_indicators_command(client, params, args))

        elif command == "vt-retrohunt-reset-fetch-indicators":
            return_results(reset_last_job_id())

        elif command == 'fetch-indicators':
            # This is the command that initiates a request to the feed endpoint
            # and create new indicators objects from the data fetched. If the
            # integration instance is configured to fetch indicators, then this
            # is the commandthat will be executed at the specified feed fetch
            # interval.
            indicators = fetch_indicators_command(client, params)
            for iter_ in batch(indicators, batch_size=2000):
                demisto.createIndicators(iter_)

        else:
            raise NotImplementedError(f'Command {command} is not implemented.')

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # Print the traceback
        return_error(f'Failed to execute {command} command.\nError:\n{str(e)}')


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
