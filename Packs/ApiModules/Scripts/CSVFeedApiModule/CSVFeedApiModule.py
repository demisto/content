import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import urllib3
import csv

# disable insecure warnings
urllib3.disable_warnings()


class Client(BaseClient):
    def __init__(self, url: list, fieldnames: str, insecure: bool = False, credentials: dict = None,
                 ignore_regex: str = None, delimiter: str = ',', doublequote: bool = True, escapechar: str = '',
                 quotechar: str = '"', skipinitialspace: bool = False, polling_timeout: int = 20, proxy: bool = False,
                 **kwargs):
        """
        :param url: URL of the feed.
        :param fieldnames: list of field names in the file. If *null* the values in the first row of the file are
            used as names. Default: *null*
        :param insecure: boolean, if *false* feed HTTPS server certificate is verified. Default: *false*
        :param credentials: username and password used for basic authentication
        :param ignore_regex: python regular expression for lines that should be ignored. Default: *null*
        :param delimiter: see `csv Python module
            <https://docs.python.org/2/library/csv.html#dialects-and-formatting-parameters>`. Default: ,
        :param doublequote: see `csv Python module
            <https://docs.python.org/2/library/csv.html#dialects-and-formatting-parameters>`. Default: true
        :param escapechar: see `csv Python module
            <https://docs.python.org/2/library/csv.html#dialects-and-formatting-parameters>`. Default null
        :param quotechar: see `csv Python module
            <https://docs.python.org/2/library/csv.html#dialects-and-formatting-parameters>`. Default "
        :param skipinitialspace: see `csv Python module
            <https://docs.python.org/2/library/csv.html#dialects-and-formatting-parameters>`. Default False
        :param polling_timeout: timeout of the polling request in seconds. Default: 20
        :param proxy: Sets whether use proxy when sending requests
        :param kwargs:
        """
        if not credentials:
            credentials = {}
        username = credentials.get('identifier', None)
        password = credentials.get('password', None)
        auth = None
        if username is not None and password is not None:
            auth = (username, password)

        if not isinstance(url, list):
            url = [url]

        super().__init__(base_url=url, proxy=proxy, verify=not insecure, auth=auth)

        try:
            self.polling_timeout = int(polling_timeout)
        except (ValueError, TypeError):
            return_error('Please provide an integer value for "Request Timeout"')

        self.ignore_regex = ignore_regex
        if self.ignore_regex is not None:
            self.ignore_regex = re.compile(self.ignore_regex)  # type: ignore
        self.fieldnames = argToList(fieldnames)

        self.dialect = {
            'delimiter': delimiter,
            'doublequote': doublequote,
            'escapechar': escapechar,
            'quotechar': quotechar,
            'skipinitialspace': skipinitialspace
        }

    def _build_request(self, url):
        r = requests.Request(
            'GET',
            url,
            auth=self._auth
        )

        return r.prepare()

    def build_iterator(self):
        results = []
        for url in self._base_url:
            _session = requests.Session()

            prepreq = self._build_request(url)

            # this is to honour the proxy environment variables
            rkwargs = _session.merge_environment_settings(
                prepreq.url,
                {}, None, None, None  # defaults
            )
            rkwargs['stream'] = True
            rkwargs['verify'] = self._verify
            rkwargs['timeout'] = self.polling_timeout

            try:
                r = _session.send(prepreq, **rkwargs)
            except requests.ConnectionError:
                raise requests.ConnectionError('Failed to establish a new connection.'
                                               ' Please make sure your URL is valid.')
            try:
                r.raise_for_status()
            except Exception:
                return_error('Exception in request: {} {}'.format(r.status_code, r.content))
                raise

            response = r.content.decode('latin-1').split('\n')
            if self.ignore_regex is not None:
                response = filter(
                    lambda x: self.ignore_regex.match(x) is None,
                    response
                )

                results.append(response)

            csvreader = csv.DictReader(
                response,
                fieldnames=self.fieldnames,
                **self.dialect
            )

            return csvreader


def fetch_indicators_command(client, itype):
    iterator = client.build_iterator()
    indicators = []
    for item in iterator:
        raw_json = dict(item)
        raw_json['value'] = value = item.get('indicator')
        raw_json['type'] = itype
        indicators.append({
            "value": value,
            "type": itype,
            "rawJSON": raw_json,
        })
    return indicators


def get_indicators_command(client, args):
    itype = args.get('indicator_type', demisto.params().get('indicator_type'))
    limit = int(args.get('limit'))
    indicators_list = fetch_indicators_command(client, itype)
    entry_result = camelize(indicators_list[:limit])
    hr = tableToMarkdown('Indicators', entry_result, headers=['Value', 'Type', 'Rawjson'])
    return hr, {'CSV.Indicator': entry_result}, indicators_list
