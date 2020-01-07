import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

''' IMPORTS '''
import urllib3
import requests

# disable insecure warnings
urllib3.disable_warnings()


class Client(BaseClient):
    def __init__(self, url: str, source_name: str, insecure: bool = False, credentials: dict = None, ignore_regex: str = None,
                 encoding: str = None, indicator: str = None, fields: str = '{}', polling_timeout: int = 20,
                 user_agent: str = None, proxy: bool = False, **kwargs):
        """Implements class for miners of plain text feeds over http/https.
        **Config parameters**
        :param: url: URL of the feed.
        :param: polling_timeout: timeout of the polling request in seconds.
            Default: 20
        :param: user_agent: string, value for the User-Agent header in HTTP
            request. If ``MineMeld``, MineMeld/<version> is used.
            Default: python ``requests`` default.
        :param: ignore_regex: Python regular expression for lines that should be
            ignored. Default: *null*
        :param: verify_cert: boolean, if *true* feed HTTPS server certificate is
            verified. Default: *true*
        :param: indicator: an *extraction dictionary* to extract the indicator from
            the line. If *null*, the text until the first whitespace or newline
            character is used as indicator. Default: *null*
        :param: fields: a dicionary of *extraction dictionaries* to extract
            additional attributes from each line. Default: {}
        :param: encoding: encoding of the feed, if not UTF-8. See
            ``str.decode`` for options. Default: *null*, meaning do
            nothing, (Assumes UTF-8).
        :param: proxy: Use proxy in requests.
        **Extraction dictionary**
            Extraction dictionaries contain the following keys:
            :regex: Python regular expression for searching the text.
            :transform: template to generate the final value from the result
                of the regular expression. Default: the entire match of the regex
                is used as extracted value.
            See Python `re <https://docs.python.org/2/library/re.html>`_ module for
            details about Python regular expressions and templates.
        Example:
            Example config in YAML where extraction dictionaries are used to
            extract the indicator and additional fields::
                url: https://www.dshield.org/block.txt
                ignore_regex: "[#S].*"
                indicator:
                    regex: '^([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})\\t([0-9]
                    {1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})'
                    transform: '\\1-\\2'
                fields:
                    dshield_nattacks:
                        regex: '^.*\\t.*\\t[0-9]+\\t([0-9]+)'
                        transform: '\\1'
                    dshield_name:
                        regex: '^.*\\t.*\\t[0-9]+\\t[0-9]+\\t([^\\t]+)'
                        transform: '\\1'
                    dshield_country:
                        regex: '^.*\\t.*\\t[0-9]+\\t[0-9]+\\t[^\\t]+\\t([A-Z]+)'
                        transform: '\\1'
                    dshield_email:
                        regex: '^.*\\t.*\\t[0-9]+\\t[0-9]+\\t[^\\t]+\\t[A-Z]+\\t(\\S+)'
                        transform: '\\1'
            Example config in YAML where the text in each line until the first
            whitespace is used as indicator::
                url: https://ransomwaretracker.abuse.ch/downloads/CW_C2_URLBL.txt
                ignore_regex: '^#'
        Args:
            name (str): node name, should be unique inside the graph
            chassis (object): parent chassis instance
            config (dict): node config.
        """
        super().__init__(base_url=url, verify=not insecure, proxy=proxy)
        try:
            self.polling_timeout = int(polling_timeout)
        except (ValueError, TypeError):
            raise ValueError('Please provide an integer value for "Request Timeout"')
        self.source_name = source_name
        self.user_agent = user_agent
        self.encoding = encoding

        if not credentials:
            credentials = {}
        self.username = credentials.get('identifier', None)
        self.password = credentials.get('password', None)

        self.ignore_regex = ignore_regex
        if self.ignore_regex is not None:
            self.ignore_regex = re.compile(self.ignore_regex)

        self.indicator = indicator
        if self.indicator is not None:
            self.indicator = json.loads(self.indicator)
            if 'regex' in self.indicator:
                self.indicator['regex'] = re.compile(self.indicator['regex'])
            else:
                raise ValueError(f'{self.source_name} - indicator stanza should have a regex')
            if 'transform' not in self.indicator:
                if self.indicator['regex'].groups > 0:
                    LOG(f'{self.source_name} - no transform string for indicator but pattern contains groups')
                self.indicator['transform'] = r'\g<0>'

        self.fields = json.loads(fields)
        for f, fattrs in self.fields.items():
            if 'regex' in fattrs:
                fattrs['regex'] = re.compile(fattrs['regex'])
            else:
                raise ValueError(f'{self.source_name} - {f} field does not have a regex')
            if 'transform' not in fattrs:
                if fattrs['regex'].groups > 0:
                    LOG(f'{self.source_name} - no transform string for field {f} but pattern contains groups')
                fattrs['transform'] = r'\g<0>'

    def build_iterator(self):
        rkwargs = dict(
            stream=True,
            verify=self._verify,
            timeout=self.polling_timeout
        )

        if self.user_agent is not None:
            rkwargs['headers'] = {
                'User-Agent': self.user_agent
            }

        if self.username is not None and self.password is not None:
            rkwargs['auth'] = (self.username, self.password)
        try:
            urls = self._base_url
            rs = []
            if not isinstance(urls, list):
                urls = [urls]
            for url in urls:
                r = requests.get(
                    url,
                    **rkwargs
                )
                try:
                    r.raise_for_status()
                except Exception:
                    LOG(f'{self.source_name} - exception in request: {r.status_code} {r.content}')
                    raise
                rs.append(r)
        except requests.ConnectionError:
            raise requests.ConnectionError('Failed to establish a new connection. Please make sure your URL is valid.')

        results = []
        for r in rs:
            result = r.iter_lines()
            if self.encoding is not None:
                result = map(
                    lambda x: x.decode(self.encoding).encode('utf_8'),
                    result
                )
            else:
                result = map(
                    lambda x: x.decode('utf_8'),
                    result
                )
            if self.ignore_regex is not None:
                result = filter(
                    lambda x: self.ignore_regex.match(x) is None,
                    result
                )
            results.append(result)
        return results


# simple function to iterate list in batches
def batch(iterable, batch_size=1):
    current_batch = []
    for item in iterable:
        current_batch.append(item)
        if len(current_batch) == batch_size:
            yield current_batch
            current_batch = []
    if current_batch:
        yield current_batch


def get_indicator_fields(itype, line, client):
    attributes = None
    value = None
    line = line.strip()
    if line:
        if client.indicator is None:
            indicator = line.split()[0]

        else:
            indicator = client.indicator['regex'].search(line)
            if indicator is None:
                return attributes, value
            indicator = indicator.expand(client.indicator['transform'])
        attributes = {}
        for f, fattrs in client.fields.items():
            m = fattrs['regex'].search(line)

            if m is None:
                continue

            attributes[f] = m.expand(fattrs['transform'])

            try:
                i = int(attributes[f])
            except Exception:
                pass
            else:
                attributes[f] = i
        attributes['value'] = value = indicator
        attributes['type'] = itype
    return attributes, value


def fetch_indicators_command(client, itype):
    iterators = client.build_iterator()
    for iterator in iterators:
        indicators = []
        for line in iterator:
            attributes, value = get_indicator_fields(itype, line, client)
            if value:
                indicators.append({
                    "value": value,
                    "type": itype,
                    "rawJSON": attributes,
                })
        return indicators


def get_indicators_command(client, default_indicator_type, args):
    itype = args.get('indicator_type', default_indicator_type)
    limit = int(args.get('limit'))
    indicators_list = fetch_indicators_command(client, itype)
    entry_result = camelize(indicators_list[:limit])
    hr = tableToMarkdown('Indicators', entry_result, headers=['Value', 'Type', 'Rawjson'])
    return hr, {'CSV.Indicator': entry_result}, indicators_list
