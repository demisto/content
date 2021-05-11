from subprocess import PIPE, Popen
from io import StringIO
import pandas as pd
import urllib3

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# disable insecure warnings
urllib3.disable_warnings()

EDL_EXPECTED_SIZES = (10 * 1000, 50 * 1000, 100 * 1000)
CONCURRENT_LIMITS = (1, 4, 8, 16)
TIMEOUT_LIMITS = (3, 5, 10, 30)

# ---------- CLASSES ---------- #

class EDLQueryBuilder:
    """
    Utility class for building a URL query for EDL
    """

    def __init__(self, size: int):
        """
        :param size: Size of the EDL to query to create
        """
        self._size = size

    def _get_query(self, _type: str):
        return f"?q=type:{_type}&n={self._size}"

    def get_domain_query(self):
        return self._get_query('Domain')

    def get_url_query(self):
        return self._get_query('URL')

    def get_ip_query(self):
        return self._get_query('IP')


class EDLPerformanceResult:
    def __init__(self, timeout: int, concurrent: int, ioc_type: str, size: int, result: str):
        self._t = timeout
        self._c = concurrent
        self._type = ioc_type
        self._size = size
        self._result = result

    def to_csv_line(self):
        df = pd.read_csv(StringIO(self._result), usecols=['response-time'])
        if len(df) == 0:
            max_time = 0
            avg_time = 0
            requests_num = 0
        else:
            response_times = df['response-time']
            max_time = max(response_times)
            avg_time = response_times.mean()
            requests_num = len(response_times)
        return f"{self._type},{self._size},{self._t},{self._c},{requests_num},{max_time},{avg_time}\n"

    @staticmethod
    def get_headers():
        return "type,size,timeout,concurrency,requests,max-time,average-time\nֿ"


# ---------- HELPER FUNCTIONS ---------- #

def run_command(command: str) -> str:
    """Run a bash command in the shell.

    Args:
        command (string): The string of the command you want to execute.

    Returns:
        string. The output of the command you are trying to execute.
    """
    p = Popen(command.split(), stdout=PIPE, stderr=PIPE, universal_newlines=True)
    output, err = p.communicate()
    if err:
        raise RuntimeError('Failed to run command {}\nerror details:\n{}'.format(command, err))

    return output


def run_test_for_ioc_types(hey_query: str, t: int, c: int, size: int) -> str:
    perf_results = ""
    edl_qb = EDLQueryBuilder(size)
    tests_map = {
        'IP': edl_qb.get_ip_query(),
        'URL': edl_qb.get_url_query(),
        'Domain': edl_qb.get_domain_query()
    }

    for ioc_type, edl_query in tests_map.items():
        result = tools.run_command(f'{hey_query}{edl_query}"')
        perf_results += EDLPerformanceResult(t, c, ioc_type, size, result).to_csv_line()
    return perf_results


def run_performance_test(edl_url: str) -> pd.DataFrame:
    test_results = EDLPerformanceResult.get_headers()
    for c in CONCURRENT_LIMITS:
        for t in TIMEOUT_LIMITS:
            for size in EDL_EXPECTED_SIZES:
                # TODO: Consider whether -z should be altered
                query = f'hey -c {c} -z 30s -t {t} -o csv "{edl_url}'
                test_results += run_test_for_ioc_types(query, t, c, size)
    test_results = test_results.replace('ֿI', 'I')  # first I is different I than the rest
    return pd.read_csv(StringIO(test_results)).sort_values(by=['type', 'size', 'concurrency'])


def hey_edl_test_command(url: str, edl_suffix: str, n: str = None, t: str = None, c: str = None, z: str = None):
    edl_url =

def main() -> None:
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()
    url = params.get('url')
    if isinstance(url, str) and url.endswith("/"):
        url = url[:-1]
    try:
        demisto.debug(f'Command being called is {command}')
        if command == 'hey-test-edl':
            hey_edl_test_command(url=url, **args)
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
