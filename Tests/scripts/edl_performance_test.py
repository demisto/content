import argparse

import logging
import demisto_client
import time
import demisto_sdk.commands.common.tools as tools
from demisto_client.demisto_api.rest import ApiException
import pandas as pd
from io import StringIO

EDL_EXPECTED_SIZES = (10*1000, 50*1000, 100*1000)
CONCURRENT_LIMITS = (1, 4, 8, 16)
# TIMEOUT_LIMITS = (3, 5, 10, 30)
TIMEOUT_LIMITS = (30, )  # TODO: Replace


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


class PerformanceResult:

    def __init__(self, timeout: int, concurrent: int, ioc_type: str, size: int, result: str):
        self._t = timeout
        self._c = concurrent
        self._type = ioc_type
        self._size = size
        self._result = result

    def to_result(self):
        df = pd.read_csv(StringIO(self._result), usecols=['response-time'])
        max_time = max(df['response-time'])
        avg_time = df['response-time'].mean()
        requests_num = len(df['response-time'])
        return f"{self._type},{self._size},{self._t},{self._c},{requests_num},{max_time},{avg_time}"

    @staticmethod
    def get_headers():
        return "type,size,timeout,concurrency,requests,max-time,average-time"


def poll_until_server_is_ready(ioc_total_target: int):
    api_instance = demisto_client.configure(base_url="http://localhost:8080", username="admin", password="admin")
    indicator_filter = demisto_client.demisto_api.IndicatorFilter(query="*", size=1, page=0)
    timeout = time.time() + 60 * 10  # 10 minutes from now
    while True:
        try:
            api_response = api_instance.indicators_search(indicator_filter=indicator_filter)
            total = api_response.total
            if time.time() > timeout:
                raise TimeoutError(f"Exception when waited for server to create [{ioc_total_target}] iocs. "
                                   f"fetched so far {total}")
            if total < ioc_total_target:
                time.sleep(60)
            else:
                break
        except ApiException as e:
            print(f"Exception when calling DefaultApi->indicators_search: {str(e)}\n")
    logging.info(f"Got {total} iocs")


def run_test_suite(hey_query: str, t: int, c: int, size: int) -> list:
    perf_results = []
    edl_qb = EDLQueryBuilder(size)
    tests_map = {
        'IP': edl_qb.get_ip_query(),
        'URL': edl_qb.get_url_query(),
        'Domain': edl_qb.get_domain_query()
    }

    for ioc_type, edl_query in tests_map.items():
        result = tools.run_command(f'{hey_query}{edl_query}"')
        perf_results.append(PerformanceResult(t, c, ioc_type, size, result).to_result())
    return perf_results


# TODO: consider returning a class based result
def run_performance_test(edl_url: str) -> list:
    test_results = [PerformanceResult.get_headers()]
    for c in CONCURRENT_LIMITS:
        for t in TIMEOUT_LIMITS:
            for size in EDL_EXPECTED_SIZES:
                # TODO: Consider whether -z should be altered
                query = f'hey -c {c} -z 5s -t {t} -o csv "{edl_url}'
                test_results.extend(run_test_suite(query, t, c, size))
            print('lol')
    return test_results


def options_handler():
    parser = argparse.ArgumentParser(description='Utility for running performance tests on EDL using '
                                                 '`Create-Mock-Feed` and `rakyll/hey`')
    parser.add_argument('-u', '--user', help='The username for the login', required=True)
    parser.add_argument('-p', '--password', help='The password for the login', required=True)
    options = parser.parse_args()

    return options


def main():
    # LOAD OPTIONS
    url = 'http://localhost:8080'  # todo take url from options
    edl_url = url + '/instance/execute/performance'  # todo: add edl name from options
    ioc_total_target = 100000  # todo: take from options

    # POLL UNTIL SERVER IS READY
    poll_until_server_is_ready(ioc_total_target)

    # RUN PERFORMANCE TESTS
    test_results = run_performance_test(edl_url)
    with open("performance_test.csv", "w") as f:
        f.write("\n".join(test_results))


if __name__ == "__main__":
    main()
