import argparse

import logging
import demisto_client
import time
import demisto_sdk.commands.common.tools as tools
from demisto_client.demisto_api.rest import ApiException
import pandas as pd
from io import StringIO


CONCURRENT_LIMITS = (1, 4, 8, 16)


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


# TODO: test instance configuration. KEEP ATTENTION: versn is dynamic
instance_execute_external = {
    "sysConf": {
        "instance.execute.external": "true",
        "versn": 10
    },
    "defaultMap": {
        "http_proxy": "",
        "https_proxy": "",
        "server.baseurl": "192.168.1.101:8443, 10.196.101.44:8443, fdfa:6a1c:c7b7:dec2::58:8443",
        "server.externalhostname": "TLVMACQ49VJG5J:8443"
    }
}


def run_test_suite(query: str, size: int):
    test_results = ""
    edl_qb = EDLQueryBuilder(size)
    tests_map = {
        'IP': edl_qb.get_url_query(),
        'URL': edl_qb.get_url_query(),
        'Domain': edl_qb.get_domain_query()
    }

    for ioc_type, edl_query in tests_map:
        hey_csv = tools.run_command(f'{query}{edl_query}"')
        df = pd.read_csv(StringIO(hey_csv))


# TODO: consider returning a class based result
def run_performance_test(edl_url: str,  size: int, t: int) -> str:
    for c in CONCURRENT_LIMITS:
        # TODO: Consider whether -z should be altered
        query = f'hey -c {c} -z 30s -t {t} -o csv "'


    hey_csv = tools.run_command(f'hey -n 16 -c 4 -t 120 -o csv "{edl_url}?q=*&n=99000"')
    return hey_csv


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
    api_instance = demisto_client.configure(base_url="http://localhost:8080", username="admin", password="admin")
    indicator_filter = demisto_client.demisto_api.IndicatorFilter(query="*")  # todo: use "paging" and put indicators filter into while loop
    total = 0
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

    # RUN PERFORMANCE TESTS
    # TODO: add for loop with different args
    test_result = run_performance_test()


if __name__ == "__main__":
    main()
