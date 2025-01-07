
import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *

""" IMPORTS """

import json
from datetime import datetime, timedelta
from collections.abc import Generator

import dateparser
import urllib3
import random
from requests.auth import HTTPBasicAuth

# Disable insecure warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
MAPPING: dict = {
    "compromised/account_group": {
        "date":
            "dateFirstSeen",
        "name":
            "login",
        "prefix":
            "Compromised Account",
        "indicators":
            [
                {
                    "main_field": "events.cnc.url", "main_field_type": "URL"
                },
                {
                    "main_field": "events.cnc.domain", "main_field_type": "Domain"
                },
                {
                    "main_field": "events.cnc.ipv4.ip", "main_field_type": "IP",
                    "add_fields": ["events.cnc.ipv4.asn", "events.cnc.ipv4.countryName", "events.cnc.ipv4.region"],
                    "add_fields_types": ["asn", "geocountry", "geolocation"]
                },
                {
                    "main_field": "events.client.ipv4.ip",
                }
            ]
    },
    "compromised/card": {
        "date":
            "dateDetected",
        "name":
            "cardInfo.number",
        "prefix":
            "Compromised Card",
        "indicators":
            [
                {
                    "main_field": "cnc.url", "main_field_type": "URL"
                },
                {
                    "main_field": "cnc.domain", "main_field_type": "Domain"
                },
                {
                    "main_field": "cnc.ipv4.ip", "main_field_type": "IP",
                    "add_fields": ["cnc.ipv4.asn", "cnc.ipv4.countryName", "cnc.ipv4.region"],
                    "add_fields_types": ["asn", "geocountry", "geolocation"]
                }
            ]
    },
    "compromised/breached": {
        "date":
            "uploadTime",
        "name":
            "email",
        "prefix":
            "Data Breach",
        "indicators": []
    },
    "bp/phishing": {
        "date":
            "dateDetected",
        "name":
            "phishingDomain.domain",
        "prefix":
            "Phishing",
        "indicators":
            [
                {
                    "main_field": "url", "main_field_type": "URL"
                },
                {
                    "main_field": "phishingDomain.domain", "main_field_type": "Domain",
                    "add_fields": ["phishingDomain.registrar"],
                    "add_fields_types": ["registrarname"]
                },
                {
                    "main_field": "ipv4.ip", "main_field_type": "IP"
                }
            ]
    },
    "bp/phishing_kit": {
        "date":
            "dateDetected",
        "name":
            "hash",
        "prefix":
            "Phishing Kit",
        "indicators":
            [
                {
                    "main_field": "emails", "main_field_type": "Email"
                }
            ]
    },
    # "bp/domain": {
    #     "date":
    #         "ts_create",
    #     "name":
    #         "attrs.domain",
    #     "prefix":
    #         "Phishing Domain",
    #     "indicators":
    #         [
    #             {
    #                 "main_field": "attrs.domain", "main_field_type": "Domain",
    #                 "add_fields": ["phishingDomain.registrar"],
    #                 "add_fields_types": ["registrarname"]
    #             },
    #             {
    #                 "main_field": "attrs.server_ip", "main_field_type": "IP",
    #                 "add_fields": ["attrs.server_ip_asn", "attrs.server_ip_country_name", "attrs.server_ip_region"],
    #                 "add_fields_types": ["asn", "geocountry", "geolocation"]
    #             }
    #         ]
    # },
    "osi/git_repository": {
        "date":
            "dateDetected",
        "name":
            "name",
        "prefix":
            "Git Leak",
    },
    "osi/public_leak": {
        "date":
            "created",
        "name":
            "hash",
        "prefix":
            "Public Leak",
    },
    "malware/targeted_malware": {
        "date":
            "date",
        "name":
            "injectMd5",
        "prefix":
            "Targeted Malware",
        "indicators":
            [
                {
                    "main_field": "md5", "main_field_type": "File",
                    "add_fields": ["fileName", "md5", "sha1", "sha256", "size"],
                    "add_fields_types": ["gibfilename", "md5", "sha1", "sha256", "size"]
                }
            ]
    },


    "compromised/mule": {
        "name":
            "account",
        "prefix":
            "Compromised Mule",
        "indicators":
            [
                {
                    "main_field": "cnc.url", "main_field_type": "URL",
                },
                {
                    "main_field": "cnc.domain", "main_field_type": "Domain",
                },
                {
                    "main_field": "cnc.ipv4.ip", "main_field_type": "IP",
                    "add_fields": ["cnc.ipv4.asn", "cnc.ipv4.countryName", "cnc.ipv4.region"],
                    "add_fields_types": ["asn", "geocountry", "geolocation"]
                }
            ]
    },
    "compromised/imei": {
        "name":
            "device.imei",
        "prefix":
            "Compromised IMEI",
        "indicators":
            [
                {
                    "main_field": "cnc.url", "main_field_type": "URL",
                },
                {
                    "main_field": "cnc.domain", "main_field_type": "Domain",
                },
                {
                    "main_field": "cnc.ipv4.ip", "main_field_type": "IP",
                    "add_fields": ["cnc.ipv4.asn", "cnc.ipv4.countryName", "cnc.ipv4.region"],
                    "add_fields_types": ["asn", "geocountry", "geolocation"]
                }
            ]
    },
    "attacks/ddos": {
        "name":
            "target.ipv4.ip",
        "prefix":
            "Attacks DDoS",
        "indicators":
            [
                {
                    "main_field": "cnc.url", "main_field_type": "URL",
                },
                {
                    "main_field": "cnc.domain", "main_field_type": "Domain",
                },
                {
                    "main_field": "cnc.ipv4.ip", "main_field_type": "IP",
                    "add_fields": ["cnc.ipv4.asn", "cnc.ipv4.countryName", "cnc.ipv4.region"],
                    "add_fields_types": ["asn", "geocountry", "geolocation"]
                },
            ]
    },
    "attacks/deface": {
        "name":
            "url",
        "prefix":
            "Attacks Deface",
        "indicators":
            [
                {
                    "main_field": "url", "main_field_type": "URL",
                },
                {
                    "main_field": "targetDomain", "main_field_type": "Domain",
                },
                {
                    "main_field": "targetIp.ip", "main_field_type": "IP",
                    "add_fields": ["targetIp.asn", "targetIp.countryName", "targetIp.region"],
                    "add_fields_types": ["asn", "geocountry", "geolocation"]
                }
            ]
    },
    "attacks/phishing": {
        "name":
            "phishingDomain.domain",
        "prefix":
            "Phishing",
        "indicators":
            [
                {
                    "main_field": "url", "main_field_type": "URL",
                },
                {
                    "main_field": "phishingDomain.domain", "main_field_type": "Domain",
                    "add_fields": ["phishingDomain.registrar"],
                    "add_fields_types": ["registrarname"]
                },
                {
                    "main_field": "ipv4.ip", "main_field_type": "IP",
                    "add_fields": ["ipv4.asn", "ipv4.countryName", "ipv4.region"],
                    "add_fields_types": ["asn", "geocountry", "geolocation"]
                }
            ]
    },
    "attacks/phishing_kit": {
        "name":
            "emails",
        "prefix":
            "Phishing Kit",
        "indicators":
            [
                {
                    "main_field": "emails", "main_field_type": "Email",
                }
            ]
    },
    "apt/threat": {
        "prefix":
            "Threat",
        "indicators":
            [
                {
                    "main_field": "indicators.params.ipv4", "main_field_type": "IP",
                },
                {
                    "main_field": "indicators.params.domain", "main_field_type": "Domain",
                },
                {
                    "main_field": "indicators.params.url", "main_field_type": "URL",
                },
                {
                    "main_field": "indicators.params.hashes.md5", "main_field_type": "File",
                    "add_fields":
                    [
                        "indicators.params.name", "indicators.params.hashes.md5",
                        "indicators.params.hashes.sha1",
                        "indicators.params.hashes.sha256", "indicators.params.size"
                    ],
                    "add_fields_types": ["gibfilename", "md5", "sha1", "sha256", "size"]
                }
            ]
    },
    "hi/threat": {
        "prefix":
            "Threat",
        "indicators":
            [
                 {
                     "main_field": "indicators.params.ipv4", "main_field_type": "IP",
                 },
                {
                     "main_field": "indicators.params.domain", "main_field_type": "Domain",
                 },
                {
                     "main_field": "indicators.params.url", "main_field_type": "URL",
                 },
                {
                     "main_field": "indicators.params.hashes.md5", "main_field_type": "File",
                     "add_fields":
                         [
                             "indicators.params.name", "indicators.params.hashes.md5",
                             "indicators.params.hashes.sha1",
                             "indicators.params.hashes.sha256", "indicators.params.size"
                         ],
                     "add_fields_types": ["gibfilename", "md5", "sha1", "sha256", "size"]
                 }
            ]
    },
    "suspicious_ip/tor_node": {
        "name":
            "ipv4.ip",
        "prefix":
            "Suspicious IP Tor Node",
        "indicators":
            [
                {
                    "main_field": "ipv4.ip", "main_field_type": "IP",
                    "add_fields": ["ipv4.asn", "ipv4.countryName", "ipv4.region"],
                    "add_fields_types": ["asn", "geocountry", "geolocation"]
                }
            ]
    },
    "suspicious_ip/open_proxy": {
        "name":
            "ipv4.ip",
        "prefix":
            "Suspicious IP Open Proxy",
        "indicators":
            [
                {
                    "main_field": "ipv4.ip", "main_field_type": "IP",
                    "add_fields": ["ipv4.asn", "ipv4.countryName", "ipv4.region"],
                    "add_fields_types": ["asn", "geocountry", "geolocation"]
                }
            ]
    },
    "suspicious_ip/socks_proxy": {
        "name":
            "ipv4.ip",
        "prefix":
            "Suspicious IP Socks Proxy",
        "indicators":
            [
                {
                    "main_field": "ipv4.ip", "main_field_type": "IP",
                    "add_fields": ["ipv4.asn", "ipv4.countryName", "ipv4.region"],
                    "add_fields_types": ["asn", "geocountry", "geolocation"]
                }
            ]
    },
    "malware/cnc": {
        "name":
            "ipv4.ip",
        "prefix":
            "Malware CNC",
        "indicators":
            [
                {
                    "main_field": "url", "main_field_type": "URL"
                },
                {
                    "main_field": "domain", "main_field_type": "Domain"
                },
                {
                    "main_field": "ipv4.ip", "main_field_type": "IP",
                    "add_fields": ["ipv4.asn", "ipv4.countryName", "ipv4.region"],
                    "add_fields_types": ["asn", "geocountry", "geolocation"]
                }
            ]
    },
    "osi/vulnerability": {
        "name":
            "id",
        "prefix":
            "OSI Vulnerability",
        "indicators":
            [
                {
                    "main_field": "id", "main_field_type": "CVE",
                    "add_fields": ["cvss.score", "description", "dateLastSeen", "datePublished"],
                    "add_fields_types": ["cvss", "cvedescription", "cvemodified", "published"]
                }
            ]
    },
    "hi/threat_actor": {"prefix": "Threat Actor"},
    "apt/threat_actor": {"prefix": "Threat Actor"}
}

STATUS_CODE_MSGS = {
    401: "Bad Credentials",
    403: "Something is wrong with your account, please, contact GIB.",
    404: "Not found. There is no such data on server.",
    500: "There are some troubles on server with your request.",
    301: "Verify that your public IP is whitelisted by Group IB.",
    302: "Verify that your public IP is whitelisted by Group IB."
}

# LEGACY_HEADERS = {
#     "Accept": "application/json",
#     'Connection': 'Keep-Alive',
#     'Keep-Alive': "30"
# }

TIMEOUT = 60.
RETRIES = 4
STATUS_LIST_TO_RETRY = [429, 500]


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def _create_update_generator(self, collection_name: str, max_requests: int,
                                 date_from: str | None = None, seq_update: int | str = '',
                                 limit: int = 200) -> Generator:
        """
        Creates generator of lists with feeds class objects for an update session
        (feeds are sorted in ascending order) `collection_name` with set parameters.

        `seq_update` allows you to receive all relevant feeds. Such a request uses the seq_update parameter,
        you will receive a portion of feeds that starts with the next `seq_update` parameter for the current collection.
        For all feeds in the Group IB Intelligence continuous numbering is carried out.
        For example, the `seq_update` equal to 1999998 can be in the `compromised/accounts` collection,
        and a feed with seq_update equal to 1999999 can be in the `attacks/ddos` collection.
        If item updates (for example, if new attacks were associated with existing APT by our specialists
        or tor node has been detected as active again), the item gets a new parameter and it automatically rises
        in the database and "becomes relevant" again.

        :param collection_name: collection to update.
        :param max_requests: a maximum number of requests to API.
        :param date_from: start date of update session.
        :param seq_update: identification number from which to start the session.
        """
        requests_count = 0
        while True:
            if requests_count >= max_requests:
                break
            session = requests.Session()
            session.auth = HTTPBasicAuth(self._auth[0], self._auth[1])

            session.headers["Accept"] = "*/*"
            session.headers["User-Agent"] = f'SOAR/CortexSOAR/{self._auth[0]}/unknown'

            params = {'df': date_from, 'limit': limit, 'seqUpdate': seq_update}
            params = {key: value for key, value in params.items() if value}
            portion = session.get(url=f'{self._base_url}{collection_name}/updated', params=params, timeout=60).json()

            # params = {"df": date_from, "seqUpdate": seq_update}
            # params = assign_params(**params)
            # portion = self._http_request(method="GET", url_suffix=collection_name + "/updated",
            #                              params=params, timeout=TIMEOUT, retries=RETRIES,
            #                              status_list_to_retry=STATUS_LIST_TO_RETRY)
            if portion.get("count") == 0:
                break
            seq_update = portion.get("seqUpdate")
            date_from = None
            requests_count += 1

            yield portion.get("items"), seq_update

    def _create_search_generator(self, collection_name: str, max_requests: int, date_to: str = None,
                                 page: int = 0, starting_date_from: str = None,
                                 starting_date_to: str = None, limit: int = 200) -> Generator:
        """
        Creates generator of lists with feeds for the search session for ingestion purpose
        (feeds are sorted in descending order) for `collection_name` with set parameters. This version solves problem
        with a large number of feeds with the same date.

        :param collection_name: collection to search.
        :param max_requests: a maximum number of requests to API.
        :param date_to: current search location.
        :param page: number of pages from start.
        :param starting_date_from: global down border for a session.
        :param starting_date_to: global upper border for a session.
        """

        requests_count = 0
        result_id = None
        no_data_flag = 0
        while True:
            if requests_count >= max_requests or no_data_flag:
                break

            if page and not result_id:
                k = 0
                while k != page:
                    if result_id:
                        params = {'resultId': result_id}
                    else:
                        params = {'df': starting_date_from, 'dt': date_to}
                    params = assign_params(**params)
                    portion = self._http_request(method="GET", url_suffix=collection_name,
                                                 params=params, timeout=TIMEOUT, retries=RETRIES,
                                                 status_list_to_retry=STATUS_LIST_TO_RETRY)
                    result_id = portion.get("resultId")
                    k += 1

            if result_id:
                params = {'resultId': result_id}
            else:
                params = {'df': starting_date_from, 'dt': date_to}
            params = assign_params(**params)
            portion = self._http_request(method="GET", url_suffix=collection_name,
                                         params=params, timeout=TIMEOUT, retries=RETRIES,
                                         status_list_to_retry=STATUS_LIST_TO_RETRY)

            requests_count += 1
            data = portion.get('items')
            if len(data) < 100:
                no_data_flag = 1
                page = 0
                starting_date_from = (dateparser.parse(starting_date_to)   # type: ignore
                                      + timedelta(seconds=1)).strftime(DATE_FORMAT)
                starting_date_to = datetime.now().strftime(DATE_FORMAT)
                date_to = starting_date_to
            else:
                if data[0].get("uploadTime") == data[-1].get("uploadTime"):
                    page += 1
                else:
                    result_id = None
                    page = 0
                    for i in range(len(data) - 1, -1, -1):
                        if data[i].get("uploadTime") != data[-1].get("uploadTime"):
                            upload_time_parsed = dateparser.parse(data[i].get("uploadTime"))
                            assert upload_time_parsed is not None, f'could not parse {data[i].get("uploadTime")}'
                            date_to = (upload_time_parsed - timedelta(seconds=1)).strftime(DATE_FORMAT)
                            data = data[:i + 1:]
                            break

            last_fetch = {"starting_date_from": starting_date_from, "page": page,
                          "starting_date_to": starting_date_to, "current_date_to": date_to}
            yield data, last_fetch

    # def _create_legacy_generator(self, action: str, max_requests: int, last: Optional[str] = None) -> Generator:
    #     """
    #     Legacy generator is similar to update generator.
    #
    #     :param action: collection to search.
    #     :param max_requests: a maximum number of requests to API.
    #     :param last: identification number from which to start the session.
    #     """
    #     requests_count = 0
    #     while True:
    #         if requests_count >= max_requests:
    #             break
    #
    #         params = {"action": action, "last": last, "module": "get", "lang": 3}
    #         params = assign_params(**params)
    #         portion = self._http_request(method="GET", full_url="https://bt.group-ib.com",
    #                                      headers=LEGACY_HEADERS, params=params, timeout=TIMEOUT, retries=RETRIES,
    #                                      status_list_to_retry=STATUS_LIST_TO_RETRY)
    #         if portion.get("status") != 200:
    #             if portion.get("status") in STATUS_CODE_MSGS:
    #                 raise DemistoException(STATUS_CODE_MSGS[portion.get("status")])
    #             else:
    #                 raise DemistoException(
    #                     "Something is wrong, status code {0} for request to APIv1".format(portion.get("status"))
    #                 )
    #         portion = portion.get("data")
    #
    #         if portion.get("count") == 0:
    #             break
    #         last = portion.get("last")
    #         requests_count += 1
    #
    #         yield portion.get("new"), last
    #
    # def _legacy_get_last(self, date_from, action):
    #     """
    #     Get last for a certain date.
    #
    #     :param action: collection to search.
    #     :param date_from: date to get the "last" identifier.
    #     """
    #     params = {"action": "get_last", "date": date_from, "module": "get", "type": action}
    #     params = assign_params(**params)
    #     resp = self._http_request(method="GET", full_url="https://bt.group-ib.com",
    #                               headers=LEGACY_HEADERS, params=params, timeout=TIMEOUT, retries=RETRIES,
    #                               status_list_to_retry=STATUS_LIST_TO_RETRY)
    #     if resp.get("status") != 200:
    #         if resp.get("status") in STATUS_CODE_MSGS:
    #             raise DemistoException(STATUS_CODE_MSGS[resp.get("status")])
    #         else:
    #             raise DemistoException(
    #                 "Something is wrong, status code {0} for request to APIv1".format(resp.get("status"))
    #             )
    #     last = resp.get("data")
    #     return last

    def create_poll_generator(self, collection_name: str, max_requests: int, **kwargs):
        """
        Interface to work with different types of indicators.
        """

        # Handle first time fetch
        date_from = None
        last_fetch = kwargs.get("last_fetch")
        if not last_fetch:
            date_from = dateparser.parse(kwargs.get("first_fetch_time"))  # type: ignore
            if date_from is None:
                raise DemistoException('Inappropriate first_fetch format, '
                                       'please use something like this: 2020-01-01 or January 1 2020 or 3 days')
            date_from = date_from.strftime('%Y-%m-%d')  # type: ignore

        if collection_name == "compromised/breached":
            # we need the isinstance check for BC because it used to be a string
            if last_fetch and isinstance(last_fetch, dict):
                starting_date_from = last_fetch.get("starting_date_from")
                starting_date_to = last_fetch.get("starting_date_to")
                date_to = last_fetch.get("current_date_to")
                page = last_fetch.get("page", 0)
            else:
                starting_date_from = date_from
                starting_date_to = datetime.now().strftime(DATE_FORMAT)
                date_to = starting_date_to
                page = 0
            return self._create_search_generator(collection_name=collection_name, max_requests=max_requests,
                                                 date_to=date_to, page=page, starting_date_from=starting_date_from,
                                                 starting_date_to=starting_date_to)
        # elif collection_name == "bp/domain":
        #     if not last_fetch:
        #         last_fetch = self._legacy_get_last(date_from=date_from, action="domain")
        #     return self._create_legacy_generator(action="domain", max_requests=max_requests, last=last_fetch)
        else:
            return self._create_update_generator(collection_name=collection_name, max_requests=max_requests,
                                                 date_from=date_from, seq_update=last_fetch)  # type: ignore

    def create_manual_generator(self, collection_name: str, date_from: str = None,
                                date_to: str = None, query: str = None) -> Generator:
        """
        Creates generator of lists with feeds for the search session
        (feeds are sorted in descending order) for `collection_name` with set parameters.

        :param collection_name: collection to search.
        :param date_from: start date of search session.
        :param date_to: end date of search session.
        :param query: query to search.
        """

        result_id = None
        while True:
            params = {'df': date_from, 'dt': date_to, 'resultId': result_id, 'q': query}
            params = assign_params(**params)
            portion = self._http_request(method="GET", url_suffix=collection_name,
                                         params=params, timeout=TIMEOUT, retries=RETRIES,
                                         status_list_to_retry=STATUS_LIST_TO_RETRY)
            if portion.get('count') > 2000:
                raise DemistoException('Portion is too large (count > 2000), this can cause timeout in Demisto.'
                                       'Please, change or set date_from/date_to arguments or change query.')
            if len(portion.get('items')) == 0:
                break
            result_id = portion.get("resultId")
            date_from, date_to, query = None, None, None
            yield portion.get('items')

    def search_feed_by_id(self, collection_name: str, feed_id: str) -> dict:
        """
        Searches for feed with `feed_id` in collection with `collection_name`.

        :param collection_name: in what collection to search.
        :param feed_id: id of feed to search.
        """
        portion = self._http_request(method="GET", url_suffix=collection_name + "/" + feed_id, timeout=TIMEOUT,
                                     retries=RETRIES, status_list_to_retry=STATUS_LIST_TO_RETRY,
                                     backoff_factor=random.random() * 10 + 1)

        return portion

    def get_available_collections(self):
        """
        Gets list of available collections from GIB TI&A API.
        """

        response = self._http_request(method="GET", url_suffix="user/granted_collections",
                                      timeout=TIMEOUT, retries=RETRIES,
                                      status_list_to_retry=STATUS_LIST_TO_RETRY)
        buffer_list = find_element_by_key(response, 'collection')

        # buffer_list = list(response.get("list").keys())
        #
        # try:
        #     self._http_request(method="GET", url_suffix="compromised/breached", params={"limit": 1},
        #                        timeout=TIMEOUT, retries=RETRIES, status_list_to_retry=STATUS_LIST_TO_RETRY)
        #     buffer_list.append("compromised/breached")
        # except Exception:
        #     pass
        #
        # # legacy collection
        # try:
        #     params = {"action": "get_last", "date": datetime.now().strftime("%Y-%m-%d"),
        #               "module": "get", "type": "domain"}
        #     response = self._http_request(method="GET", full_url="https://bt.group-ib.com",
        #                                   headers=LEGACY_HEADERS, params=params, timeout=TIMEOUT, retries=RETRIES,
        #                                   status_list_to_retry=STATUS_LIST_TO_RETRY)
        #     last = response.get("data")
        #     params = {"action": "domain", "last": last, "module": "get"}
        #     portion = self._http_request(method="GET", full_url="https://bt.group-ib.com",
        #                                  headers=LEGACY_HEADERS, params=params, timeout=TIMEOUT, retries=RETRIES,
        #                                  status_list_to_retry=STATUS_LIST_TO_RETRY)
        #     if portion.get("status") == 200:
        #         buffer_list.append("bp/domain")
        # except Exception:
        #     pass

        collections_list = []
        for key in MAPPING:
            if key in buffer_list:
                collections_list.append(key)
        return {"collections": collections_list}, buffer_list

    def search_by_query(self, q):
        results = self._http_request(method="GET", url_suffix="search", params={'q': q},
                                     timeout=TIMEOUT, retries=RETRIES,
                                     status_list_to_retry=STATUS_LIST_TO_RETRY)
        return results


def test_module(client: Client) -> str:
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.

    :param client: GIB_TI&A client
    :return: 'ok' if test passed, anything else will fail the test.
    """

    collections_list, _ = client.get_available_collections()
    for collection in collections_list.get("collections"):
        if collection not in MAPPING:
            return "Test failed, some problems with getting available collections."
    return "ok"


""" Support functions """


def find_element_by_key(obj, key):
    """
    Recursively finds element or elements in dict.
    """

    path = key.split(".", 1)
    if len(path) == 1:
        if isinstance(obj, list):
            return [i.get(path[0]) for i in obj if i not in ["255.255.255.255", "0.0.0.0", ""]]
        elif isinstance(obj, dict):
            if obj.get(path[0]) in ["255.255.255.255", "0.0.0.0", ""]:
                return None
            else:
                return obj.get(path[0])
        else:
            if obj in ["255.255.255.255", "0.0.0.0", ""]:
                return None
            else:
                return obj
    else:
        if isinstance(obj, list):
            return [find_element_by_key(i.get(path[0]), path[1]) for i in obj]
        elif isinstance(obj, dict):
            return find_element_by_key(obj.get(path[0]), path[1])
        else:
            if obj in ["255.255.255.255", "0.0.0.0", ""]:
                return None
            else:
                return obj


def transform_to_command_results(iocs, ioc_type, fields, fields_names, collection_name):
    """
    Recursively ties together and transforms indicator data.
    """

    parsed_info = []
    if isinstance(iocs, list):
        for i, ioc in enumerate(iocs):
            buf_fields = []
            for field in fields:
                if isinstance(field, list):
                    buf_fields.append(field[i])
                else:
                    buf_fields.append(field)
            parsed_info.extend(transform_to_command_results(ioc, ioc_type, buf_fields, fields_names, collection_name))
        return parsed_info
    else:
        if iocs is None:
            return []

        fields = {fields_names[i]: fields[i] for i in range(len(fields_names)) if fields[i] is not None}

        output = parse_to_outputs(iocs, ioc_type, fields)
        if output:
            results = [CommandResults(
                readable_output=tableToMarkdown(f"{ioc_type} indicator", {"value": iocs, **fields}),
                indicator=output,
                ignore_auto_extract=True
            )]
            return results
        else:
            return []


def parse_to_outputs(value, indicator_type, fields):
    def calculate_dbot_score(type_):
        severity = fields.get("severity")
        if severity == "green":
            score = Common.DBotScore.GOOD
        elif severity == "orange":
            score = Common.DBotScore.SUSPICIOUS
        elif severity == "red":
            score = Common.DBotScore.BAD
        else:
            score = Common.DBotScore.NONE

        return Common.DBotScore(
            indicator=value,
            indicator_type=type_,
            integration_name="GIB TI&A",
            score=score
        )

    if indicator_type == "IP":
        return Common.IP(ip=value, asn=fields.get("asn"), geo_country=fields.get("geocountry"),
                         geo_description=fields.get("geolocation"),
                         dbot_score=calculate_dbot_score(DBotScoreType.IP))
    elif indicator_type == "Domain":
        return Common.Domain(domain=value, registrar_name=fields.get("registrarname"),
                             dbot_score=calculate_dbot_score(DBotScoreType.DOMAIN))
    elif indicator_type == "File":
        return Common.File(md5=value, sha1=fields.get("sha1"), sha256=fields.get("sha256"),
                           name=fields.get("gibfilename"), size=fields.get("size"),
                           dbot_score=calculate_dbot_score(DBotScoreType.FILE))
    elif indicator_type == "URL":
        return Common.URL(url=value, dbot_score=calculate_dbot_score(DBotScoreType.URL))
    elif indicator_type == "CVE":
        return Common.CVE(id=value, cvss=fields.get("cvss"), published=fields.get("published"),
                          modified=fields.get("cvemodified"), description=fields.get("cvedescription"))
    return None


def find_iocs_in_feed(feed: dict, collection_name: str) -> list:
    """
    Finds IOCs in the feed and transform them to the appropriate format to ingest them into Demisto.

    :param feed: feed from GIB TI&A.
    :param collection_name: which collection this feed belongs to.
    """

    indicators = []
    indicators_info = MAPPING.get(collection_name, {}).get("indicators", [])
    for i in indicators_info:
        main_field = find_element_by_key(feed, i["main_field"])
        main_field_type = i["main_field_type"]
        add_fields = []
        add_fields_list = i.get("add_fields", []) + ["evaluation.severity"]
        add_fields_types = i.get("add_fields_types", []) + ["severity"]
        for j in add_fields_list:
            add_fields.append(find_element_by_key(feed, j))
        parsed_info = transform_to_command_results(main_field, main_field_type,
                                                   add_fields, add_fields_types, collection_name)
        indicators.extend(parsed_info)

    return indicators


def transform_some_fields_into_markdown(collection_name, feed: dict) -> dict:
    """
    Some fields can have complex nesting, so this function transforms them into an appropriate state.

    :param collection_name: which collection this feed belongs to.
    :param feed: feed from GIB TI&A that needs transformation.
    :return: given feed with transformed fields.
    """

    if collection_name == "osi/git_repository":
        buffer = ""
        files = feed.get("files", [])
        for i in files:
            url = i.get("url")
            date = i.get("dateCreated")
            # file_diff = "[https://bt.group-ib.com/api/v2/osi/git_leak]({0})".format(i.get("fileDiff"))
            # info = find_element_by_key(i,'revisions.info')
            author_email = ''.join(str(find_element_by_key(i, 'revisions.info.authorEmail')))
            author_name = ''.join(str(find_element_by_key(i, 'revisions.info.authorName')))
            timestamp = ''.join(str(find_element_by_key(i, 'revisions.info.timestamp')))
            # author_email, author_name, date = info.get("authorEmail"), info.get("authorName"), info.get("dateCreated")
            buffer += f"| {url} | {author_email} | {author_name} | {date} | {timestamp} |\n"
        if buffer:
            buffer = "| URL  |   Author Email  | Author Name  | Date Created| TimeStamp    |\n" \
                     "| ---- | --------------- | ------------ | ----------- | ------------ |\n" + buffer
            feed["files"] = buffer
        else:
            del feed["files"]

    elif collection_name == "osi/public_leak":
        buffer = ""
        link_list = feed.get("linkList", [])
        for i in link_list:
            author = i.get("author")
            detected = i.get("dateDetected")
            published = i.get("datePublished")
            hash_ = i.get("hash")
            link = "[{0}]({0})".format(i.get("link"))
            source = i.get("source")
            buffer += f"| {author} | {detected} | {published} | {hash_} | {link} | {source} |\n"
        if buffer:
            buffer = "| Author | Date Detected | Date Published | Hash | Link | Source |\n" \
                     "| ------ | ------------- | -------------- | ---- |----- | ------ |\n" + buffer
            feed["linkList"] = buffer
        else:
            del feed["linkList"]

        buffer = ""
        matches = feed.get("matches", {})
        if isinstance(matches, list):
            matches = {}
        for type_, sub_dict in matches.items():
            for sub_type, sub_list in sub_dict.items():
                for value in sub_list:
                    buffer += f"| {type_} | {sub_type} | {value} |\n"
        if buffer:
            buffer = "| Type | Sub Type | Value |\n" \
                     "| ---- | -------- | ----- |\n" + buffer
            feed["matches"] = buffer
        else:
            del feed["matches"]

    elif collection_name == "bp/phishing_kit":
        buffer = ""
        downloaded_from = feed.get("downloadedFrom", [])
        for i in downloaded_from:
            date, url, domain, filename = i.get("date"), i.get("url"), i.get("domain"), i.get("fileName")
            buffer += f"| {url} | {filename} | {domain} | {date} |\n"
        if buffer:
            buffer = "| URL | File Name | Domain | Date |\n| --- | --------- | ------ | ---- |\n" + buffer
            feed["downloadedFrom"] = buffer
        else:
            del feed["downloadedFrom"]

    return feed


def get_human_readable_feed(collection_name, feed):
    return tableToMarkdown(name="Feed from {} with ID {}".format(collection_name, feed.get("id")),
                           t=feed, removeNull=True)


def transform_function(result, previous_keys="", is_inside_list=False):
    result_dict = {}
    additional_tables: list[Any] = []

    if isinstance(result, dict):
        if is_inside_list:
            additional_tables.append(result)
        else:
            for key, value in result.items():
                sub_key = previous_keys + " " + key if previous_keys else key
                transformed_part, additional_info = transform_function(value, previous_keys=sub_key,
                                                                       is_inside_list=is_inside_list)
                result_dict.update(transformed_part)
                additional_tables.extend(additional_info)

        return result_dict, additional_tables

    elif isinstance(result, list):
        is_inside_list = True
        for value in result:
            transformed_part, additional_info = transform_function(value, previous_keys=previous_keys,
                                                                   is_inside_list=is_inside_list)
            additional_tables.extend(additional_info)
            if result_dict.get(previous_keys) is None:
                result_dict.update(transformed_part)
            else:
                result_dict[previous_keys].extend(transformed_part[previous_keys])

        if additional_tables:
            additional_tables = [CommandResults(
                readable_output=tableToMarkdown(f"{previous_keys} table", additional_tables, removeNull=True),
                ignore_auto_extract=True
            )]

        return result_dict, additional_tables

    elif isinstance(result, str | int | float) or result is None:
        if not is_inside_list:
            result_dict.update({previous_keys: result})
        else:
            result_dict.update({previous_keys: [result]})

        return result_dict, additional_tables
    return None


""" Commands """


def fetch_incidents_command(client: Client, last_run: dict, first_fetch_time: str,
                            incident_collections: list, requests_count: int) -> tuple[dict, list]:
    """
    This function will execute each interval (default is 1 minute).

    :param client: GIB_TI&A_Feed client.
    :param last_run: the greatest sequpdate we fetched from last fetch.
    :param first_fetch_time: if last_run is None then fetch all incidents since first_fetch_time.
    :param incident_collections: list of collections enabled by client.
    :param requests_count: count of requests to API per collection.

    :return: next_run will be last_run in the next fetch-incidents; incidents and indicators will be created in Demisto.
    """
    incidents = []
    next_run: dict[str, dict[str, int | Any]] = {"last_fetch": {}}
    for collection_name in incident_collections:
        last_fetch = last_run.get("last_fetch", {}).get(collection_name)

        portions = client.create_poll_generator(collection_name=collection_name, max_requests=requests_count,
                                                last_fetch=last_fetch, first_fetch_time=first_fetch_time)
        for portion, last_fetch in portions:
            for feed in portion:
                mapping = MAPPING.get(collection_name, {})
                if collection_name == "compromised/breached":
                    feed.update({"name": mapping.get("prefix", "") + ": " + ', '.join(
                        find_element_by_key(feed, mapping.get("name")))})
                else:
                    feed.update({"name": mapping.get("prefix", "") + ": " + str(
                        find_element_by_key(feed, mapping.get("name")))})

                feed.update({"gibType": collection_name})

                severity = feed.get("evaluation", {}).get("severity")
                system_severity = 0
                if severity == "green":
                    system_severity = 1
                elif severity == "orange":
                    system_severity = 2
                elif severity == "red":
                    system_severity = 3

                related_indicators_data = []
                indicators_info = MAPPING.get(collection_name, {}).get("indicators", [])
                for i in indicators_info:
                    if find_element_by_key(feed, i["main_field"]) is not None:
                        related_indicators_data.append(find_element_by_key(feed, i["main_field"]))

                incident_created_time = dateparser.parse(feed.get(mapping.get("date")))
                assert incident_created_time is not None
                feed.update({"relatedIndicatorsData": related_indicators_data})
                feed.update({"systemSeverity": system_severity})
                if collection_name in ["osi/git_repository", "osi/public_leak", "bp/phishing_kit"]:
                    feed = transform_some_fields_into_markdown(collection_name, feed)
                incident = {
                    "name": feed["name"],
                    "occurred": incident_created_time.strftime(DATE_FORMAT),
                    "rawJSON": json.dumps(feed)
                }
                incidents.append(incident)

        next_run["last_fetch"][collection_name] = last_fetch

    return next_run, incidents


def get_available_collections_command(client: Client):
    """
    Returns list of available collections to context and War Room.

    :param client: GIB_TI&A_Feed client.
    """

    result, buffer_list = client.get_available_collections()
    readable_output = tableToMarkdown(name="Available collections", t=result, headers="collections")
    return CommandResults(
        outputs_prefix="GIBTIA.OtherInfo",
        outputs_key_field="collections",
        outputs=result,
        readable_output=readable_output,
        ignore_auto_extract=True,
        raw_response=buffer_list
    )


def get_info_by_id_command(collection_name: str):
    """
    Decorator around actual commands, that returns command depends on `collection_name`.
    """

    def get_info_by_id_for_collection(client: Client, args: dict) -> list[CommandResults]:
        """
        This function returns additional information to context and War Room.

        :param client: GIB_TI&A_Feed client.
        :param args: arguments, provided by client.
        """
        results = []
        coll_name = collection_name
        id_ = str(args.get("id"))

        if coll_name in ["threat", "threat_actor"]:
            flag = args.get("isAPT")
            if flag:
                coll_name = "apt/" + coll_name
            else:
                coll_name = "hi/" + coll_name
            result = client.search_feed_by_id(coll_name, id_)
            if "displayOptions" in result:
                del result["displayOptions"]

        else:
            result = client.search_feed_by_id(coll_name, id_)
            if "isFavourite" in result:
                del result["isFavourite"]
            if "isHidden" in result:
                del result["isHidden"]

        if "seqUpdate" in result:
            del result["seqUpdate"]

        indicators: list[CommandResults] = []
        if coll_name not in ["apt/threat_actor", "hi/threat_actor"]:
            indicators = find_iocs_in_feed(result, coll_name)

        if coll_name in ["apt/threat", "hi/threat"]:
            del result["indicatorMalwareRelationships"], result["indicatorRelationships"], \
                result["indicatorToolRelationships"], result["indicatorsIds"], \
                result["indicators"]

        if coll_name == "compromised/breached":
            if "updateTime" in result:
                del result["updateTime"]
            main_table_data, additional_tables = result, []
        else:
            main_table_data, additional_tables = transform_function(result)
        results.append(CommandResults(
            outputs_prefix="GIBTIA.{}".format(MAPPING.get(coll_name, {}).get("prefix", "").replace(" ", "")),
            outputs_key_field="id",
            outputs=result,
            readable_output=get_human_readable_feed(collection_name, main_table_data),
            raw_response=result,
            ignore_auto_extract=True
        ))
        results.extend(additional_tables)
        results.extend(indicators)
        return results

    return get_info_by_id_for_collection


def global_search_command(client: Client, args: dict):
    query = str(args.get('query'))
    raw_response = client.search_by_query(query)
    handled_list = []
    for result in raw_response:
        if result.get('apiPath') in MAPPING:
            handled_list.append({'apiPath': result.get('apiPath'), 'count': result.get('count'),
                                 'GIBLink': result.get('link'),
                                 'query': result.get('apiPath') + '?q=' + query})
    if len(handled_list) != 0:
        results = CommandResults(
            outputs_prefix="GIBTIA.search.global",
            outputs_key_field="query",
            outputs=handled_list,
            readable_output=tableToMarkdown('Search results', t=handled_list,
                                            headers=['apiPath', 'count', 'GIBLink'],
                                            url_keys=['GIBLink']),
            raw_response=raw_response,
            ignore_auto_extract=True
        )
    else:
        results = CommandResults(
            raw_response=raw_response,
            ignore_auto_extract=True,
            outputs=[],
            readable_output="Did not find anything for your query :("
        )
    return results


def local_search_command(client: Client, args: dict):
    query, date_from, date_to = args.get('query'), args.get('date_from', None), args.get('date_to', None)
    collection_name = str(args.get('collection_name'))

    if date_from is not None:
        date_from_parsed = dateparser.parse(date_from)
        if date_from_parsed is None:
            raise DemistoException('Inappropriate date_from format, '
                                   'please use something like this: 2020-01-01 or January 1 2020')
        date_from_parsed = date_from_parsed.strftime('%Y-%m-%dT%H:%M:%SZ')
    else:
        date_from_parsed = date_from  # type: ignore
    if date_to is not None:
        date_to_parsed = dateparser.parse(date_to)
        if date_to_parsed is None:
            raise DemistoException('Inappropriate date_to format, '
                                   'please use something like this: 2020-01-01 or January 1 2020')
        date_to_parsed = date_to_parsed.strftime('%Y-%m-%dT%H:%M:%SZ')
    else:
        date_to_parsed = date_to  # type: ignore

    portions = client.create_manual_generator(collection_name=collection_name, query=query,
                                              date_from=date_from_parsed, date_to=date_to_parsed)
    result_list = []
    name = MAPPING.get(collection_name, {}).get('name')
    for portion in portions:
        for feed in portion:
            add_info = None
            if name is not None:
                add_info = name + ": " + str(find_element_by_key(feed, name))
            result_list.append({'id': feed.get('id'), 'additional_info': add_info})

    results = CommandResults(
        outputs_prefix="GIBTIA.search.local",
        outputs_key_field="id",
        outputs=result_list,
        readable_output=tableToMarkdown('Search results', t=result_list,
                                        headers=['id', 'additional_info']),
        ignore_auto_extract=True
    )
    return results


def main():
    """
        PARSE AND VALIDATE INTEGRATION PARAMS
    """
    params = demisto.params()
    username = params.get("credentials").get("identifier")
    password = params.get("credentials").get("password")
    base_url = str(params.get("url"))
    proxy = params.get("proxy", False)
    verify_certificate = not params.get("insecure", False)

    incident_collections = params.get("incident_collections", [])
    incidents_first_fetch = params.get("first_fetch", "3 days").strip()
    requests_count = int(params.get("max_fetch", 3))

    args = demisto.args()
    command = demisto.command()
    LOG(f"Command being called is {command}")
    try:
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            auth=(username, password),
            proxy=proxy,
            headers={"Accept": "*/*"}
        )

        commands = {
            "gibtia-get-compromised-account-info": get_info_by_id_command("compromised/account_group"),
            "gibtia-get-compromised-card-info": get_info_by_id_command("compromised/card"),
            "gibtia-get-compromised-mule-info": get_info_by_id_command("compromised/mule"),
            "gibtia-get-compromised-imei-info": get_info_by_id_command("compromised/imei"),
            "gibtia-get-compromised-breached-info": get_info_by_id_command("compromised/breached"),
            "gibtia-get-phishing-kit-info": get_info_by_id_command("attacks/phishing_kit"),
            "gibtia-get-phishing-info": get_info_by_id_command("attacks/phishing"),
            "gibtia-get-osi-git-leak-info": get_info_by_id_command("osi/git_repository"),
            "gibtia-get-osi-public-leak-info": get_info_by_id_command("osi/public_leak"),
            "gibtia-get-osi-vulnerability-info": get_info_by_id_command("osi/vulnerability"),
            "gibtia-get-attacks-ddos-info": get_info_by_id_command("attacks/ddos"),
            "gibtia-get-attacks-deface-info": get_info_by_id_command("attacks/deface"),
            "gibtia-get-threat-info": get_info_by_id_command("threat"),
            "gibtia-get-threat-actor-info": get_info_by_id_command("threat_actor"),
            "gibtia-get-suspicious-ip-tor-node-info": get_info_by_id_command("suspicious_ip/tor_node"),
            "gibtia-get-suspicious-ip-open-proxy-info": get_info_by_id_command("suspicious_ip/open_proxy"),
            "gibtia-get-suspicious-ip-socks-proxy-info": get_info_by_id_command("suspicious_ip/socks_proxy"),
            "gibtia-get-malware-targeted-malware-info": get_info_by_id_command("malware/targeted_malware"),
            "gibtia-get-malware-cnc-info": get_info_by_id_command("malware/cnc"),
            "gibtia-get-available-collections": get_available_collections_command,
            "gibtia-global-search": global_search_command,
            "gibtia-local-search": local_search_command
        }

        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            demisto.results(result)

        elif command == "fetch-incidents":
            # Set and define the fetch incidents command to run after activated via integration settings.
            next_run, incidents = fetch_incidents_command(client=client, last_run=demisto.getLastRun(),
                                                          first_fetch_time=incidents_first_fetch,
                                                          incident_collections=incident_collections,
                                                          requests_count=requests_count)
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)
        else:
            return_results(commands[command](client, args))

    # Log exceptions
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
