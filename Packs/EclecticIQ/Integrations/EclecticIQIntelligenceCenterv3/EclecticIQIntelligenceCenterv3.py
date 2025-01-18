import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

""" IMPORTS """

import csv
import io
import json
import logging
import re
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

""" GLOBALS/PARAMS """

PASSWORD = demisto.params().get("eiq_token")
URL = demisto.params().get("url")
SERVER = URL[:-1] if (URL and URL.endswith("/")) else URL
API_VERSION = demisto.params().get("eiq_api_version")
USE_SSL = not demisto.params().get("insecure", False)
HEADERS = {}  # type: Dict[str, str]
IP_THRESHOLD = demisto.params().get("ip_threshold", "").lower()
URL_THRESHOLD = demisto.params().get("url_threshold", "").lower()
FILE_THRESHOLD = demisto.params().get("file_threshold", "").lower()
EMAIL_THRESHOLD = demisto.params().get("email_threshold", "").lower()
DOMAIN_THRESHOLD = demisto.params().get("domain_threshold", "").lower()
GROUP_NAME = demisto.params().get("group_name")
SIGHTINGS_AUTO_CREATE = demisto.params().get("sightings_auto_creation")

""" EclecticIQ lib """

API_PATHS = {
    "v1": {
        "group_id_search": "/api/v1/sources/",
        "feeds_list": "/private/outgoing-feed-download/",
        "outgoing_feeds": "/private/outgoing-feeds/",
        "feed_content_blocks": "/private/outgoing-feed-download/",
        "groups": "/private/groups/",
        "entities": "/private/entities/",
        "observable_search": "/api/v1/observables",
        "observable_search_raw": "/private/search-history/search-observable",
        "entity_search": "/api/v1/entities",
        "taxonomy_get": "/api/v1/taxonomies",
        "observables": "/private/search-all",
        "tasks": "/private/tasks/",
        "dataset": "/private/intel-sets/",
        "relationships": "/api/v1/relationships",
        "task_status": "/private/task-runs/",
        "incoming_feeds": "/private/incoming-feeds/",
        "observables_batch_delete": "/private/extracts/batch-delete/",
        "status": "/private/status",
        "enrichers": "/private/enricher-tasks/",
        "enrichers-run": "/private/enricher-tasks/batch-run",
    },
    "v2": {
        "group_id_search": "/api/v2/sources/",
        "feeds_list": "/private/outgoing-feed-download/",
        "outgoing_feeds": "/api/v2/outgoing-feeds/",
        "feed_content_blocks": "/private/outgoing-feed-download/",
        "groups": "/private/groups/",
        "entities": "/private/entities/",
        "observable_search": "/api/v2/observables",
        "observable_search_raw": "/private/search-history/search-observable",
        "entity_search": "/api/v2/entities",
        "taxonomy_get": "/api/v2/taxonomies",
        "observables": "/private/search-all",
        "tasks": "/private/tasks/",
        "dataset": "/private/intel-sets/",
        "relationships": "/api/v2/relationships",
        "task_status": "/private/task-runs/",
        "incoming_feeds": "/private/incoming-feeds/",
        "observables_batch_delete": "/private/extracts/batch-delete/",
        "status": "/private/status",
        "enrichers": "/private/enricher-tasks/",
        "enrichers-run": "/private/enricher-tasks/batch-run",
    },
}

USER_AGENT = "script"


def extract_uuid_from_url(url):
    match = re.search(r"[\da-z\-]{36}", url)

    if match:
        return match.group()
    else:
        return None


def observable_id_from_url(url):
    match = re.search(r"(observables\/)([\d]+)", url)

    if match:
        return match.group(2)
    else:
        return None


def taxonomie_id_from_url(url):
    match = re.search(r"(taxonomies\/)([\d]+)", url)

    if match:
        return match.group(2)
    else:
        return None


def format_ts(dt):
    return dt.replace(microsecond=0).isoformat() + "Z"


def format_ts_human(dt):
    return dt.replace(microsecond=0).isoformat() + "Z"


class xsoar_logger:
    def info(self, message):
        demisto.info(message)

    def error(self, message):
        demisto.error(message)

    def exception(self, message):
        demisto.error(message)

    def debug(self, message):
        demisto.debug(message)

    def warning(self, message):
        demisto.error(message)


class EclecticIQ_api:
    def __init__(
        self,
        baseurl,
        eiq_api_version,
        username,
        password,
        verify_ssl=True,
        proxy_ip=None,
        proxy_username=None,
        proxy_password=None,
        logger=None,
        init_cred_test=True,
    ):
        self.eiq_logging = xsoar_logger()
        self.eiq_username = username
        self.eiq_password = password
        self.baseurl = baseurl
        self.verify_ssl = self.set_verify_ssl(verify_ssl)
        self.proxy_ip = proxy_ip
        self.proxy_username = proxy_username
        self.proxy_password = proxy_password
        self.proxies = self.set_eiq_proxy()
        self.eiq_api_version = eiq_api_version
        self.taxonomie_dict = {}
        self.headers = {
            "user-agent": USER_AGENT,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self.get_outh_token(test_credentials=init_cred_test)

    def set_logger(self, logger):
        if logger is None:
            logging.basicConfig(level=logging.INFO)
            logger_output = logging.getLogger()
            return logger_output
        else:
            return logger

    def set_verify_ssl(self, ssl_status):
        if ssl_status in ["1", "True", "true", True]:
            return True
        return ssl_status not in ["0", "False", "false", False]

    def sanitize_eiq_url(self, eiq_url):
        # TD
        return eiq_url

    def set_eiq_proxy(self):
        if self.proxy_ip and self.proxy_username and self.proxy_password:
            return {
                "http": "http://"
                + self.proxy_username
                + ":"
                + self.proxy_password
                + "@"
                + self.proxy_ip
                + "/",
                "https": "http://"
                + self.proxy_username
                + ":"
                + self.proxy_password
                + "@"
                + self.proxy_ip
                + "/",
            }
        elif self.proxy_ip:
            return {
                "http": "http://" + self.proxy_ip + "/",
                "https": "http://" + self.proxy_ip + "/",
            }
        else:
            return None

    def get_outh_token(self, test_credentials=True):
        self.eiq_logging.info(
            "Authenticating using username: " + str(self.eiq_username)
        )

        try:
            self.headers["Authorization"] = "Bearer " + str(self.eiq_password)

            if test_credentials:
                r = requests.get(
                    str(self.baseurl) + "/private",
                    headers=self.headers,
                    verify=self.verify_ssl,
                    proxies=self.proxies,
                    timeout=30,
                )

                if r and r.status_code in [100, 200, 201, 202]:
                    self.eiq_logging.info("Authentication successful")
                else:
                    if not r:
                        msg = "Could not perform auth request to EclecticIQ"
                        self.eiq_logging.exception(msg)
                        raise Exception(msg)
                    try:
                        err = r.json()
                        detail = err["errors"][0]["detail"]
                        msg = (
                            f"EclecticIQ VA returned an error, "
                            f"code:[{r.status_code}], reason:[{r.reason}], URL: [{r.url}], details:[{detail}]"
                        )
                    except Exception:
                        msg = f"EclecticIQ VA returned an error, code:[{r.status_code}], reason:[{r.reason}], URL: [{r.url}]"
                    raise Exception(msg)

        except Exception:
            self.eiq_logging.error("Authentication failed")
            raise

    def send_api_request(self, method, path, params=None, data=None):
        url = self.baseurl + path

        r = None
        try:
            if hasattr(requests, method):
                request_method = getattr(requests, method)
                r = request_method(
                    url,
                    headers=self.headers,
                    params=params,
                    data=json.dumps(data),
                    verify=self.verify_ssl,
                    proxies=self.proxies,
                    timeout=30,
                )
            else:
                self.eiq_logging.error("Unknown method: " + str(method))
                raise Exception(f"Unsupported HTTP method: {method}")

        except Exception as e:
            self.eiq_logging.exception(
                "Could not perform request to EclecticIQ VA: {}: {}. Exception: {}".format(
                    method, url, e
                )
            )

        if r and r.status_code in [100, 200, 201, 202, 204]:
            return r
        else:
            if r is None:
                msg = f"Could not perform request to EclecticIQ VA: {method}: {url}. Check network connectivity."
                self.eiq_logging.exception(msg)
                raise Exception(msg)
            elif r.status_code in [401]:
                msg = f"Wrong credentials. Status code:{r.status_code}"
                self.eiq_logging.exception(msg)
                raise Exception(msg)
            elif not r:
                msg = f"Could not perform request to EclecticIQ VA: {method}: {url}."
                self.eiq_logging.exception(msg)
                raise Exception(msg)

            try:
                err = r.json()
                detail = err["errors"][0]["detail"]
                msg = "EclecticIQ VA returned an error, code:{}, reason:[{}], URL: [{}], details:[{}]".format(
                    r.status_code, r.reason, r.url, detail
                )
            except Exception:
                msg = (
                    "EclecticIQ VA returned an error, code:{}, reason:[{}], URL: [{}]"
                ).format(r.status_code, r.reason, r.url)
            raise Exception(msg)

    def get_source_group_uid(self, group_name):
        # get source group UID.
        self.eiq_logging.debug(
            "Requesting source id for specified group, name=[" + str(group_name) + "]"
        )
        r = self.send_api_request(
            "get",
            path=API_PATHS[self.eiq_api_version]["groups"],
            params="filter[name]=" + str(group_name),
        )

        if not r.json()["data"]:
            self.eiq_logging.error(
                "Something went wrong fetching the group id. "
                "Please note the source group name is case sensitive! "
                "Received response:" + str(r.json())
            )
            return "error_in_fetching_group_id"
        else:
            self.eiq_logging.debug("Source group id received")
            self.eiq_logging.debug(
                "Source group id is: " + str(r.json()["data"][0]["source"])
            )
            return r.json()["data"][0]["source"]

    def get_source_group_order_id(self, group_name):
        # get source group UID.
        self.eiq_logging.debug(
            "Requesting source id for specified group, name=[" + str(group_name) + "]"
        )
        r = self.send_api_request(
            "get",
            path=API_PATHS[self.eiq_api_version]["groups"],
            params="filter[name]=" + str(group_name),
        )

        return r.json()["data"][0]["id"]

    def get_enrichers_list(self):
        # get enrichers list
        self.eiq_logging.debug("Requesting availble Enrichers list from platform.")
        r = self.send_api_request(
            "get", path=API_PATHS[self.eiq_api_version]["enrichers"]
        )

        return r.json()["data"]

    def get_active_enrichers_list(self):
        enrichers_list = []
        enrichers_list = self.get_enrichers_list()
        active_list = []

        for enricher in enrichers_list:
            if enricher["is_active"]:
                active_list.append(enricher)

        return active_list

    def enrich_observable(self, enricher_id, observable_id):
        # To enrich Observable
        self.eiq_logging.debug(f"Enriching observable.{observable_id}")
        run_dict = {
            "data": {"enricher_tasks": [enricher_id], "extracts": [observable_id]}
        }

        r = self.send_api_request(
            "post", path=API_PATHS[self.eiq_api_version]["enrichers-run"], data=run_dict
        )

        return r.json()["data"]

    def get_status(self):
        # get platform status
        self.eiq_logging.info("Requesting Platform status")

        r = self.send_api_request("get", path=API_PATHS[self.eiq_api_version]["status"])

        return r.json()["data"]

    def get_status_red_component(self):
        status = self.get_status()

        result = {"health": status["health"], "components": []}

        for celery_component in status["celery_states"]:
            if celery_component["health"] == "RED":
                result["components"].append(celery_component)

        for service_component in status["service_states"]:
            if service_component["health"] == "RED":
                result["components"].append(service_component)

        return result

    def create_incoming_feed(
        self,
        feed_title,
        content_type,
        password,
        username,
        collection_name="null",
        polling_service_url="null",
        taxii_version="null",
        transport_type="null",
        basic_auth="false",
    ):
        self.eiq_logging.info(f"Creating Incoming Feed {feed_title}")
        # To create Incoming feed

        # TD "null" doesnt work, if lines are not commented it leads to 500 error
        create_feed_dict = {
            "data": {
                "content_type": content_type,
                "half_life": {},
                "is_public": "false",
                "name": feed_title,
                "require_link_types": "false",
                "require_valid_signature": "false",
                "transport_configuration": {
                    "basic_authentication_mode": basic_auth,
                    "password": password,
                    "username": username,
                    "collection_name": collection_name,
                    "polling_service_url": polling_service_url,
                    "ssl_authentication_mode": "false",
                    "taxii_version": taxii_version,
                    "verify_ssl": "false",
                },
                "transport_type": transport_type,
            }
        }

        r = self.send_api_request(
            "post",
            path=API_PATHS[self.eiq_api_version]["incoming_feeds"],
            data=create_feed_dict,
        )

        result = (json.loads(r.text))["data"]

        return result

    def download_incoming_feed(self, feed_id, feed_provider_task):
        # To download incmoing feed
        self.eiq_logging.info(f"Downloading Incoming Feed {feed_id}")

        run_task_download_feed = {
            "data": {
                "id": feed_provider_task,
                "is_active": True,
                # "parameters": {
                #     "basic_authentication_mode": False,
                #     "collection_name": "multi-binding-fixed",
                #     "polling_service_url": "https://test.taxiistand.com/read-only/services/poll",
                #     "ssl_authentication_mode": False,
                #     "taxii_version": "1.1",
                #     "verify_ssl": False
                # },
                # "task_name": "eiq.incoming-transports.taxii",
                "task_type": "provider_task",
                "trigger": "null",
            }
        }

        r = self.send_api_request(
            "post",
            path=API_PATHS[self.eiq_api_version]["tasks"]
            + str(feed_provider_task)
            + "/run",
            data=run_task_download_feed,
        )

        result = (json.loads(r.text))["data"]
        return result

    def create_outgoing_feed(
        self,
        content_type,
        intel_set_id,
        feed_title,
        transport_type,
        update_strategy,
        access_group_name,
    ):
        # create Outgoing feed

        self.eiq_logging.info(f"Creating Outgoing Feed {feed_title}")

        group_id = self.get_source_group_order_id(access_group_name)

        authorized_group_order_id = str(group_id)

        create_outgoing_feed = {
            "data": {
                "allowed_extract_states": [
                    {"classification": "bad", "confidence": "high"},
                    {"classification": "bad", "confidence": "medium"},
                    {"classification": "bad", "confidence": "low"},
                    {"classification": "good"},
                    {"classification": "unknown"},
                ],
                "allowed_link_types": [
                    "parameter",
                    "affected",
                    "configuration",
                    "vulnerability",
                    "weakness",
                    "affected-asset",
                    "related",
                    "observed",
                    "sighted",
                    "test-mechanism",
                    "identity",
                    "malicious-infrastructure",
                    "targeted-victim",
                ],
                "anonymize_replace_actions": [],
                "anonymize_skip_paths": [],
                "content_configuration": {"producer_override_enabled": False},
                "content_type": content_type,
                "deselected_enrichers": [],
                "do_sign_content": False,
                "enrichment_extract_types": [
                    "company",
                    "geo-lat",
                    "registrar",
                    "city",
                    "forum-name",
                    "file",
                    "netname",
                    "street",
                    "host",
                    "person",
                    "uri-hash-sha256",
                    "product",
                    "postcode",
                    "domain",
                    "cce",
                    "name",
                    "card",
                    "actor-id",
                    "winregistry",
                    "geo",
                    "fox-it-portal-uri",
                    "mac-48",
                    "email",
                    "inetnum",
                    "eui-64",
                    "forum-thread",
                    "address",
                    "card-owner",
                    "email-subject",
                    "uri",
                    "country-code",
                    "ipv6",
                    "telephone",
                    "rule",
                    "nationality",
                    "forum-room",
                    "mutex",
                    "asn",
                    "hash-md5",
                    "ipv4",
                    "organization",
                    "country",
                    "bank-account",
                    "snort",
                    "handle",
                    "hash-sha256",
                    "industry",
                    "port",
                    "cve",
                    "geo-long",
                    "hash-sha1",
                    "yara",
                    "malware",
                    "hash-sha512",
                    "cwe",
                    "process",
                ],
                # "execution_schedule": "null",
                "extract_types": [
                    "actor-id",
                    "address",
                    "asn",
                    "bank-account",
                    "card",
                    "card-owner",
                    "cce",
                    "city",
                    "company",
                    "country",
                    "country-code",
                    "cve",
                    "cwe",
                    "domain",
                    "email",
                    "email-subject",
                    "eui-64",
                    "file",
                    "forum-name",
                    "forum-room",
                    "forum-thread",
                    "fox-it-portal-uri",
                    "geo",
                    "geo-lat",
                    "geo-long",
                    "handle",
                    "hash-md5",
                    "hash-sha1",
                    "hash-sha256",
                    "hash-sha512",
                    "host",
                    "industry",
                    "inetnum",
                    "ipv4",
                    "ipv6",
                    "mac-48",
                    "malware",
                    "mutex",
                    "name",
                    "nationality",
                    "netname",
                    "organization",
                    "person",
                    "port",
                    "postcode",
                    "process",
                    "product",
                    "registrar",
                    "rule",
                    "snort",
                    "street",
                    "telephone",
                    "uri",
                    "uri-hash-sha256",
                    "winregistry",
                    "yara",
                ],
                # "half_life_filter": "null",
                "include_without_link_type": True,
                "intel_sets": [str(intel_set_id)],
                "is_active": False,
                "name": feed_title,
                "require_valid_data": False,
                # "source_reliability_filter": "null",
                # "tlp_color_filter": "null",
                # "tlp_color_override": "null",
                "transport_configuration": {
                    "authorized_groups": [authorized_group_order_id],
                    "is_public": False,
                },
                "transport_type": transport_type,
                "update_strategy": update_strategy,
                "whitelist_sources": [],
                "whitelist_tags": [],
                "whitelist_taxonomy_nodes": [],
            }
        }

        r = self.send_api_request(
            "post",
            path=API_PATHS[self.eiq_api_version]["outgoing_feeds"],
            data=create_outgoing_feed,
        )

        result = r.json()["data"]

        return result

    def get_incoming_feed_blobs_pending(self, feed_id):
        # to get incmoing feed blobs
        self.eiq_logging.info(f"Requesting Incoming feed run status: {feed_id}")

        r = self.send_api_request(
            "get", path=API_PATHS[self.eiq_api_version]["incoming_feeds"]
        )

        result = None

        for feed in (json.loads(r.text))["data"]:
            if feed["id"] == feed_id:
                result = feed["n_blobs_pending"]

        return result

    def get_full_feed_info(self, feed_id):
        # to get outgoing feed full info

        self.eiq_logging.info(f"Requesting full feed info for feed id={feed_id}")

        if feed_id == "*":
            feed_id = ""

        r = self.send_api_request(
            "get", path=API_PATHS[self.eiq_api_version]["outgoing_feeds"] + str(feed_id)
        )

        result = (json.loads(r.text))["data"]

        return result

    def get_incoming_feed_full_info(self, feed_id):
        # to get incmoing feed full info

        self.eiq_logging.info(
            f"Requesting full feed info for incoming feed id={feed_id}"
        )

        if feed_id == "*":
            feed_id = ""

        r = self.send_api_request(
            "get", path=API_PATHS[self.eiq_api_version]["incoming_feeds"] + str(feed_id)
        )

        result = (json.loads(r.text))["data"]

        return result

    def get_feed_info(self, feed_ids):
        self.eiq_logging.info(f"Requesting feed info for feed id={feed_ids}")
        feed_ids = (feed_ids.replace(" ", "")).split(",")
        result = []

        if self.eiq_api_version == "FC":
            for k in feed_ids:
                feed_result = {
                    "id": k,
                    "created_at": "",
                    "update_strategy": "REPLACE",
                    "packaging_status": "SUCCESS",
                }
                result.append(feed_result)
            self.feeds_info = result
            return result

        for k in feed_ids:
            feed_result = {}
            try:
                r = self.send_api_request(
                    "get", path=API_PATHS[self.eiq_api_version]["outgoing_feeds"] + k
                )
            except Exception:
                self.eiq_logging.error(f"Feed id={k} information cannot be requested.")
                continue

            if not r.json()["data"]:
                self.eiq_logging.error(
                    "Feed id={0} information cannot be requested. Received response:"
                    + str(r.json())
                ).format(k)
                return "error_in_fetching_feed_info"
            else:
                self.eiq_logging.debug(f"Feed id={k} information requested")
                feed_result["id"] = r.json()["data"]["id"]
                feed_result["created_at"] = r.json()["data"]["created_at"]
                feed_result["update_strategy"] = r.json()["data"]["update_strategy"]
                feed_result["packaging_status"] = r.json()["data"]["packaging_status"]
                feed_result["name"] = r.json()["data"]["name"]
                result.append(feed_result)
                self.eiq_logging.debug(
                    f"Feed id={k} information retrieved successfully. Received response:"
                    + str(json.dumps(feed_result))
                )

        return result

    def download_block_list(self, block):
        self.eiq_logging.debug(f"Downloading block url{block}")

        if self.eiq_api_version == "FC":
            block = (str(block)).replace(self.baseurl, "")

        r = self.send_api_request("get", path=str(block))
        data = r.text

        return data

    def get_feed_content_blocks(self, feed, feed_last_run=None):
        self.eiq_logging.debug(
            "Requesting block list for feed id={}".format(feed["id"])
        )

        if feed_last_run is None:
            feed_last_run = {}
            feed_last_run["last_ingested"] = None
            feed_last_run["created_at"] = None

        if (
            feed["packaging_status"] == "SUCCESS"
            and feed["update_strategy"] == "REPLACE"
        ):
            self.eiq_logging.debug("Requesting block list for REPLACE feed.")

            r = self.send_api_request(
                "get",
                path=API_PATHS[self.eiq_api_version]["feed_content_blocks"]
                + "{}/runs/latest".format(feed["id"]),
            )

            data = r.json()["data"]["content_blocks"]
            if feed_last_run["last_ingested"] == data[-1]:
                self.eiq_logging.info(
                    "Received list contains {} blocks for feed id={}.".format(
                        len(data), feed["id"]
                    )
                )
                return []
            self.eiq_logging.info(
                "Received list contains {} blocks for feed id={}.".format(
                    len(data), feed["id"]
                )
            )
            return data

        elif feed["packaging_status"] == "SUCCESS" and (
            feed["update_strategy"] in ["APPEND", "DIFF"]
        ):
            self.eiq_logging.debug(
                "Requesting block list for {} feed.".format(feed["update_strategy"])
            )

            r = self.send_api_request(
                "get",
                path=API_PATHS[self.eiq_api_version]["feed_content_blocks"]
                + "{}".format(feed["id"])
                + "/",
            )

            data = r.json()["data"]["content_blocks"]

            if (feed["created_at"] != feed_last_run["created_at"]) or feed_last_run[
                "last_ingested"
            ] is None:
                self.eiq_logging.info(
                    f"Received list contains {len(data)} blocks for {feed['update_strategy']} feed:{feed['id']}."
                    " Feed created time changed or first run, "
                    "reingestion of all the feed content."
                )
                return data
            else:
                try:
                    last_ingested_index = data.index(feed_last_run["last_ingested"])
                    diff_data = data[last_ingested_index + 1:]
                    self.eiq_logging.info(
                        "Received list contains {} blocks for {} feed:{}.".format(
                            len(diff_data), feed["update_strategy"], feed["id"]
                        )
                    )
                    return diff_data
                except ValueError:
                    self.eiq_logging.error(
                        "Value of last ingested block not available in Feed {}.".format(
                            feed["id"]
                        )
                    )
                    return None

        elif feed["packaging_status"] == "RUNNING":
            self.eiq_logging.info(
                "Feed id={} is running now. Collecting data is not possible.".format(
                    feed["id"]
                )
            )
            return None
        else:
            self.eiq_logging.info(
                "Feed id={} update strategy is not supported. Use Replace or Diff".format(
                    feed["id"]
                )
            )
            return None

    def get_group_name(self, group_id):
        self.eiq_logging.info(f"Getting group name by id:{group_id}")
        r = self.send_api_request(
            "get",
            path=API_PATHS[self.eiq_api_version]["group_id_search"] + str(group_id),
        )

        response = json.loads(r.text)
        result = {}

        result["name"] = response["data"].get("name", "N/A")
        result["type"] = response["data"].get("source_type", "N/A")

        return result

    def get_observable_by_id(self, id):
        self.eiq_logging.info(f"Searching Observable with ID:{id}")

        r = self.send_api_request(
            "get",
            path=API_PATHS[self.eiq_api_version]["observable_search"] + "/" + str(id),
        )

        observable_response = json.loads(r.text)

        return observable_response

    def lookup_observable(self, value, type=None):
        """Method lookups specific observable by value and type.

        Args:
            value: value of Observable
            type: type of observable, e.g. ipv4, hash-md5 etc

        Returns:
            Return dictionary with Observable details:
             {created: date and time of creation,
             last_updated: last update time,
             maliciousness: value of maliciousness,
             type: type of Observable from args ,
             value: value of Observable from args,
             source_name: who produced Observable,
             platform_link: direct link o the platform
             }

            Otherwise returns None.

        """
        self.eiq_logging.info(f"Searching Observable:{value}, type:{type}")

        params = {}
        params["filter[value]"] = value

        if type is not None:
            params["filter[type]"] = type

        r = self.send_api_request(
            "get",
            path=API_PATHS[self.eiq_api_version]["observable_search"],
            params=params,
        )

        observable_response = json.loads(r.text)

        if observable_response["count"] == 1:
            result = {}
            result["created"] = str(observable_response["data"][0]["created_at"])[:16]
            result["last_updated"] = str(
                observable_response["data"][0]["last_updated_at"]
            )[:16]
            result["maliciousness"] = observable_response["data"][0]["meta"][
                "maliciousness"
            ]
            result["type"] = observable_response["data"][0]["type"]
            result["value"] = observable_response["data"][0]["value"]
            result["id"] = str(observable_response["data"][0]["id"])
            result["source_name"] = ""

            for k in observable_response["data"][0]["sources"]:
                source_lookup_data = self.get_group_name(extract_uuid_from_url(k))
                result["source_name"] += (
                    str(source_lookup_data["type"])
                    + ": "
                    + str(source_lookup_data["name"])
                    + "; "
                )

            result["platform_link"] = (
                self.baseurl
                + "/main/intel/all/browse/observable?tab=overview&id="
                + result["id"]
            )

            return result

        elif observable_response["count"] > 1:
            self.eiq_logging.info(
                f"Finding duplicates for observable:{value}, type:{type}, return first one"
            )
            result = {}
            result["created"] = str(observable_response["data"][0]["created_at"])[:16]
            result["last_updated"] = str(
                observable_response["data"][0]["last_updated_at"]
            )[:16]
            result["maliciousness"] = observable_response["data"][0]["meta"][
                "maliciousness"
            ]
            result["type"] = observable_response["data"][0]["type"]
            result["value"] = observable_response["data"][0]["value"]
            result["id"] = str(observable_response["data"][0]["id"])
            result["source_name"] = ""

            for k in observable_response["data"][0]["sources"]:
                source_lookup_data = self.get_group_name(extract_uuid_from_url(k))
                result["source_name"] += (
                    str(source_lookup_data["type"])
                    + ": "
                    + str(source_lookup_data["name"])
                    + "; "
                )

            result["platform_link"] = (
                self.baseurl
                + "/main/intel/all/browse/observable?tab=overview&id="
                + result["id"]
            )

            return result

        else:
            return None

    def get_all_observables(self):
        self.eiq_logging.info("Searching all Observable.")

        r = self.send_api_request(
            "get", path=API_PATHS[self.eiq_api_version]["observable_search"]
        )

        return json.loads(r.text)

    def get_taxonomy_dict(self):
        """Method returns dictionary with all the available taxonomy in Platform.

        Returns:
            Return dictionary with {taxonomy ids:taxonomy title}. Otherwise returns False.

        """
        self.eiq_logging.info("Get all the taxonomy titles from Platform.")

        r = self.send_api_request(
            "get",
            path=API_PATHS[self.eiq_api_version]["taxonomy_get"],
            params={"limit": 500},
        )

        taxonomy = json.loads(r.text)
        taxonomy_dict = {}

        for i in taxonomy["data"]:
            try:
                id = str(i["id"])
                name = i["name"]

                taxonomy_dict[id] = name
            except KeyError:
                continue

        if len(taxonomy_dict) > 0:
            return taxonomy_dict
        else:
            return False

    def get_entity_realtionships(self, source_id=None, target_id=None):
        self.eiq_logging.info(
            f"Get realtionshsip for entity. Source id: {source_id}, Destination id: {target_id}"
        )
        params = {}

        if source_id:
            params["filter[data.source]"] = source_id
            direction = "source"
        elif target_id:
            params["filter[data.target]"] = target_id
            direction = "target"
        else:
            direction = ""
            demisto.debug(f"No source_id or target_id. {direction=}")

        r = self.send_api_request(
            "get", path=API_PATHS[self.eiq_api_version]["relationships"], params=params
        )

        parsed_response = json.loads(r.text)
        result = []

        if len(parsed_response["data"]) > 0:
            for i in parsed_response["data"]:
                relation = {}
                if direction == "source":
                    r = self.send_api_request(
                        "get",
                        path=(
                            API_PATHS[self.eiq_api_version]["entity_search"]
                            + "/"
                            + str(extract_uuid_from_url(i["data"]["target"]))
                        ),
                    )
                elif direction == "target":
                    r = self.send_api_request(
                        "get",
                        path=(
                            API_PATHS[self.eiq_api_version]["entity_search"]
                            + "/"
                            + str(extract_uuid_from_url(i["data"]["source"]))
                        ),
                    )

                related_entity_parsed_response = json.loads(r.text)

                if self.eiq_api_version == "v1":
                    relation["relation_title"] = i["meta"].get("title")
                    relation["entity_type"] = related_entity_parsed_response["data"]["type"]
                elif self.eiq_api_version == "v2":
                    relation["relation_title"] = i["data"].get("key")
                    relation["entity_type"] = related_entity_parsed_response["data"]["data"]["type"]

                relation["entity_title"] = related_entity_parsed_response["data"]["data"]["title"]
                relation["entity_id"] = related_entity_parsed_response["data"]["id"]
                relation["observables_count"] = len(related_entity_parsed_response["data"]["observables"])
                result.append(relation)
        return result

    def get_entity_by_id(
        self, entity_id, observables_lookup=True, relationships_lookup=True
    ):
        """Method lookups specific entity by Id.

        Args:
            entity_id: Requested entity Id.

        Returns:
            Return dictionary with entity details:
             {entity_title: value,
             entity_type: value,
             created_at: value,
             source_name: value,
             tags_list: [
                tag and taxonomy list ...
                ],
             relationships_list: [
                    {relationship_type: incoming/outgoing,
                    connected_node: id,
                    connected_node_type: value,
                    connected_node_type: value
                    }
                relationship list ...
                ],
             observables_list: [
                    {value: obs_value,
                    type: obs_type
                    },
                    ...
                ]
             }

            Otherwise returns False.

        """
        self.eiq_logging.info(f"Looking up Entity {entity_id}.")

        try:
            r = self.send_api_request(
                "get",
                path=API_PATHS[self.eiq_api_version]["entity_search"]
                + "/"
                + str(entity_id),
            )
            parsed_response = json.loads(r.text)

            if len(self.taxonomie_dict) == 0:
                self.taxonomie_dict = self.get_taxonomy_dict()

            result = {}

            result["entity_title"] = parsed_response["data"]["data"].get("title", "N/A")
            result["created_at"] = str(
                parsed_response["data"].get("created_at", "N/A")
            )[:16]
            source = self.get_group_name(
                extract_uuid_from_url(parsed_response["data"]["sources"][0])
            )
            result["source_name"] = source["type"] + ": " + source["name"]
            result["tags_list"] = []
            result["confidence"] = parsed_response["data"]["data"].get(
                "confidence", "N/A"
            )
            result["description"] = parsed_response["data"]["data"].get(
                "description", "N/A"
            )
            result["impact"] = parsed_response["data"]["data"].get("impact", "N/A")

            if self.eiq_api_version == "v1":
                result["entity_type"] = parsed_response["data"].get("type", "N/A")
            elif self.eiq_api_version == "v2":
                result["entity_type"] = parsed_response["data"]["data"].get(
                    "type", "N/A"
                )

            try:
                for i in parsed_response["data"]["meta"]["tags"]:
                    result["tags_list"].append(i)
            except KeyError:
                pass

            try:
                for i in parsed_response["data"]["meta"]["taxonomies"]:
                    result["tags_list"].append(
                        self.taxonomie_dict.get(taxonomie_id_from_url(i))
                    )
            except KeyError:
                pass

            if observables_lookup:
                result["observables_list"] = []
                try:
                    for i in parsed_response["data"]["observables"]:
                        observable_data = self.get_observable_by_id(
                            observable_id_from_url(i)
                        )
                        result["observables_list"].append(
                            {
                                "value": observable_data["data"]["value"],
                                "type": observable_data["data"]["type"],
                                "maliciousness": observable_data["data"]["meta"][
                                    "maliciousness"
                                ],
                            }
                        )
                except (KeyError, TypeError):
                    pass

            if relationships_lookup:
                entity_is_source_relationships = self.get_entity_realtionships(
                    source_id=entity_id
                )
                entity_is_target_relationships = self.get_entity_realtionships(
                    target_id=entity_id
                )
                result["relationships_list"] = []

                for i in entity_is_source_relationships:
                    result["relationships_list"].append(
                        {
                            "source_entity_title": result["entity_title"],
                            "source_entity_type": result["entity_type"],
                            "target_entity_title": i["entity_title"],
                            "target_entity_type": i["entity_type"],
                            "target_entity_id": i["entity_id"],
                            "target_entity_observables_count": i["observables_count"],
                            "relationship_title": i["relation_title"],
                        }
                    )

                for i in entity_is_target_relationships:
                    result["relationships_list"].append(
                        {
                            "source_entity_title": i["entity_title"],
                            "source_entity_type": i["entity_type"],
                            "target_entity_title": result["entity_title"],
                            "target_entity_type": result["entity_type"],
                            "source_entity_id": i["entity_id"],
                            "source_entity_observables_count": i["observables_count"],
                            "relationship_title": i["relation_title"],
                        }
                    )

        except Exception as e:
            if "Status code: 404" in str(e):
                return False
            else:
                return e

        return result

    def search_entity(self, entity_value=None, entity_type=None, observable_value=None):
        """Method search specific entity by specific search conditions.

        Note: search works with wildcards for entity value and with strict conditions for everything else.
            Also, it's recommended to use this method to lookup entity name based on the entity ID, because it doesnt
            return all the relationships.

            if you need to find specific entity - search by entity id
            if you need to find all the entities with specific observables extracted - search with observable values

        Args:
            entity_value: entity value to search. add " or * to make search wildcard or strict
            entity_type: value to search
            entity_id: entity id to search
            observable_value: observable value to search inside entity

        Returns:
            Return dictionary with all the entity details.
            Otherwise returns False.

        """
        self.eiq_logging.info(
            "Searching Entity:{} with extracted observable:{}, type:{}".format(
                entity_value, observable_value, entity_type
            )
        )

        params = {}

        if entity_value is not None:
            if entity_value[0] == '"' and entity_value[-1] == '"':
                entity_value = entity_value[1:-1]
                entity_value = entity_value.replace('"', '\\"')
                entity_value = '"' + entity_value + '"'
            else:
                entity_value = entity_value.replace('"', '\\"')

            params["filter[data.title]"] = entity_value

        if observable_value is not None:
            observable_data = self.lookup_observable(value=observable_value)

            try:
                params["filter[observables]"] = observable_data["id"]
            except Exception:
                return False

        if entity_type is not None:
            params["filter[type]"] = entity_type

        r = self.send_api_request(
            "get", path=API_PATHS[self.eiq_api_version]["entity_search"], params=params
        )

        search_response = json.loads(r.text)

        if len(search_response["data"]) > 0:
            parsed_result = []
            for entity in search_response["data"]:
                parsed_entity = self.get_entity_by_id(entity["id"])
                parsed_result.append(parsed_entity)

            return parsed_result
        else:
            return False

    def elastic_search(self, search_payload=None, latency_check=False, page_size=10):
        self.eiq_logging.info("Searching in elastic")

        r = self.send_api_request(
            "post",
            path=API_PATHS[self.eiq_api_version]["entity_search"]
            + "?size="
            + str(page_size),
            data=search_payload,
        )

        search_response = json.loads(r.text)

        if len(search_response["hits"]["hits"]) > 0:
            if latency_check:
                search_response["latency"] = r.elapsed.total_seconds()
                return search_response

            else:
                return search_response["hits"]["hits"]
        else:
            return False

    def create_entity(
        self,
        observable_dict,
        source_group_name,
        entity_title,
        entity_description,
        entity_confidence="Medium",
        entity_tags=[],
        entity_type="eclecticiq-sighting",
        entity_impact_value="None",
    ):
        """Method creates entity in Platform.

        Args:
            observable_dict: list of dictionaries with observables to create. Format:
                [{
                observable_type: "value",
                observable_value: value,
                observable_maliciousness: high/medium/low,
                observable_classification: good/bad
                }]
            source_group_name: group name in Platform for Source. Case sensitive.
            entity_title: value
            entity_description: value
            entity_confidence: Low/Medium/High
            entity_tags: list of strings
            entity_type: type of entity. e.g. indicator, ttp, eclecticiq-sighting etc
            entity_impact_value: "None", "Unknown", "Low", "Medium", "High"

        Returns:
            Return created entity id if successful otherwise returns False.

        """
        self.eiq_logging.info(
            "Creating Entity in EclecticIQ Platform. Type:{}, title:{}".format(
                entity_type, entity_title
            )
        )

        group_id = self.get_source_group_uid(source_group_name)

        today = datetime.utcnow().date()

        today_begin = format_ts(datetime(today.year, today.month, today.day, 0, 0, 0))
        threat_start = format_ts(datetime.utcnow())

        observable_dict_to_add = []
        record: dict[str, Any] = {}

        for i in observable_dict:
            record = {}

            if entity_type == "eclecticiq-sighting":
                record["link_type"] = "sighted"
            else:
                record["link_type"] = "observed"

            if i.get("observable_maliciousness", "") in ["low", "medium", "high"]:
                record["confidence"] = i["observable_maliciousness"]

            if i.get("observable_classification", "") in ["bad", "good", "unknown"]:
                record["classification"] = i["observable_classification"]

            if i.get("observable_value", ""):
                record["value"] = i["observable_value"]
            else:
                continue

            if i.get("observable_type", "") in [
                "asn",
                "country",
                "cve",
                "domain",
                "email",
                "email-subject",
                "file",
                "handle",
                "hash-md5",
                "hash-sha1",
                "hash-sha256",
                "hash-sha512",
                "industry",
                "ipv4",
                "ipv6",
                "malware",
                "name",
                "organization",
                "port",
                "snort",
                "uri",
                "yara",
            ]:
                record["kind"] = i["observable_type"]
            else:
                continue

            observable_dict_to_add.append(record)

        entity = {
            "data": {
                "data": {
                    "confidence": {"type": "confidence", "value": entity_confidence},
                    "description": entity_description,
                    "description_structuring_format": "html",
                    "impact": {
                        "type": "statement",
                        "value": entity_impact_value,
                        "value_vocab": "{http://stix.mitre.org/default_vocabularies-1}HighMediumLowVocab-1.0",
                    },
                    "type": entity_type,
                    "title": entity_title,
                    "security_control": {
                        "type": "information-source",
                        "time": {
                            "type": "time",
                            "start_time": today_begin,
                            "start_time_precision": "second",
                        },
                    },
                },
                "meta": {
                    "manual_extracts": observable_dict_to_add,
                    "taxonomy": [],
                    "estimated_threat_start_time": threat_start,
                    "tags": entity_tags,
                    "ingest_time": threat_start,
                },
                "sources": [{"source_id": group_id}],
            }
        }

        r = self.send_api_request(
            "post", path=API_PATHS[self.eiq_api_version]["entities"], data=entity
        )

        entity_response = json.loads(r.text)

        try:
            return entity_response["data"]["id"]
        except KeyError:
            return False

    def get_observable(self, observable):
        self.eiq_logging.info(f"EclecticIQ_api: Searching for Observable: {observable}")
        path = (
            API_PATHS[self.eiq_api_version]["observables"]
            + "?q=extracts.value:"
            + observable
        )
        r = self.send_api_request("get", path=path)
        return r.json()


""" HELPER FUNCTIONS """


def maliciousness_to_dbotscore(maliciousness, threshold):
    """

    Translates EclecticIQ obversable maliciousness confidence level to DBotScore based on given threshold

    Parameters
    ----------
    maliciousness : str
        EclecticIQ obversable maliciousness confidence level.
    threshold : str
        Minimum maliciousness confidence level to consider the IOC malicious.

    Returns
    -------
    number
        Translated DBot Score

    """
    maliciousness_list = ["unknown", "safe", "low", "medium", "high"]

    maliciousness_dictionary = {
        "unknown": 0,
        "safe": 1,
        "low": 2,
        "medium": 2,
        "high": 3,
    }

    for i in maliciousness_list[maliciousness_list.index(threshold):]:
        maliciousness_dictionary[i] = 3

    return maliciousness_dictionary[maliciousness]


""" COMMANDS + REQUESTS FUNCTIONS """


def test_module(eiq_api):
    """
    The function which runs when clicking on Test in integration settings
    Returns
    -------
    str
        ok if getting observable successfully

    """
    try:
        eiq_api.lookup_observable("123.123.123.123", "ipv4")
    except Exception as exception:
        if 'Unauthorized' in str(exception) or 'authentication' in str(exception):
            return 'Authorization Error: make sure API Credentials are correctly set'

        if 'connection' in str(exception):
            return 'Connection Error: make sure Server URL is correctly set'
        raise exception

    return 'ok'


def ip_command(eiq_api):
    """
    Gets reputation of an EclecticIQ IPv4 observable
    Parameters
    ----------
    ip : str
        IPv4 to get reputation of
    Returns
    -------
    entry
        Reputation of given IPv4
    """
    observable_value = demisto.args()["ip"]
    response_eiq = eiq_api.lookup_observable(observable_value, "ipv4")
    ip_result = parse_reputation_results(
        response_eiq, observable_value, "ip", IP_THRESHOLD, "IP"
    )

    if SIGHTINGS_AUTO_CREATE:
        observable_dict = [
            {
                "observable_type": response_eiq["type"],
                "observable_value": observable_value,
                "observable_maliciousness": "medium",
                "observable_classification": "bad",
            }
        ]

        eiq_api.create_entity(
            observable_dict=observable_dict,
            source_group_name=GROUP_NAME,
            entity_title="XSOAR automatic Sighting for " + observable_value,
            entity_description="",
        )

    return ip_result


def parse_reputation_results(
    response_eiq,
    observable_value,
    demisto_observable_type,
    observable_threshold,
    demisto_observable_alias,
):
    command_results = []
    indicator: Any = None
    if response_eiq is not None:
        score = 0
        maliciousness = response_eiq.get("maliciousness")
        score = maliciousness_to_dbotscore(maliciousness, observable_threshold)

        if demisto_observable_type == "ip":
            indicator = Common.IP(
                ip=observable_value,
                dbot_score=Common.DBotScore(
                    observable_value,
                    DBotScoreType.IP,
                    "EclecticIQ",
                    score,
                    "EclecticIQ maliciousness confidence level: " + maliciousness,
                ),
            )
            prefix = "EclecticIQ.IP"

        elif demisto_observable_type == "url":
            indicator = Common.URL(
                url=observable_value,
                dbot_score=Common.DBotScore(
                    observable_value,
                    DBotScoreType.URL,
                    "EclecticIQ",
                    score,
                    "EclecticIQ maliciousness confidence level: " + maliciousness,
                ),
            )
            prefix = "EclecticIQ.URL"

        elif demisto_observable_type == "domain":
            indicator = Common.Domain(
                domain=observable_value,
                dbot_score=Common.DBotScore(
                    observable_value,
                    DBotScoreType.DOMAIN,
                    "EclecticIQ",
                    score,
                    "EclecticIQ maliciousness confidence level: " + maliciousness,
                ),
            )
            prefix = "EclecticIQ.Domain"

        elif demisto_observable_type == "file" and bool(
            re.search(r"\w{40}", observable_value)
        ):  # SHA1
            indicator = Common.File(
                sha1=observable_value,
                dbot_score=Common.DBotScore(
                    observable_value,
                    DBotScoreType.FILE,
                    "EclecticIQ",
                    score,
                    "EclecticIQ maliciousness confidence level: " + maliciousness,
                ),
            )
            prefix = "EclecticIQ.File"

        elif demisto_observable_type == "file" and bool(
            re.search(r"\w{64}", observable_value)
        ):  # SHA256
            indicator = Common.File(
                sha256=observable_value,
                dbot_score=Common.DBotScore(
                    observable_value,
                    DBotScoreType.FILE,
                    "EclecticIQ",
                    score,
                    "EclecticIQ maliciousness confidence level: " + maliciousness,
                ),
            )
            prefix = "EclecticIQ.File"

        elif demisto_observable_type == "file" and bool(
            re.search(r"\w{32}", observable_value)
        ):  # MD5
            indicator = Common.File(
                md5=observable_value,
                dbot_score=Common.DBotScore(
                    observable_value,
                    DBotScoreType.FILE,
                    "EclecticIQ",
                    score,
                    "EclecticIQ maliciousness confidence level: " + maliciousness,
                ),
            )
            prefix = "EclecticIQ.File"

        elif demisto_observable_type == "file" and bool(
            re.search(r"\w{128}", observable_value)
        ):  # SHA512
            indicator = Common.File(
                sha512=observable_value,
                dbot_score=Common.DBotScore(
                    observable_value,
                    DBotScoreType.FILE,
                    "EclecticIQ",
                    score,
                    "EclecticIQ maliciousness confidence level: " + maliciousness,
                ),
            )
            prefix = "EclecticIQ.File"

        elif demisto_observable_type == "email":
            indicator = Common.EMAIL(
                address=observable_value,
                dbot_score=Common.DBotScore(
                    observable_value,
                    DBotScoreType.EMAIL,
                    "EclecticIQ",
                    score,
                    "EclecticIQ maliciousness confidence level: " + maliciousness,
                ),
            )
            prefix = "EclecticIQ.Email"
        else:
            prefix = ""
            demisto.debug(f"{demisto_observable_type=} -> {prefix=}")

        raw_result = response_eiq

        entry_context = {
            "Observable": observable_value,
            "Created": response_eiq.get("created"),
            "LastUpdated": response_eiq.get("last_updated"),
            "SourceName": response_eiq.get("source_name"),
            "Maliciousness": maliciousness,
        }

        outputs_key_field = "Observable"

        human_readable_title = (
            "EclecticIQ "
            + demisto_observable_alias
            + f" reputation - {observable_value}"
        )
        human_readable = tableToMarkdown(human_readable_title, response_eiq)

        command_results.append(
            CommandResults(
                readable_output=human_readable,
                raw_response=raw_result,
                outputs_prefix=prefix,
                outputs=entry_context,
                outputs_key_field=outputs_key_field,
                indicator=indicator,
            )
        )

    else:
        human_readable = (
            "### Observable: " + str(observable_value) + " not found in EclecticIQ IC."
        )
        raw_result = {
            "result": "Observable not found in EclecticIQ IC.",
            "observable": str(observable_value),
        }

        if demisto_observable_type == "ip":
            prefix = "EclecticIQ.IP"
        elif demisto_observable_type == "url":
            prefix = "EclecticIQ.URL"
        elif demisto_observable_type == "domain":
            prefix = "EclecticIQ.Domain"
        elif demisto_observable_type == "file" and bool(
            re.search(r"\w{40}", observable_value)
        ):  # SHA1
            prefix = "EclecticIQ.File"
        elif demisto_observable_type == "file" and bool(
            re.search(r"\w{64}", observable_value)
        ):  # SHA256
            prefix = "EclecticIQ.File"
        elif demisto_observable_type == "file" and bool(
            re.search(r"\w{32}", observable_value)
        ):  # MD5
            prefix = "EclecticIQ.File"
        elif demisto_observable_type == "file" and bool(
            re.search(r"\w{128}", observable_value)
        ):  # SHA512
            prefix = "EclecticIQ.File"
        elif demisto_observable_type == "email":
            prefix = "EclecticIQ.Email"

        command_results.append(
            CommandResults(readable_output=human_readable, raw_response=raw_result)
        )

    return command_results


def url_command(eiq_api):
    """
    Gets reputation of an EclecticIQ URI observable
    Parameters
    ----------
    url : str
        URL to get reputation of
    Returns
    -------
    entry
        Reputation of given URL
    """
    observable_value = demisto.args()["url"]
    response_eiq = eiq_api.lookup_observable(observable_value, "uri")
    url_result = parse_reputation_results(
        response_eiq, observable_value, "url", URL_THRESHOLD, "URL"
    )

    if SIGHTINGS_AUTO_CREATE:
        observable_dict = [
            {
                "observable_type": response_eiq["type"],
                "observable_value": observable_value,
                "observable_maliciousness": "medium",
                "observable_classification": "bad",
            }
        ]

        eiq_api.create_entity(
            observable_dict=observable_dict,
            source_group_name=GROUP_NAME,
            entity_title="XSOAR automatic Sighting for " + observable_value,
            entity_description="",
        )

    return url_result


def file_command(eiq_api):
    """
    Gets reputation of an EclecticIQ hash observable
    Parameters
    ----------
    file : str
        File hash to get reputation of
    Returns
    -------
    entry
        Reputation of given file hash
    """

    observable_value = demisto.args()["file"]
    response_eiq = eiq_api.lookup_observable(
        observable_value, ["hash-md5", "hash-sha1", "hash-sha256", "hash-sha512"]
    )
    file_result = parse_reputation_results(
        response_eiq, observable_value, "file", FILE_THRESHOLD, "File"
    )

    if SIGHTINGS_AUTO_CREATE:
        observable_dict = [
            {
                "observable_type": response_eiq["type"],
                "observable_value": observable_value,
                "observable_maliciousness": "medium",
                "observable_classification": "bad",
            }
        ]

        eiq_api.create_entity(
            observable_dict=observable_dict,
            source_group_name=GROUP_NAME,
            entity_title="XSOAR automatic Sighting for " + observable_value,
            entity_description="",
        )

    return file_result


def email_command(eiq_api):
    """
    Gets reputation of an EclecticIQ email address observable
    Parameters
    ----------
    email : str
        Email address to get reputation of
    Returns
    -------
    entry
        Reputation of given email address
    """

    observable_value = demisto.args()["email"]
    response_eiq = eiq_api.lookup_observable(observable_value, "email")
    email_result = parse_reputation_results(
        response_eiq, observable_value, "email", EMAIL_THRESHOLD, "Email"
    )

    if SIGHTINGS_AUTO_CREATE:
        observable_dict = [
            {
                "observable_type": response_eiq["type"],
                "observable_value": observable_value,
                "observable_maliciousness": "medium",
                "observable_classification": "bad",
            }
        ]

        eiq_api.create_entity(
            observable_dict=observable_dict,
            source_group_name=GROUP_NAME,
            entity_title="XSOAR automatic Sighting for " + observable_value,
            entity_description="",
        )

    return email_result


def domain_command(eiq_api):
    """
    Gets reputation of an EclecticIQ domain observable
    Parameters
    ----------
    domain : str
        Domain address to get reputation of
    Returns
    -------
    entry
        Reputation of given domain address
    """
    observable_value = demisto.args()["domain"]
    response_eiq = eiq_api.lookup_observable(observable_value, "domain")
    domain_result = parse_reputation_results(
        response_eiq, observable_value, "domain", DOMAIN_THRESHOLD, "Domain"
    )

    if SIGHTINGS_AUTO_CREATE:
        observable_dict = [
            {
                "observable_type": response_eiq["type"],
                "observable_value": observable_value,
                "observable_maliciousness": "medium",
                "observable_classification": "bad",
            }
        ]

        eiq_api.create_entity(
            observable_dict=observable_dict,
            source_group_name=GROUP_NAME,
            entity_title="XSOAR automatic Sighting for " + observable_value,
            entity_description="",
        )

    return domain_result


def get_entity(eiq_api):
    observable_value = demisto.args().get("observable_value", None)
    entity_value = demisto.args().get("entity_title", None)
    entity_type = demisto.args()["entity_type"]

    if entity_type == "all":
        entity_type = None

    query_result = eiq_api.search_entity(
        entity_value=entity_value,
        entity_type=entity_type,
        observable_value=observable_value,
    )

    if (type(query_result) is dict) or (type(query_result) is list):
        output_result = []
        for entity in query_result:
            record = entity

            record["observables_output"] = str(entity.get("observables_list"))
            record["relationships_output"] = str(entity.get("relationships_list"))
            output_result.append(record)

        total_count = len(query_result)
        human_readable_title = (
            "Total "
            + str(total_count)
            + " entities found in EclecticIQ Intelligence Center."
        )

        human_readable = tableToMarkdown(human_readable_title, output_result)

        return CommandResults(
            readable_output=human_readable,
            raw_response=query_result,
            outputs_prefix="EclecticIQ.Entity",
            outputs=output_result,
            outputs_key_field="entity_title")

    return "No entities found in EclecticIQ Intelligence Center."


def get_entity_by_id(eiq_api):
    entity_id = demisto.args().get("entity_id", None)
    query_result = eiq_api.get_entity_by_id(entity_id)

    if type(query_result).__name__ == "Exception" and "Status code:404" in str(
        query_result
    ):
        return "No entities found in EclecticIQ Platform."

    elif (type(query_result) is dict) or (type(query_result) is list):
        human_readable_title = "Entities found in EclecticIQ Intelligence Center."
        human_readable = tableToMarkdown(human_readable_title, query_result)

        return CommandResults(
            readable_output=human_readable,
            raw_response=query_result,
            outputs_prefix="EclecticIQ.EntityById",
            outputs=query_result,
            outputs_key_field="entity_title")

    return "No entities found in EclecticIQ Platform."


def create_sighting(eiq_api):
    args = demisto.args()
    observable_value = args.get("observable_value", "")
    observable_type = args.get("observable_type", "")
    observable_maliciousness = args.get("observable_maliciousness", "")
    sighting_title = args.get("sighting_title", "")
    sighting_description = args.get("sighting_description", "")
    sighting_confidence = args.get("sighting_confidence", "")
    sighting_impact = args.get("sighting_impact", "")
    sighting_tag = argToList(args.get("sighting_tag"))

    if sighting_tag == [""]:
        del sighting_tag[:]

    observable_record = {}

    observable_record = convert_maliciousness(observable_maliciousness)
    observable_record["observable_type"] = observable_type
    observable_record["observable_value"] = observable_value

    observable_list = []
    observable_list.append(observable_record)

    sighting_id = eiq_api.create_entity(
        observable_dict=observable_list,
        source_group_name=GROUP_NAME,
        entity_title=sighting_title,
        entity_description=sighting_description,
        entity_confidence=sighting_confidence,
        entity_tags=sighting_tag,
        entity_impact_value=sighting_impact,
    )

    raw_result = {
        "entity_id": sighting_id,
        "sighting_details": {
            "sighting_title": sighting_title,
            "observable_value": observable_value,
            "observable_type": observable_type,
            "observable_maliciousness": observable_maliciousness,
        },
    }

    entry_context = {
        "SightingId": sighting_id,
        "SightingDetails": {
            "SightingTitle": sighting_title,
            "ObservableValue": observable_value,
            "ObservableType": observable_type,
            "ObservableMaliciousness": observable_maliciousness,
        },
    }

    human_readable_title = (
        f'EclecticIQ Sighting Created, Entity ID - {raw_result["entity_id"]}'
    )
    human_readable = tableToMarkdown(human_readable_title, raw_result)

    return CommandResults(
        readable_output=human_readable,
        raw_response=raw_result,
        outputs_prefix="EclecticIQ.Sightings",
        outputs=entry_context,
        outputs_key_field="SightingId")


def convert_maliciousness(observable_dict):
    maliciousness_to_meta = {
        "Malicious (High confidence)": {
            "classification": "bad",
            "confidence": "high",
        },
        "Malicious (Medium confidence)": {
            "classification": "bad",
            "confidence": "medium",
        },
        "Malicious (Low confidence)": {
            "classification": "bad",
            "confidence": "low",
        },
        "Safe": {
            "classification": "good",
        },
        "Unknown": {},
    }

    record = {}
    meta_data = maliciousness_to_meta[observable_dict]
    record["observable_maliciousness"] = meta_data.get("confidence", "")  # type: ignore[attr-defined]
    record["observable_classification"] = meta_data.get("classification", "")  # type: ignore[attr-defined]

    return record


def prepare_entity_observables(
    observable1value, observable1type, observable1malicousness, observable_dict
):
    """Method duplicate _prepare_observables method with difference in params names.
    Been added for backward compatibility.

    """

    maliciousness_to_meta = {
        "Malicious (High confidence)": {
            "classification": "bad",
            "confidence": "high",
        },
        "Malicious (Medium confidence)": {
            "classification": "bad",
            "confidence": "medium",
        },
        "Malicious (Low confidence)": {
            "classification": "bad",
            "confidence": "low",
        },
        "Safe": {
            "classification": "good",
        },
        "Unknown": {},
    }

    maliciousness_to_meta_dict = {
        "high": {
            "classification": "bad",
            "confidence": "high",
        },
        "medium": {
            "classification": "bad",
            "confidence": "medium",
        },
        "low": {
            "classification": "bad",
            "confidence": "low",
        },
        "safe": {
            "classification": "good",
        },
        "unknown": {},
    }

    result = []

    record = {"observable_type": observable1type, "observable_value": observable1value}

    meta_data = maliciousness_to_meta[observable1malicousness]
    record["observable_maliciousness"] = meta_data.get("confidence", "")  # type: ignore[attr-defined]
    record["observable_classification"] = meta_data.get("classification", "")  # type: ignore[attr-defined]

    result.append(record)

    if observable_dict:
        observable_dict = json.loads(observable_dict)

        for observable in observable_dict:
            record = {
                "observable_type": observable["type"],
                "observable_value": observable["value"],
            }
            meta_data = maliciousness_to_meta_dict[observable["maliciousness"]]
            record["observable_maliciousness"] = meta_data.get("confidence", "")  # type: ignore[attr-defined]
            record["observable_classification"] = meta_data.get("classification", "")  # type: ignore[attr-defined]

            result.append(record)

    return result


def create_indicator(eiq_api):
    args = demisto.args()
    observable_value = args.get("observable_value", "")
    observable_type = args.get("observable_type", "")
    observable_maliciousness = args.get("observable_maliciousness", "")
    indicator_title = args.get("indicator_title", "")
    indicator_description = args.get("indicator_description", "")
    indicator_confidence = args.get("indicator_confidence", "")
    indicator_impact = args.get("indicator_impact", "")
    indicator_tag = argToList(args.get("indicator_tag"))
    observable_dictionary = args.get("observable_dictionary", {})

    if indicator_tag == [""]:
        del indicator_tag[:]

    if observable_dictionary == "":
        observable_dictionary = {}

    observable_list = []
    observable_list = prepare_entity_observables(
        observable_value,
        observable_type,
        observable_maliciousness,
        observable_dictionary,
    )

    indicator_id = eiq_api.create_entity(
        observable_dict=observable_list,
        source_group_name=GROUP_NAME,
        entity_title=indicator_title,
        entity_description=indicator_description,
        entity_confidence=indicator_confidence,
        entity_tags=indicator_tag,
        entity_impact_value=indicator_impact,
        entity_type="indicator",
    )

    raw_result = {
        "entity_id": indicator_id,
        "indicator_title": indicator_title,
        "observables_list": observable_list,
    }

    entry_context = {
        "IndicatorId": indicator_id,
        "IndicatorTitle": indicator_title,
        "ObservablesList": observable_list,
    }

    human_readable_title = "EclecticIQ Indicator Created, Entity ID - {}".format(
        raw_result["entity_id"]
    )
    human_readable = tableToMarkdown(human_readable_title, raw_result)

    return CommandResults(
        readable_output=human_readable,
        raw_response=raw_result,
        outputs_prefix="EclecticIQ.Indicators",
        outputs=entry_context,
        outputs_key_field="IndicatorId")


def get_indicators(eiq_api):
    feed_ids = demisto.params().get("feedId", "")

    if len(feed_ids) > 0:
        feeds_info = eiq_api.get_feed_info(feed_ids)
        indicators_to_add: list[dict] = []

        for item in feeds_info:
            item["id"] = str(item["id"])

            demisto.debug("Feed id {} is starting to fetch.".format(item["id"]))
            blocks = eiq_api.get_feed_content_blocks(item)

            for block in blocks:
                demisto.debug(
                    "Feed id={} preparing data to ingest block {}.".format(
                        str(item["id"]), block
                    )
                )
                data_from_block = eiq_api.download_block_list(block)
                indicators_to_add = indicators_to_add + export_csv_to_indicators_get(
                    item["id"], data_from_block
                )
                break

        human_readable = tableToMarkdown(
            "Indicators collected from first block of feed:" + str(feeds_info),
            indicators_to_add,
        )

        return CommandResults(readable_output=human_readable)
    else:
        human_readable = tableToMarkdown(
            "Feed ID to fetch is not configured in the Integreation settings.", {}
        )
        return CommandResults(readable_output=human_readable)


def export_csv_to_indicators_get(feed_id, text, flag=False):
    demisto.info(f"Getting Indicators from feed #{str(feed_id)}")
    text = io.StringIO(text)
    csvreader = csv.DictReader(text, delimiter=",")

    indicators_to_add = []

    indicator_types_mapper = {
        "cve": "CVE",
        "domain": "Domain",
        "email": "Email",
        "hash-md5": "File MD5",
        "hash-sha1": "File SHA-1",
        "hash-sha256": "File SHA-256",
        "hash-sha512": "File SHA-512",
        "ipv4": "IP",
        "ipv4-cidr": "CIDR",
        "ipv6": "IPv6",
        "uri": "URL",
    }

    maliciousness_dictionary = {
        "": 0,
        "unknown": 0,
        "safe": 1,
        "low": 2,
        "medium": 2,
        "high": 3,
    }

    if "diff" not in csvreader.fieldnames:  # type: ignore[operator]
        demisto.info("Update method is 'replace' or 'append'.")
        # If there is no "diff" column in the CSV
        # So the update method is set to "replace", this means we
        # delete everything from this feed and then recreate it.
        for row in csvreader:
            if row["type"] in indicator_types_mapper:
                indicator_obj = {
                    "value": row["value"],
                    "type": indicator_types_mapper[row["type"]],
                    "eclecticiqentityid": row["entity.id"],
                    "eclecticiqentitytitle": row["entity.title"],
                    "eclecticiqentitytype": row["entity.type"],
                    "eclecticiqfeedid": str(feed_id),
                    "eclecticiqsource": row["source.names"],
                    "eclecticiqentitydescription": row.get("entity.description", ""),
                    "score": maliciousness_dictionary[row["meta.confidence"]],
                }

                indicators_to_add.append(indicator_obj)

    return indicators_to_add


def fetch_indicators(eiq_api):
    feed_ids = demisto.params().get("feedId", "")

    if len(feed_ids) > 0:
        feeds_info = eiq_api.get_feed_info(feed_ids)
        context = demisto.getLastRun()

        for item in feeds_info:
            item["id"] = str(item["id"])

            demisto.debug("Feed id {} is starting to fetch.".format(item["id"]))

            flag = False
            state = context.get(
                item["id"],
                {
                    "created_at": None,
                    "feed_name": None,
                    "update_strategy": None,
                    "last_ingested": None,
                },
            )

            if not state["created_at"] or item["created_at"] != state["created_at"]:
                # check created_at field between platform and IBM
                # if they are different
                # delete all from this feed and ingest again
                flag = True

            if item["update_strategy"] == "REPLACE":
                flag = True

            if flag is True:
                context = demisto.getLastRun()
                context[item["id"]] = {
                    "created_at": item["created_at"],
                    "feed_name": item["name"],
                    "update_strategy": item["update_strategy"],
                    "last_ingested": None,
                }
                demisto.setLastRun(context)
                blocks = eiq_api.get_feed_content_blocks(item, state)
            else:
                state = context[item["id"]]
                blocks = eiq_api.get_feed_content_blocks(item, state)

            demisto.info("Starting Ingestion of feed #{}".format(item["id"]))

            indicators_to_add: list[dict] = []

            for block in blocks:
                demisto.debug(
                    "Feed id={} preparing data to ingest block {}.".format(
                        str(item["id"]), block
                    )
                )
                data_from_block = eiq_api.download_block_list(block)
                indicators_to_add = indicators_to_add + export_csv_to_indicators(
                    item["id"], data_from_block, flag
                )

                flag = False
                context[item["id"]]["last_ingested"] = block
                demisto.setLastRun(context)

            demisto.info("Feed id={} was fully ingested/updated.".format(str(item["id"])))

            return indicators_to_add
        return []
    else:
        demisto.error("Fetching enabled but Feed IDs not configured.")
        return []


def export_csv_to_indicators(feed_id, text, flag=False):
    demisto.info(f"Exporting to Indicators feed #{str(feed_id)}")
    text = io.StringIO(text)
    csvreader = csv.DictReader(text, delimiter=",")

    indicators_to_add = []

    indicator_types_mapper = {
        "cve": "CVE",
        "domain": "Domain",
        "email": "Email",
        "hash-md5": "File MD5",
        "hash-sha1": "File SHA-1",
        "hash-sha256": "File SHA-256",
        "hash-sha512": "File SHA-512",
        "ipv4": "IP",
        "ipv4-cidr": "CIDR",
        "ipv6": "IPv6",
        "uri": "URL",
    }

    maliciousness_dictionary = {
        "": 0,
        "unknown": 0,
        "safe": 1,
        "low": 2,
        "medium": 2,
        "high": 3,
    }

    if "diff" not in csvreader.fieldnames:  # type: ignore[operator]
        demisto.info(
            "Update method is 'replace' or 'append' so check for changes and update."
        )
        # If there is no "diff" column in the CSV
        # So the update method is set to "replace", this means we
        # delete everything from this feed and then recreate it.
        for row in csvreader:
            if row["type"] in indicator_types_mapper:
                raw_json = {}
                raw_json = row

                indicator_obj = {
                    "value": row["value"],
                    "type": indicator_types_mapper[row["type"]],
                    "rawJSON": raw_json,
                    "fields": {
                        "eclecticiqentityid": row["entity.id"],
                        "eclecticiqentitytitle": row["entity.title"],
                        "eclecticiqentitytype": row["entity.type"],
                        "eclecticiqfeedid": str(feed_id),
                        "eclecticiqsource": row["source.names"],
                        "eclecticiqentitydescription": row.get(
                            "entity.description", ""
                        ),
                    },
                    "score": maliciousness_dictionary[row["meta.confidence"]],
                }

                indicators_to_add.append(indicator_obj)

    return indicators_to_add


def request_get(eiq_api):
    uri = demisto.args().get("uri", "")

    raw_response = eiq_api.send_api_request("get", uri)
    entry_context = {}
    entry_context["URI"] = uri
    entry_context["ReplyStatus"] = str(raw_response.status_code)
    entry_context["ReplyBody"] = raw_response.json()

    human_readable_title = (
        "### EclecticIQ GET action to endpoint "
        + uri
        + " exectued. Reply status: "
        + str(raw_response.status_code)
    )

    return CommandResults(
        readable_output=human_readable_title,
        raw_response=raw_response.json(),
        outputs_prefix="EclecticIQ.GET",
        outputs=entry_context,
        outputs_key_field="URI")


def request_post(eiq_api):
    uri = demisto.args().get("uri", "")
    body = json.loads(demisto.args().get("body", "{}"))

    raw_response = eiq_api.send_api_request("post", uri, data=body)
    entry_context = {}
    entry_context["URI"] = uri
    entry_context["ReplyStatus"] = str(raw_response.status_code)
    entry_context["ReplyBody"] = raw_response.json()

    human_readable_title = f"### EclecticIQ POST action to endpoint {uri} exectued. Reply status: {raw_response.status_code}"

    return CommandResults(
        readable_output=human_readable_title,
        raw_response=raw_response.json(),
        outputs_prefix="EclecticIQ.POST",
        outputs=entry_context,
        outputs_key_field="URI")


def request_put(eiq_api):
    uri = demisto.args().get("uri", "")
    body = json.loads(demisto.args().get("body", "{}"))

    raw_response = eiq_api.send_api_request("put", uri, data=body)
    entry_context = {
        "URI": uri,
        "ReplyStatus": str(raw_response.status_code),
        "ReplyBody": raw_response.json(),
    }

    human_readable_title = f"### EclecticIQ PUT action to endpoint {uri} exectued. Reply status: {raw_response.status_code}"

    return CommandResults(
        readable_output=human_readable_title,
        raw_response=raw_response.json(),
        outputs_prefix="EclecticIQ.PUT",
        outputs=entry_context,
        outputs_key_field="URI"
    )


def request_patch(eiq_api):
    uri = demisto.args().get("uri", "")
    body = json.loads(demisto.args().get("body", "{}"))

    raw_response = eiq_api.send_api_request("patch", uri, data=body)
    entry_context = {
        "URI": uri,
        "ReplyStatus": str(raw_response.status_code),
        "ReplyBody": raw_response.json(),
    }

    human_readable_title = f"### EclecticIQ PATCH action to endpoint {uri} exectued. Reply status: {raw_response.status_code}"

    return CommandResults(
        readable_output=human_readable_title,
        raw_response=raw_response.json(),
        outputs_prefix="EclecticIQ.PATCH",
        outputs=entry_context,
        outputs_key_field="URI"
    )


def request_delete(eiq_api):
    uri = demisto.args().get("uri", "")

    raw_response = eiq_api.send_api_request("delete", uri)
    entry_context = {}
    entry_context["URI"] = uri
    entry_context["ReplyStatus"] = str(raw_response.status_code)

    human_readable_title = f"### EclecticIQ DELETE action to endpoint {uri} exectued. Reply status: {raw_response.status_code}"

    return CommandResults(
        readable_output=human_readable_title,
        raw_response=entry_context,
        outputs_prefix="EclecticIQ.DELETE",
        outputs=entry_context,
        outputs_key_field="URI")


""" COMMANDS MANAGER / SWITCH PANEL """


def main():
    COMMANDS = {
        "test-module": test_module,
        "url": url_command,
        "ip": ip_command,
        "email": email_command,
        "file": file_command,
        "domain": domain_command,
        "fetch-indicators": fetch_indicators,
        "eclecticiq-get-entity": get_entity,
        "eclecticiq-get-entity-by-id": get_entity_by_id,
        "eclecticiq-create-sighting": create_sighting,
        "eclecticiq-create-indicator": create_indicator,
        "eclecticiq-get-indicators": get_indicators,
        "eclecticiq-request-get": request_get,
        "eclecticiq-request-post": request_post,
        "eclecticiq-request-delete": request_delete,
        "eclecticiq-request-put": request_put,
        "eclecticiq-request-patch": request_patch,
    }

    if not demisto.params().get('proxy', False):
        skip_proxy()

    try:
        eiq = EclecticIQ_api(  # noqa: F841
            baseurl=SERVER,
            eiq_api_version=API_VERSION,
            username="",
            password=PASSWORD,
            verify_ssl=USE_SSL,
        )

        LOG(f"Command being called is {demisto.command()}")
        command = demisto.command()
        command_func = COMMANDS.get(command)

        if command == "fetch-indicators":
            indicators_to_add = fetch_indicators(eiq)
            for b in batch(indicators_to_add, batch_size=500):
                demisto.createIndicators(b)
        elif command is not None:
            return_results(command_func(eiq))  # type: ignore[misc]

    except Exception as e:
        return_error(f"Error has occurred in EclecticIQ integration: {str(e)}.")


if __name__ == "__builtin__" or __name__ == "builtins":
    main()
