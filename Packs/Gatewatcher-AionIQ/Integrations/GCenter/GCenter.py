"""Base Integration for Cortex XSOAR (aka Demisto)"""
from typing import (
    Any
)
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
import urllib3
# Disable insecure warnings
urllib3.disable_warnings()  # pylint: disable=no-member


class GwElasticQueryBuilder():
    """Represent an Elasticsearch query.

    Query is built using boolean clauses filter and must_not. Allows you to answer these questions:
      - List of files reconstructed by the Gcap over a 24H period.
      - List of files not reconstructed by the Gcap over a 24H period.
      - List of malcore alerts that does not have the flow_id field.
      - List of Sigflow alerts with a certain signature and originating from a certain interface.

    Aggregation query summarizes data as metrics, statistics, or other analytics. Allows you to answer these questions:
      - How many distinct files have been reconstructed by the Gcap.
      - List of distinct values of a field.
      - Count malcore alerts by interval of 1 hour.

    Class features:
      - Filter field exact value or value in list.
      - Filter existing/non existing field.
      - Filter timerange.
      - Filter document number.
      - Filter document field.
      - Date histogram aggregation.
      - Field cardinality aggregation.
      - Field terms aggregation.
    """

    def __init__(self):
        """Init class."""
        self.query = {"query": {}}  # type: ignore
        self.query["query"]["bool"] = {}
        self.query["query"]["bool"]["must_not"] = []
        self.query["query"]["bool"]["filter"] = []
        self.query["query"]["bool"]["filter"].append({})
        self.query["query"]["bool"]["filter"][0]["range"] = {}
        self.query["query"]["bool"]["filter"][0]["range"]["@timestamp"] = {}
        self.query["query"]["bool"]["filter"][0]["range"]["@timestamp"]["gte"] = "now-1d/d"
        self.query["query"]["bool"]["filter"][0]["range"]["@timestamp"]["lte"] = "now"

    def dumps(self, pretty: bool = False):
        """Get the query in json format.

        Args:
            pretty: True to indent the json string and False instead.

        Returns:
            Json string with indentation if pretty is True and without indentation if pretty is False.
        """
        if pretty:
            return json.dumps(self.query, indent=4)
        else:
            return json.dumps(self.query)

    def set_must_match(self, field: str, value: str) -> None:
        """Filter document that match the value using the term query.

        Args:
            field: Document key with format key1.key2.key3 for nested keys.
            value: Document key value that must match.
        """
        terms = {
            "term": {
                field: value
            }
        }
        self.query["query"]["bool"]["filter"].append(terms)

    def set_must_match_in_list(self, field: str, values: list) -> None:
        """Filter document that match one or more values provided in list using the terms query.

        Args:
            field: Document key with format key1.key2.key3 for nested keys.
            values: Document key values that must match.
        """
        terms = {
            "terms": {
                field: values
            }
        }
        self.query["query"]["bool"]["filter"].append(terms)

    def set_must_exists(self, field: str) -> None:
        """Filter document with existing key using the exists query.

        Args:
            field: Document key with format key1.key2.key3 for nested keys.
        """
        terms = {
            "exists": {
                "field": field
            }
        }
        self.query["query"]["bool"]["filter"].append(terms)

    def set_must_not_match(self, field: str, value: Union[str, list]) -> None:
        """Filter document that does not match the value or values using the term query.

        Args:
            field: Document key with format key1.key2.key3 for nested keys.
            value: Document key value that must not match, as a string or a list of strings.
        """
        if isinstance(value, str):
            value = [value]
        terms = {
            "terms": {
                field: value
            }
        }
        self.query["query"]["bool"]["must_not"].append(terms)

    def set_aggs_terms(self, field: str, size: int) -> None:
        """List and count each distinct values of a document field using the terms aggregation.

        Args:
            field: Document key with format key1.key2.key3 for nested keys.
            size: Number of distinct values to return. By default it will return the top ten values.

        Examples:
            List and count each event_type values::

                >>> query = GwElasticQueryBuilder()
                >>> query.set_size(0)
                >>> query.set_aggs_terms(field="event_type", size=10000)
                {
                    "event_type": {
                        "doc_count_error_upper_bound": 0,
                        "sum_other_doc_count": 0,
                        "buckets": [
                            {
                                "key": "alert",
                                "doc_count": 176305
                            },
                            {
                                "key": "dns",
                                "doc_count": 14550
                            },
                            {
                                "key": "fileinfo",
                                "doc_count": 144
                            }
                        ]
                    }
                }
        """
        terms = {
            field: {
                "terms": {
                    "field": field,
                    "size": size
                }
            }
        }
        if "aggs" not in self.query:
            self.query["aggs"] = {}
        self.query["aggs"].update(terms)

    def set_size(self, size: int) -> None:
        """Filter the number of returned documents.

        It does not affect aggregation query.
        Set it to 0 when using aggregation query to avoid getting the query results
        in adition to the aggregation results.

        Args:
            size: Maximum number of returned documents. By default all documents are returned.
        """
        self.query["size"] = size  # type: ignore[assignment]

    def set_timerange(self, lower: Optional[Union[str, datetime]] = None,
                      upper: Optional[Union[str, datetime]] = None) -> None:
        """Set the lower and upper timerange based on the now keyword.

        The unit for upper and lower relative timestamp are:
          - y: Years
          - M: Months
          - w: Weeks
          - d: Days
          - h: Hours
          - H: Hours
          - m: Minutes
          - s: Seconds

        Args:
            lower: Set the lower relative timestamp based on now or absolute timestamp based on datetime.
                    If set without the upper argument, the query lte field will be deleted.
                    Format: "(-/+)Xunit" ("+1h" to add an hour or "-1d" to substract 1 day) or datetime.utcnow().
            upper: Set the upper relative timestamp based on now or absolute timestamp based on datetime.
                    If set without the lower argument, the query gte field will be deleted.
                    Format: "(-/+)Xunit" ("+1h" to add an hour or "-1d" to substract 1 day) or datetime.utcnow().

        """
        if lower is None and upper is None:
            raise AttributeError("set_timerange take at least one argument between lower and upper: [ERROR]")
        timerange = self.query["query"]["bool"]["filter"][0]["range"]
        if isinstance(upper, str):
            timerange["@timestamp"]["lte"] = f"now{upper}"
        elif isinstance(upper, datetime):
            timerange["@timestamp"]["lte"] = upper.strftime("%Y-%m-%dT%H:%M:%S")
        elif upper is not None:
            raise TypeError("set_timerange upper argument only support str and datetime: [ERROR]")
        if isinstance(lower, str):
            timerange["@timestamp"]["gte"] = f"now{lower}"
        elif isinstance(lower, datetime):
            timerange["@timestamp"]["gte"] = lower.strftime("%Y-%m-%dT%H:%M:%S")
        elif lower is not None:
            raise TypeError("set_timerange lower argument only support str and datetime: [ERROR]")
        if lower is not None and upper is None:
            timerange["@timestamp"].pop("lte", None)
        elif upper is not None and lower is None:
            timerange["@timestamp"].pop("gte", None)


class GwAPIException(Exception):
    """A base class from which all other exceptions inherit.

    If you want to catch all errors that the gwapi_benedictine package might raise,
    catch this base exception.
    """


class GwRequests():
    """Allows to easily interact with HTTP server.

    Class features:
      - Get requests package wrapper.
      - Put requests package wrapper.
      - Post requests package wrapper.
      - Delete requests package wrapper.
    """

    PROXIES = {
        "http": "",
        "https": ""
    }

    def __init__(self, ip: str, headers: dict = {}, check_cert: bool = False,
                 proxies: dict = None) -> None:
        """Init.

        Disable urllib3 warning. Allow unsecure ciphers.

        Args:
            ip: IP address of the HTTP server.
            check_cert: True to validate server certificate and False instead.
            proxies: Requests proxies. Default to no proxies.
        """
        self.index_values = [
            "suricata",
            "codebreaker",
            "malware",
            "netdata",
            "syslog",
            "machine_learning",
            "retrohunt",
            "iocs"
        ]
        self.ip = ip
        self.headers = headers
        self.check_cert = check_cert
        if proxies is not None:
            self.PROXIES = proxies

    def _gen_request_kwargs(self,
                            endpoint: str,
                            data: dict,
                            json_data: dict,
                            params: dict,
                            headers: dict,
                            cookies: dict,
                            redirects: bool,
                            files: dict = None) -> dict:
        """Generate requests arguments.

        Args:
            endpoint: URL endpoint in format /XX/YY/ZZ.
            data: request data.
            json_data: Set to True if data is in json_data format and False instead.
            params: Set to True if data need to be send with the url and False instead.
            headers: Set to True if redirection is allowed and False instead.
            cookies: Set to True if redirection is allowed and False instead.
            redirects: Set to True if redirection is allowed and False instead.
            files: files to upload in multipart/form-data

        Returns:
            Return requests arguments in dictionnary format.
        """
        kwargs = {
            "url": f"https://{self.ip}{endpoint}",
            "headers": headers if headers else self.headers,
            "cookies": cookies,
            "verify": self.check_cert,
            "proxies": self.PROXIES,
            "allow_redirects": redirects,
            "data": data,
            "json": json_data,
            "params": params,
            "files": files
        }
        return kwargs

    def _get(self, endpoint: str,
             data: dict = None,
             json_data: dict = None,
             params: dict = None,
             headers: dict = None,
             cookies: dict = None,
             redirects: bool = True) -> requests.Response:
        """Wrap the get requests.

        Same arguments as _gen_request_kwargs functions.

        Returns:
            Return a requests object with properties:

            - status_code
            - reason
            - headers
            - text
        """
        kwargs = self._gen_request_kwargs(
            endpoint=endpoint,
            data=data,  # type: ignore
            json_data=json_data,  # type: ignore
            params=params,  # type: ignore
            headers=headers,  # type: ignore
            cookies=cookies,  # type: ignore
            redirects=redirects
        )
        return requests.get(**kwargs)

    def _post(self, endpoint: str,
              data: dict = None,
              json_data: dict = None,
              params: dict = None,
              headers: dict = None,
              cookies: dict = None,
              redirects: bool = True,
              files: dict = None) -> requests.Response:
        """Wrap the post requests.

        Same arguments as _gen_request_kwargs functions.

        Returns:
            Return a requests object with properties:

            - status_code
            - reason
            - headers
            - text
        """
        kwargs = self._gen_request_kwargs(
            endpoint=endpoint,
            data=data,  # type: ignore
            json_data=json_data,  # type: ignore
            params=params,  # type: ignore
            headers=headers,  # type: ignore
            cookies=cookies,  # type: ignore
            redirects=redirects,
            files=files
        )
        return requests.post(**kwargs)

    def _put(self, endpoint: str,
             data: dict = None,
             json_data: dict = None,
             params: dict = None,
             headers: dict = None,
             cookies: dict = None,
             redirects: bool = True,
             files: dict = None) -> requests.Response:
        """Wrap the put requests.

        Same arguments as _gen_request_kwargs functions.

        Returns:
            Return a requests object with properties:

            - status_code
            - reason
            - headers
            - text
        """
        kwargs = self._gen_request_kwargs(
            endpoint=endpoint,
            data=data,  # type: ignore
            json_data=json_data,  # type: ignore
            params=params,  # type: ignore
            headers=headers,  # type: ignore
            cookies=cookies,  # type: ignore
            redirects=redirects,
            files=files
        )
        return requests.put(**kwargs)

    def _delete(self, endpoint: str,
                data: dict = None,
                json_data: dict = None,
                params: dict = None,
                headers: dict = None,
                cookies: dict = None,
                redirects: bool = True) -> requests.Response:
        """Wrap the delete requests.

        Same arguments as _gen_request_kwargs functions.

        Returns:
            Return a requests object with properties:

            - status_code
            - reason
            - headers
            - text
        """
        kwargs = self._gen_request_kwargs(
            endpoint=endpoint,
            data=data,  # type: ignore
            json_data=json_data,  # type: ignore
            params=params,  # type: ignore
            headers=headers,  # type: ignore
            cookies=cookies,  # type: ignore
            redirects=redirects
        )
        return requests.delete(**kwargs)


class GwClient(GwRequests):
    """Client class to interact with the service API."""

    def auth(self, user: str = None, password: str = None, token: str = None) -> None:
        """Authentication through the GCenter API.

        Args:
            user: GCenter WEBui username.
            password: GCenter WEBui password.
            token: GCenter API token.

        Raises:
            GwAPIException: If status_code != 200.
        """
        if user is None and password is None and token is None:
            raise AttributeError("A user/password or an API token must be provided: [ERROR]")
        elif ((user is None and password is not None)
                or (user is not None and password is None)):
            raise AttributeError("A user and a password must be provided: [ERROR]")
        if user is not None and password is not None:
            response = self._post(
                endpoint="/api/auth/login",
                json_data={
                    "username": user,
                    "password": password
                }
            )
            if response.status_code == 200:
                demisto.info(
                    f"Authentication on GCenter {self.ip} with user {user}: [OK]"
                )
                self.headers["API-KEY"] = response.json()["token"]
            else:
                raise GwAPIException(
                    f"Authentication on GCenter {self.ip} with"
                    f" user {user}: [FAILED]",
                    response.text, response.status_code, response.reason
                )
        else:
            self.headers["API-KEY"] = token

    def is_authenticated(self) -> bool:
        """Return True if authenticated and False instead.

        Raises:
            GwAPIException: If status_code != 200.
        """
        response = self._get(
            endpoint="/api/status/healthchecks/"
        )
        if response.status_code == 200:
            demisto.info(
                f"Get healthchecks on GCenter {self.ip}: [OK]"
            )
            return True
        else:
            demisto.error(
                f"Get healthchecks on GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )
            return False

    def list_alerts(self) -> dict:
        """Get the latest elasticsearch alerts sorted by date
        in descending order (most recent first in the list).

        Returns:
            Alerts lists.

        Raises:
            GwAPIException: If status_code != 200.
        """
        response = self._get(
            endpoint="/api/raw-alerts/"
        )
        if response.status_code == 200:
            demisto.info(f"List alerts on GCenter {self.ip}: [OK]")
            return response.json()["results"]
        else:
            raise GwAPIException(
                f"List alerts on GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def get_alert(self, uid: str) -> dict:
        """Get an elasticsearch alert by uid.

        Args:
            uid: An alert uuid.

        Returns:
            The alert document.

        Raises:
            GwAPIException: If status_code != 200.
        """
        response = self._get(
            endpoint=f"/api/raw-alerts/{uid}/"
        )
        if response.status_code == 200:
            demisto.info(f"Get alert {uid} on GCenter {self.ip}: [OK]")
            return response.json()
        else:
            raise GwAPIException(
                f"Get alert {uid} on GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def get_malcore_list_entry(self, ltype: str) -> list:
        """Get malcore whitelist/blacklist entry.

        Args:
            ltype: List type either white or black.

        Returns:
            Malcore list

        Raises:
            GwAPIException: If status_code != 200.
        """
        response = self._get(
            endpoint=f"/api/malcore/{ltype}-list/",
        )
        if response.status_code == 200:
            demisto.info(f"Get malcore {ltype}lists on GCenter {self.ip}: [OK]")
            return response.json()["results"]
        else:
            raise GwAPIException(
                f"Get malcore {ltype}lists on GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def add_malcore_list_entry(self, ltype: str, sha256: str,
                               comment: str = None, threat: str = None) -> dict:  # noqa: E501
        """Add malcore whitelist/blacklist entry.

        Args:
            ltype: List type either white or black.
            sha256: Sha256 to be added.

        Returns:
            sha256 added to the whitelist/blacklist.

        Raises:
            GwAPIException: If status_code != 201.
        """
        response = self._post(
            endpoint=f"/api/malcore/{ltype}-list/",
            json_data={
                "sha256": sha256,
                "comment": comment,
                "threat": threat
            }
        )
        if response.status_code == 201:
            demisto.info(
                f"Add {ltype} list with sha256 {sha256} on"
                f" GCenter {self.ip}: [OK]"
            )
            return response.json()
        else:
            raise GwAPIException(
                f"Add {ltype} list with sha256 {sha256} on"
                f" GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def del_malcore_list_entry(self, ltype: str, sha256: str) -> None:
        """Del malcore whitelist/blacklist entry.

        Args:
            ltype: List type either white or black.
            sha256: Sha256 to be deleted.

        Raises:
            GwAPIException: If status_code != 204.
        """
        response = self._delete(
            endpoint=f"/api/malcore/{ltype}-list/{sha256}"
        )
        if response.status_code == 204:
            demisto.info(
                f"Delete {ltype} list with sha256 {sha256} on"
                f" GCenter {self.ip}: [OK]"
            )
        else:
            raise GwAPIException(
                f"Delete {ltype} list with sha256 {sha256} on"
                f" GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def get_dga_list_entry(self, ltype: str) -> list:  # noqa: E501
        """Get the domain name whitelist/blacklist entry.

        Args:
            ltype: List type either white or black.

        Returns:
            Domain list whitelist/blacklist.

        Raises:
            GwAPIException: If status_code != 200.
        """
        response = self._get(
            endpoint=f"/api/dga-detection/{ltype}-list/",
        )
        if response.status_code == 200:
            demisto.info(
                f"Get dga {ltype}lists on"
                f" GCenter {self.ip}: [OK]"
            )
            return response.json()["results"]
        else:
            raise GwAPIException(
                f"Get dga {ltype}lists on"
                f" GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def add_dga_list_entry(self, ltype: str, domain: str, comment: str = None) -> dict:  # noqa: E501
        """Add malcore whitelist/blacklist entry.

        Args:
            ltype: List type either white or black.
            domain: Domain name to be added.

        Returns:
            Domain added to the whitelist/blacklist.

        Raises:
            GwAPIException: If status_code != 201.
        """
        response = self._post(
            endpoint=f"/api/dga-detection/{ltype}-list/",
            json_data={
                "domain_name": domain,
                "comment": comment
            }
        )
        if response.status_code == 201:
            demisto.info(
                f"Add {ltype} list with domain {domain} on"
                f" GCenter {self.ip}: [OK]"
            )
            return response.json()
        else:
            raise GwAPIException(
                f"Add {ltype} list with domain {domain} on"
                f" GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def del_dga_list_entry(self, ltype: str, domain: str) -> None:
        """Del malcore whitelist/blacklist entry.

        Args:
            ltype: List type either white or black.
            domain: Domain name to be deleted.

        Raises:
            GwAPIException: If status_code != 204.
        """
        response = self._delete(
            endpoint=f"/api/dga-detection/{ltype}-list/{domain}"
        )
        if response.status_code == 204:
            demisto.info(
                f"Delete {ltype} list with domain {domain} on"
                f" GCenter {self.ip}: [OK]"
            )
        else:
            raise GwAPIException(
                f"Delete {ltype} list with domain {domain} on"
                f" GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def get_es_query(self, index: str, query: str) -> list:
        """Get results of an elasticsearch query.

        Args:
            index: Index name between suricata, codebreaker, malware,
                    netdata, syslog, machine_learning, retrohunt, iocs.
            query: Query in a dictionary format.

        Returns:
            The elacticsearch response.

        Raises:
            GwAPIException: If status_code != 200.
            TypeError: If index value doesn't exist.
        """

        if index not in self.index_values:
            raise TypeError(f"Index value must be between: {self.index_values}")
        response = self._post(
            endpoint=f"/api/data/es/search/?index={index}",
            json_data=json.loads(query)
        )
        if response.status_code == 200:
            demisto.info(
                f"Get elasticsearch results for index {index} on"
                f" GCenter {self.ip}: [OK]"
            )
            return response.json()
        else:
            raise GwAPIException(
                f"Get elasticsearch results for index {index} on"
                f" GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def get_es_wrapper(self, index: str, timerange: str, size: str, aggs_term: str = None, must_match: str = None,
                       must_exists: str = None, formatted: str = None) -> dict:
        """Get results of an elasticsearch query.

        Args:
            index: Index name between suricata, codebreaker, malware,
                    netdata, syslog, machine_learning, retrohunt, iocs
            aggs_term: List and count each distinct values of a document field using the terms aggregation
                        If aggs_term is empty list hits value
            must_match: Filter document that match the value using the term query
            must_exists: Filter document with existing key using the exists query
            timerange: Set the lower timerange in hour based on the now keyword
            formatted: True to get the list of aggregation value False to get entire response
            size : Set the number of aggregate or hits value that can be returned

        Returns:
            The elacticsearch response.

        Raises:
            GwAPIException: If status_code != 200.
            TypeError: If index value doesn't exist.
        """

        aggs_term = aggs_term.replace(" ", "").split(",") if aggs_term else []
        must_exists = must_exists.replace(" ", "").split(",") if must_exists else []
        must_match = must_match.replace(" ", "").split(",") if must_match else {}
        must_match = (
            dict(element.split('=') for element in must_match)
            if must_match
            else {}
        )

        try:
            size_converted = int(size)
        except ValueError:
            raise ValueError("Size value must be a number")
        hits_size = 0 if aggs_term else size_converted
        query_builder = GwElasticQueryBuilder()
        query_builder.set_size(hits_size)

        for field in aggs_term:
            query_builder.set_aggs_terms(field=field, size=size_converted)
        for field in must_exists:
            query_builder.set_must_exists(field=field)
        for field in must_match:
            query_builder.set_must_match(field=field, value=must_match[field])
        if timerange:
            query_builder.set_timerange(lower=f"-{timerange}h")

        if index not in self.index_values:
            raise TypeError(f"Index value must be between: {self.index_values}")
        response = self._post(
            endpoint=f"/api/data/es/search/?index={index}",
            json_data=json.loads(query_builder.dumps())
        )

        if response.status_code == 200:
            demisto.info(
                f"Get elasticsearch results for index {index} on"
                f" GCenter {self.ip}: [OK]"
            )
            response_formatted = response.json()
            if formatted == "True" and aggs_term:
                response_formatted = {}
                for agg_term in aggs_term:
                    response_formatted[agg_term] = [
                        bucket['key'] for bucket in response.json()['aggregations'][agg_term]["buckets"]
                    ]
            return response_formatted
        else:
            raise GwAPIException(
                f"Get elasticsearch results for index {index} on"
                f" GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def get_file_infected(self, timerange: str = None, size: str = None, state: str = None, uuid: str = None) -> list:  # noqa: E501
        """Get a file from an uuid.
            If there is no uuid, get all the files infected from a time interval.

        Args:
            uuid: The uuid of the file to get
            state: The state of the files to get, in list
            timerange: Set the lower timerange in minute based on the now keyword
            size: Set the number of aggregate value that can be returned

        Returns:
            Asset ignored.

        Raises:
            GwAPIException: If status_code != 200.
        """

        if uuid:
            uuids = [uuid]
        else:
            value_state = state.replace(" ", "").split(",") if state else ["Infected", "Suspicious"]
            try:
                size_converted = int(size) if size else 10000
            except ValueError:
                raise ValueError("Size value must be a number")
            if timerange is None:
                timerange = "60"
            query = GwElasticQueryBuilder()
            query.set_size(0)
            query.set_aggs_terms(field="uuid", size=size_converted)
            query.set_must_not_match(field="fileinfo.filename", value="/ls")
            query.set_must_match(field="state", value="Infected")
            query.set_must_match_in_list(field="state", values=value_state)
            query.set_must_match(field="event_type", value="malware")
            query.set_timerange(lower=f"-{timerange}m")
            response = self._post(
                endpoint="/api/data/es/search/?index=malware",
                json_data=json.loads(query.dumps())
            )
            if response.status_code == 200:
                demisto.info(f"Get ES uuid on GCenter {self.ip}: [OK]")
            else:
                raise GwAPIException(
                    f"Get alerts uuid on GCenter {self.ip}: [FAILED]",
                    response.text, response.status_code, response.reason
                )
            uuids = [bucket['key'] for bucket in response.json()['aggregations']["uuid"]["buckets"]]
        files = []
        for uuid in uuids:
            response = self._get(
                endpoint=f"/api/raw-alerts/{uuid}/file",
            )
            if response.status_code == 200:
                filename = response.headers.get("Content-Disposition", "").split("filename=")[1]
                content = response.content
                files.append(fileResult(filename, content))
            else:
                raise GwAPIException(
                    f"Get file on GCenter {self.ip}: [FAILED]",
                    response.text, response.status_code, response.reason
                )

        demisto.info(f"Get files infected on GCenter {self.ip}: [OK]")
        return files

    def get_ignore_asset_name(self) -> list:  # noqa: E501
        """Get ignore asset name.

        Returns:
            Asset ignored.

        Raises:
            GwAPIException: If status_code != 200.
        """
        response = self._get(
            endpoint="/api/ignore-lists/asset-names/",
        )
        if response.status_code == 200:
            demisto.info(f"Get ignore asset on GCenter {self.ip}: [OK]")
            return response.json()["results"]
        else:
            raise GwAPIException(
                f"Get ignore asset on GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def get_ignore_mac_address(self) -> list:
        """Get ignore mac address.

        Returns:
            Asset ignored.

        Raises:
            GwAPIException: If status_code != 200.
        """
        response = self._get(
            endpoint="/api/ignore-lists/mac-addresses/",
        )
        if response.status_code == 200:
            demisto.info(
                f"Get ignore mac address on GCenter {self.ip}: [OK]"
            )
            return response.json()["results"]
        else:
            raise GwAPIException(
                f"Get ignore mac address on GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def get_ignore_kuser_ip(self) -> list:
        """Get ignore Kerberos ip.

        Returns:
            Kerberos ip ignored.

        Raises:
            GwAPIException: If status_code != 200.
        """
        response = self._get(
            endpoint="/api/ignore-lists/kuser-ips/",
        )
        if response.status_code == 200:
            demisto.info(
                f"Get ignore kerberos ips on GCenter {self.ip}: [OK]"
            )
            return response.json()["results"]
        else:
            raise GwAPIException(
                f"Get ignore kerberos ips on GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def get_ignore_kuser_name(self) -> list:  # noqa: E501
        """Get ignore Kerberos username.

        Returns:
            Kerberos ignored.

        Raises:
            GwAPIException: If status_code != 200.
        """
        response = self._get(
            endpoint="/api/ignore-lists/kuser-names/"
        )
        if response.status_code == 200:
            demisto.info(
                f"Get ignore kerberos username on GCenter {self.ip}: [OK]"
            )
            return response.json()["results"]
        else:
            raise GwAPIException(
                f"Get ignore kerberos username on"
                f" GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def ignore_asset_name(self, name: str, start: bool = True, end: bool = True) -> dict:  # noqa: E501
        """Ignore asset name.

        Args:
            name: Asset name.
            start: Will be ignored if they start with this name.
            end: Will be ignored if they end with this name.

        Returns:
            Asset ignored.

        Raises:
            GwAPIException: If status_code != 201.
        """
        response = self._post(
            endpoint="/api/ignore-lists/asset-names/",
            json_data={
                "name": name,
                "is_startswith_pattern": start,
                "is_endswith_pattern": end
            }
        )
        if response.status_code == 201:
            demisto.info(f"Ignore asset {name} on GCenter {self.ip}: [OK]")
            return response.json()
        else:
            raise GwAPIException(
                f"Ignore asset {name} on GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def ignore_mac_address(self, mac: str, start: bool = True) -> dict:
        """Ignore mac address.

        Args:
            mac: Mac address name.
            start: Will be ignored if they start with this name.

        Returns:
            Asset ignored.

        Raises:
            GwAPIException: If status_code != 201.
        """
        response = self._post(
            endpoint="/api/ignore-lists/mac-addresses/",
            json_data={
                "address": mac,
                "is_startswith_pattern": start
            }
        )
        if response.status_code == 201:
            demisto.info(
                f"Ignore mac address {mac} on GCenter {self.ip}: [OK]"
            )
            return response.json()
        else:
            raise GwAPIException(
                f"Ignore mac address {mac} on GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def ignore_kuser_ip(self, ip: str) -> dict:
        """Ignore Kerberos ip.

        Args:
            ip: Kerberos ip.

        Returns:
            Kerberos ip ignored.

        Raises:
            GwAPIException: If status_code != 201.
        """
        response = self._post(
            endpoint="/api/ignore-lists/kuser-ips/",
            json_data={
                "ip": ip
            }
        )
        if response.status_code == 201:
            demisto.info(
                f"Ignore kerberos ip {ip} on GCenter {self.ip}: [OK]"
            )
            return response.json()
        else:
            raise GwAPIException(
                f"Ignore kerberos ip {ip} on GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def ignore_kuser_name(self, name: str, start: bool = True, end: bool = True) -> dict:  # noqa: E501
        """Ignore Kerberos username.

        Args:
            name: Kerberos username.
            start: Will be ignored if they start with this name.
            end: Will be ignored if they end with this name.

        Returns:
            Kerberos ignored.

        Raises:
            GwAPIException: If status_code != 201.
        """
        response = self._post(
            endpoint="/api/ignore-lists/kuser-names/",
            json_data={
                "name": name,
                "is_startswith_pattern": start,
                "is_endswith_pattern": end
            }
        )
        if response.status_code == 201:
            demisto.info(
                f"Ignore kerberos username {name} on GCenter {self.ip}: [OK]"
            )
            return response.json()
        else:
            raise GwAPIException(
                f"Ignore kerberos username {name} on"
                f" GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def del_ignore_asset_name(self, ignore_id: int) -> None:  # noqa: E501
        """Delete an ignore asset name.

        Args:
            ignore_id: Ignore list identifier.

        Raises:
            GwAPIException: If status_code != 204.
        """
        response = self._delete(
            endpoint=f"/api/ignore-lists/asset-names/{ignore_id}/"
        )
        if response.status_code == 204:
            demisto.info(f"Delete an ignore asset {ignore_id} on GCenter {self.ip}: [OK]")
        else:
            raise GwAPIException(
                f"Delete an ignore asset {ignore_id} on GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def del_ignore_mac_address(self, ignore_id: int) -> None:
        """Delete an ignore mac address.

        Args:
            ignore_id: Ignore list identifier.

        Raises:
            GwAPIException: If status_code != 204.
        """
        response = self._delete(
            endpoint=f"/api/ignore-lists/mac-addresses/{ignore_id}/"
        )
        if response.status_code == 204:
            demisto.info(
                f"Delete an ignore mac address {ignore_id} on GCenter {self.ip}: [OK]"
            )
        else:
            raise GwAPIException(
                f"Delete an ignore mac address {ignore_id} on GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def del_ignore_kuser_ip(self, ignore_id: int) -> None:
        """Delete an ignore Kerberos ip.

        Args:
            ignore_id: Ignore list identifier.

        Raises:
            GwAPIException: If status_code != 204.
        """
        response = self._delete(
            endpoint=f"/api/ignore-lists/kuser-ips/{ignore_id}/"
        )
        if response.status_code == 204:
            demisto.info(
                f"Delete an ignore kerberos ip {ignore_id} on GCenter {self.ip}: [OK]"
            )
        else:
            raise GwAPIException(
                f"Delete an ignore kerberos ip {ignore_id} on GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def del_ignore_kuser_name(self, ignore_id: int) -> None:  # noqa: E501
        """Delete an ignore Kerberos username.

        Args:
            ignore_id: Ignore list identifier.

        Raises:
            GwAPIException: If status_code != 204.
        """
        response = self._delete(
            endpoint=f"/api/ignore-lists/kuser-names/{ignore_id}/"
        )
        if response.status_code == 204:
            demisto.info(
                f"Delete an ignore kerberos username {ignore_id} on GCenter {self.ip}: [OK]"
            )
        else:
            raise GwAPIException(
                f"Delete an ignore kerberos username {ignore_id} on"
                f" GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def send_malware(self, filename: str, file_id: str) -> dict:
        """Send file to the GScan malcore analysis.

        Args:
            filename: Filename to be sent.
            file_id: The file entry id.

        Returns:
            Gscan analysis report.

        Raises:
            GwAPIException: If status_code != 201.
        """
        file = demisto.getFilePath(file_id)
        with open(file.get("path"), "rb") as fo:
            response = self._post(
                endpoint="/api/gscan/malcore/",
                files={
                    "file": (
                        filename,
                        fo
                    )
                }
            )
        if response.status_code == 201:
            demisto.info(
                f"Send malcore file {filename} on GCenter {self.ip}: [OK]"
            )
            return response.json()
        else:
            raise GwAPIException(
                f"Send malcore file {filename} on GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def send_shellcode(self, filename: str, file_id: str, deep: bool = False, timeout: int = None) -> dict:
        """Send file to the GScan shellcode analysis.

        Args:
            filename: Filename to be sent.
            file_id: The file entry id.
            deep: True to enabled deep scan and False instead.
            timeout: Deep scan timeout.

        Returns:
            Gscan analysis report.

        Raises:
            GwAPIException: If status_code != 201.
        """
        file = demisto.getFilePath(file_id)
        with open(file.get("path"), "rb") as fo:
            response = self._post(
                endpoint="/api/gscan/shellcode/",
                files={
                    "file": (
                        filename,
                        fo
                    ),
                    "deep": deep,
                    "timeout": timeout
                }
            )
        if response.status_code == 201:
            demisto.info(
                f"Send shellcode file {filename} on GCenter {self.ip}: [OK]"
            )
            return response.json()
        else:
            raise GwAPIException(
                f"Send shellcode file {filename} on GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )

    def send_powershell(self, filename: str, file_id: str) -> dict:
        """Send file to the GScan powershell analysis.

        Args:
            filename: Filename to be sent.
            file_id: The file entry id.

        Returns:
            Gscan analysis report.

        Raises:
            GwAPIException: If status_code != 201.
        """
        file = demisto.getFilePath(file_id)
        with open(file.get("path"), "rb") as fo:
            response = self._post(
                endpoint="/api/gscan/powershell/",
                files={
                    "file": (
                        filename,
                        fo
                    )
                }
            )
        if response.status_code == 201:
            demisto.info(
                f"Send powershell file {filename} on GCenter {self.ip}: [OK]"
            )
            return response.json()
        else:
            raise GwAPIException(
                f"Send powershell file {filename} on GCenter {self.ip}: [FAILED]",
                response.text, response.status_code, response.reason
            )


def test_module(client: GwClient) -> str:  # noqa: E501
    """Tests API connectivity and authentication command.

    Args:
        client: Client to interact with the GCenter.

    Returns:
        'Authentication successful' when the GCenter connection works.
        'Authentication error' when the GCenter connection doesn't works.
    """
    if client.is_authenticated():
        return "ok"
    else:
        return "Authentication error, please check ip/user/password/token: [ERROR]"


def gw_list_alerts(client: GwClient, args: dict[str, Any]) -> CommandResults:  # noqa: E501
    """Get the latest elasticsearch alerts sorted by date in
    descending order (most recent first in the list) command.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Alert.List" prefix.
    """
    result = client.list_alerts()
    readable_result = tableToMarkdown("Elasticsearch alerts list", result)
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="GCenter.Alert.List",
        outputs_key_field="id",
        outputs=result,
        raw_response=result
    )


def gw_get_alert(client: GwClient, args: dict[str, Any]) -> CommandResults:  # noqa: E501
    """Get an elasticsearch alert by uid command.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Alert.Single" prefix.
    """
    result = client.get_alert(
        uid=args.get("uid")  # type: ignore
    )
    readable_result = tableToMarkdown("Elasticsearch alert entry", result)
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="GCenter.Alert.Single",
        outputs_key_field="id",
        outputs=result,
        raw_response=result
    )


def gw_get_malcore_list_entry(client: GwClient, args: Optional[dict[Any, Any]]) -> CommandResults:  # noqa: E501
    """Get the malcore whitelist/blacklist

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Malcore.List" prefix.
    """
    result = client.get_malcore_list_entry(ltype=args.get("type"))  # type: ignore
    readable_result = tableToMarkdown("Malcore whitelist/blacklist entries", result)
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="GCenter.Malcore.List",
        outputs_key_field="sha256",
        outputs=result,
        raw_response=result
    )


def gw_add_malcore_list_entry(client: GwClient, args: dict[str, Any]) -> CommandResults:  # noqa: E501
    """Add malcore whitelist/blacklist entry command.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Malcore" prefix.
    """
    ltype = args.get("type")
    result = client.add_malcore_list_entry(
        ltype=ltype,  # type: ignore
        sha256=args.get("sha256"),  # type: ignore
        comment=args.get("comment", "added by cortex"),  # type: ignore
        threat=args.get("threat", "unknown")  # type: ignore
    )
    readable_result = tableToMarkdown(f"Malcore {ltype}list entry", result)
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="GCenter.Malcore",
        outputs_key_field="sha256",
        outputs=result,
        raw_response=result
    )


def gw_del_malcore_list_entry(client: GwClient, args: dict[str, Any]) -> CommandResults:  # noqa: E501
    """Del malcore whitelist/blacklist entry command.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Malcore" prefix.
    """
    client.del_malcore_list_entry(
        ltype=args.get("type"),  # type: ignore
        sha256=args.get("sha256")  # type: ignore
    )
    return CommandResults(
        readable_output=None,
        outputs_prefix="GCenter.Malcore",
        outputs_key_field=None,
        outputs=None,
        raw_response=None
    )


def gw_get_dga_list_entry(client: GwClient, args: Optional[dict[Any, Any]]) -> CommandResults:  # noqa: E501
    """Get dga whitelist/blacklist
    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Dga.List" prefix.
    """
    result = client.get_dga_list_entry(
        ltype=args.get("type"),  # type: ignore
    )
    readable_result = tableToMarkdown("DGA whitelist/blacklist entry", result)
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="GCenter.Dga.List",
        outputs_key_field="domain_name",
        outputs=result,
        raw_response=result
    )


def gw_add_dga_list_entry(client: GwClient, args: Optional[dict[Any, Any]]) -> CommandResults:  # noqa: E501
    """Add dga whitelist/blacklist entry command.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Dga" prefix.
    """
    result = client.add_dga_list_entry(
        ltype=args.get("type"),  # type: ignore
        domain=args.get("domain"),  # type: ignore
        comment=args.get("comment", "added by cortex")  # type: ignore
    )
    readable_result = tableToMarkdown("DGA whitelist/blacklist entry", result)
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="GCenter.Dga",
        outputs_key_field="domain_name",
        outputs=result,
        raw_response=result
    )


def gw_del_dga_list_entry(client: GwClient, args: dict[str, Any]) -> CommandResults:  # noqa: E501
    """Del dga whitelist/blacklist entry command.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Dga" prefix.
    """
    client.del_dga_list_entry(
        ltype=args.get("type"),  # type: ignore
        domain=args.get("domain")  # type: ignore
    )
    return CommandResults(
        readable_output=None,
        outputs_prefix="GCenter.Dga",
        outputs_key_field=None,
        outputs=None,
        raw_response=None
    )


def gw_es_query(client: GwClient, args: dict[str, Any]) -> CommandResults:  # noqa: E501
    """Get results of an elasticsearch query command.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Elastic" prefix.
    """
    result = client.get_es_query(
        index=args.get("index"),  # type: ignore
        query=args.get("query")  # type: ignore
    )
    readable_result = tableToMarkdown("Elasticsearch query result", result)
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="GCenter.Elastic",
        outputs_key_field=None,
        outputs=result,
        raw_response=result
    )


def gw_es_wrapper(client: GwClient, args: Optional[dict[Any, Any]]) -> CommandResults:  # noqa: E501
    """Get results of an elasticsearch query command.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Elastic.Wrapper" prefix.
    """
    result = client.get_es_wrapper(
        index=args.get("index"),  # type: ignore
        aggs_term=args.get("aggs_term"),  # type: ignore
        must_match=args.get("must_match"),  # type: ignore
        must_exists=args.get("must_exists"),  # type: ignore
        timerange=args.get("timerange"),  # type: ignore
        formatted=args.get("formatted"),  # type: ignore
        size=args.get("size")  # type: ignore
    )
    readable_result = tableToMarkdown("Elasticsearch wrapper result", result)
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="GCenter.Elastic.Wrapper",
        outputs_key_field=None,
        outputs=result,
        raw_response=result
    )


def gw_get_file_infected(client: GwClient, args: Optional[dict[Any, Any]]) -> CommandResults:  # noqa: E501
    """Get a file from an uuid.
        If there is no uuid, get all the files infected from a time interval.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.FileInfected.List" prefix.
    """
    result = client.get_file_infected(
        uuid=args.get("uuid"),  # type: ignore
        state=args.get("state"),  # type: ignore
        timerange=args.get("timerange"),  # type: ignore
        size=args.get("size"),  # type: ignore
    )
    readable_result = tableToMarkdown("Files infected entry", result)
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="GCenter.File",
        outputs_key_field="id",
        outputs=result,
        raw_response=result
    )


def gw_get_ignore_asset_name(client: GwClient, args: Optional[dict[Any, Any]]) -> CommandResults:  # noqa: E501
    """Get all the ignored assets name command.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Ignore.AssetName.List" prefix.
    """
    result = client.get_ignore_asset_name()
    readable_result = tableToMarkdown("Asset name entry", result)
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="GCenter.Ignore.AssetName.List",
        outputs_key_field="id",
        outputs=result,
        raw_response=result
    )


def gw_get_ignore_kuser_ip(client: GwClient, args: Optional[dict[Any, Any]]) -> CommandResults:  # noqa: E501
    """Get all the ignored Kerberos ips command.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Ignore.KuserIP.List" prefix.
    """
    result = client.get_ignore_kuser_ip()
    readable_result = tableToMarkdown("Kuser IP entry", result)
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="GCenter.Ignore.KuserIP.List",
        outputs_key_field="id",
        outputs=result,
        raw_response=result
    )


def gw_get_ignore_kuser_name(client: GwClient, args: Optional[dict[Any, Any]]) -> CommandResults:  # noqa: E501
    """Get all the ignored Kerberos username command.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Ignore.KuserName.List" prefix.
    """
    result = client.get_ignore_kuser_name()
    readable_result = tableToMarkdown("Kuser name entry", result)
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="GCenter.Ignore.KuserName.List",
        outputs_key_field="id",
        outputs=result,
        raw_response=result
    )


def gw_get_ignore_mac_address(client: GwClient, args: Optional[dict[Any, Any]]) -> CommandResults:  # noqa: E501
    """Get all the ignored mac addresses command.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Ignore.MacAddress.List" prefix.
    """
    result = client.get_ignore_mac_address()
    readable_result = tableToMarkdown("MAC adrress entry", result)
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="GCenter.Ignore.MacAddress.List",
        outputs_key_field="id",
        outputs=result,
        raw_response=result
    )


def gw_add_ignore_asset_name(client: GwClient, args: dict[str, Any]) -> CommandResults:  # noqa: E501
    """Ignore asset name command.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Ignore.AssetName" prefix.
    """
    result = client.ignore_asset_name(
        name=args.get("name"),  # type: ignore
        start=args.get("start"),  # type: ignore
        end=args.get("end")  # type: ignore
    )
    readable_result = tableToMarkdown("Asset name entry", result)
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="GCenter.Ignore.AssetName",
        outputs_key_field="id",
        outputs=result,
        raw_response=result
    )


def gw_add_ignore_kuser_ip(client: GwClient, args: dict[str, Any]) -> CommandResults:  # noqa: E501
    """Ignore Kerberos ip command.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Ignore.KuserIP" prefix.
    """
    result = client.ignore_kuser_ip(
        ip=args.get("ip")  # type: ignore
    )
    readable_result = tableToMarkdown("Kuser IP entry", result)
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="GCenter.Ignore.KuserIP",
        outputs_key_field="id",
        outputs=result,
        raw_response=result
    )


def gw_add_ignore_kuser_name(client: GwClient, args: dict[str, Any]) -> CommandResults:  # noqa: E501
    """Ignore Kerberos username command.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Ignore.KuserName" prefix.
    """
    result = client.ignore_kuser_name(
        name=args.get("name"),  # type: ignore
        start=args.get("start"),  # type: ignore
        end=args.get("end")  # type: ignore
    )
    readable_result = tableToMarkdown("Kuser name entry", result)
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="GCenter.Ignore.KuserName",
        outputs_key_field="id",
        outputs=result,
        raw_response=result
    )


def gw_add_ignore_mac_address(client: GwClient, args: dict[str, Any]) -> CommandResults:  # noqa: E501
    """Ignore mac address command.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Ignore" prefix.
    """
    result = client.ignore_mac_address(
        mac=args.get("mac"),  # type: ignore
        start=args.get("start")  # type: ignore
    )
    readable_result = tableToMarkdown("MAC adrress entry", result)
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="GCenter.Ignore.MacAddress",
        outputs_key_field="id",
        outputs=result,
        raw_response=result
    )


def gw_del_ignore_asset_name(client: GwClient, args: dict[str, Any]) -> CommandResults:  # noqa: E501
    """Delete ignore asset name command.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Ignore.AssetName" prefix.
    """
    result = client.del_ignore_asset_name(
        ignore_id=int(args.get("ignore_id"))  # type: ignore
    )
    readable_result = tableToMarkdown("Asset name entry", result)
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="GCenter.Ignore.AssetName",
        outputs_key_field=None,
        outputs=result,
        raw_response=result
    )


def gw_del_ignore_kuser_ip(client: GwClient, args: dict[str, Any]) -> CommandResults:  # noqa: E501
    """Delete ignore Kerberos ip command.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Ignore.KuserIP" prefix.
    """
    result = client.del_ignore_kuser_ip(
        ignore_id=int(args.get("ignore_id"))  # type: ignore
    )
    readable_result = tableToMarkdown("Kuser IP entry", result)
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="GCenter.Ignore.KuserIP",
        outputs_key_field=None,
        outputs=result,
        raw_response=result
    )


def gw_del_ignore_kuser_name(client: GwClient, args: dict[str, Any]) -> CommandResults:  # noqa: E501
    """Delete ignore Kerberos username command.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Ignore.KuserName" prefix.
    """
    result = client.del_ignore_kuser_name(
        ignore_id=int(args.get("ignore_id"))  # type: ignore
    )
    readable_result = tableToMarkdown("Kuser name entry", result)
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="GCenter.Ignore.KuserName",
        outputs_key_field=None,
        outputs=result,
        raw_response=result
    )


def gw_del_ignore_mac_address(client: GwClient, args: dict[str, Any]) -> CommandResults:  # noqa: E501
    """Delete ignore mac address command.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Ignore.MacAddress" prefix.
    """
    result = client.del_ignore_mac_address(
        ignore_id=int(args.get("ignore_id"))  # type: ignore
    )
    readable_result = tableToMarkdown("MAC address entry", result)
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="GCenter.Ignore.MacAddress",
        outputs_key_field=None,
        outputs=result,
        raw_response=result
    )


def gw_send_malware(client: GwClient, args: dict[str, Any]) -> CommandResults:  # noqa: E501
    """Send file to the GScan malcore analysis.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Gscan.Malware" prefix.
    """
    result = client.send_malware(
        filename=args.get("filename"),  # type: ignore
        file_id=args.get("file_id")  # type: ignore
    )
    readable_result = tableToMarkdown("Malcore analysis result", result)
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="GCenter.Gscan.Malware",
        outputs_key_field="id",
        outputs=result,
        raw_response=result
    )


def gw_send_powershell(client: GwClient, args: dict[str, Any]) -> CommandResults:  # noqa: E501
    """Send file to the GScan shellcode analysis command.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Gscan.Powershell" prefix.
    """
    result = client.send_powershell(
        filename=args.get("filename"),  # type: ignore
        file_id=args.get("file_id")  # type: ignore
    )
    readable_result = tableToMarkdown("Powershell analysis result", result)
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="GCenter.Gscan.Powershell",
        outputs_key_field="id",
        outputs=result,
        raw_response=result
    )


def gw_send_shellcode(client: GwClient, args: dict[str, Any]) -> CommandResults:  # noqa: E501
    """Send file to the GScan powershell analysis command.

    Args:
        client: Client to interact with the GCenter.
        args: Command arguments.

    Returns:
        CommandResults object with the "GCenter.Gscan.Shellcode" prefix.
    """
    result = client.send_shellcode(
        filename=args.get("filename"),  # type: ignore
        file_id=args.get("file_id"),  # type: ignore
        deep=args.get("deep"),  # type: ignore
        timeout=int(args.get("timeout"))  # type: ignore
    )
    readable_result = tableToMarkdown("Shellcode analysis result", result)
    return CommandResults(
        readable_output=readable_result,
        outputs_prefix="GCenter.Gscan.Shellcode",
        outputs_key_field="id",
        outputs=result,
        raw_response=result
    )


def main() -> None:
    """Main function, parses params and runs command functions."""

    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    ip = params.get("ip")
    token = params.get("token", None)
    user = params.get("credentials", {}).get("identifier", None)
    password = params.get("credentials", {}).get("password", None)
    check_cert = params.get("check_cert", False)

    demisto.debug(f"Command being called is {command}")
    try:
        client = GwClient(ip=ip, check_cert=check_cert)
        client.auth(
            user=user if user != "" else None,
            password=password if password != "" else None,
            token=token
        )
        if command == "test-module":
            return_results(
                test_module(client=client)
            )
        elif command == "gw-list-alerts":
            return_results(
                gw_list_alerts(client=client, args=args)
            )
        elif command == "gw-get-alert":
            return_results(
                gw_get_alert(client=client, args=args)
            )
        elif command == "gw-get-malcore-list-entry":
            return_results(
                gw_get_malcore_list_entry(client=client, args=args)
            )
        elif command == "gw-add-malcore-list-entry":
            return_results(
                gw_add_malcore_list_entry(client=client, args=args)
            )
        elif command == "gw-del-malcore-list-entry":
            return_results(
                gw_del_malcore_list_entry(client=client, args=args)
            )
        elif command == "gw-get-dga-list-entry":
            return_results(
                gw_get_dga_list_entry(client=client, args=args)
            )
        elif command == "gw-add-dga-list-entry":
            return_results(
                gw_add_dga_list_entry(client=client, args=args)
            )
        elif command == "gw-del-dga-list-entry":
            return_results(
                gw_del_dga_list_entry(client=client, args=args)
            )
        elif command == "gw-es-query":
            return_results(
                gw_es_query(client=client, args=args)
            )
        elif command == "gw-es-wrapper":
            return_results(
                gw_es_wrapper(client=client, args=args)
            )
        elif command == "gw-get-file-infected":
            return_results(
                gw_get_file_infected(client=client, args=args)
            )
        elif command == "gw-get-ignore-asset-name":
            return_results(
                gw_get_ignore_asset_name(client=client, args=args)
            )
        elif command == "gw-get-ignore-kuser-ip":
            return_results(
                gw_get_ignore_kuser_ip(client=client, args=args)
            )
        elif command == "gw-get-ignore-kuser-name":
            return_results(
                gw_get_ignore_kuser_name(client=client, args=args)
            )
        elif command == "gw-get-ignore-mac-address":
            return_results(
                gw_get_ignore_mac_address(client=client, args=args)
            )
        elif command == "gw-add-ignore-asset-name":
            return_results(
                gw_add_ignore_asset_name(client=client, args=args)
            )
        elif command == "gw-add-ignore-kuser-ip":
            return_results(
                gw_add_ignore_kuser_ip(client=client, args=args)
            )
        elif command == "gw-add-ignore-kuser-name":
            return_results(
                gw_add_ignore_kuser_name(client=client, args=args)
            )
        elif command == "gw-add-ignore-mac-address":
            return_results(
                gw_add_ignore_mac_address(client=client, args=args)
            )
        elif command == "gw-del-ignore-asset-name":
            return_results(
                gw_del_ignore_asset_name(client=client, args=args)
            )
        elif command == "gw-del-ignore-kuser-ip":
            return_results(
                gw_del_ignore_kuser_ip(client=client, args=args)
            )
        elif command == "gw-del-ignore-kuser-name":
            return_results(
                gw_del_ignore_kuser_name(client=client, args=args)
            )
        elif command == "gw-del-ignore-mac-address":
            return_results(
                gw_del_ignore_mac_address(client=client, args=args)
            )
        elif command == "gw-send-malware":
            return_results(
                gw_send_malware(client=client, args=args)
            )
        elif command == "gw-send-powershell":
            return_results(
                gw_send_powershell(client=client, args=args)
            )
        elif command == "gw-send-shellcode":
            return_results(
                gw_send_shellcode(client=client, args=args)
            )
    except Exception as e:
        return_error(
            f"Failed to execute {command} command.\nError: {str(e)}"
        )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
