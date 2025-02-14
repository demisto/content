import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *


""" IMPORTS """

from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings as urllib3_disable_warnings
from cyberintegrations import DRPPoller
from traceback import format_exc
from cyberintegrations.utils import ParserHelper
from enum import Enum
from dateparser import parse as dateparser_parse
from json import dumps as json_dumps
import base64
from requests import Response
from cyberintegrations.exception import ConnectionException
from cyberintegrations.cyberintegrations import Parser

# Disable insecure warnings
urllib3_disable_warnings(InsecureRequestWarning)

""" CONSTANTS """

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


class ViolationTypeMapping(Enum):
    WEB = 1
    MARKETPLACE = 3
    ADVERTISING = 5
    MOBILE_APPS = 2
    SOCIAL_NETWORKS = 4
    INSTANT_MESSENGERS = 6


class ViolationSubType(Enum):
    Counterfeit = 1
    Piracy = 2
    Partner_policy_compliance = 3
    Trademark = 4
    Malware = 5
    Phishing = 6
    Fraud = 7
    NoViolation = 8


COMMON_VIOLATION_MAPPING = {
    # Start Information From Group-IB DRP
    "id": "id",  # GIB DRP ID
    "title": "violation.title",  # GIB DRP Title
    "description": "violation.description",  # GIB DRP Description
    "brand": "brand",  # GIB DRP Brand
    "company": "company",  # GIB DRP Company
    "violation_uri": "violation.uri",  # GIB DRP VIOLATION URI
    "approve_state": "violation.approveState",  # GIB DRP Approve State
    "violation_status": "violation.status",  # GIB DRP Status
    "source": "violation.source",  # GIB DRP Source
    "violation_type": "violation.violationSubtype",  # GIB DRP Type
    "tags": "violation.tags.name",  # GIB DRP Tags
    "link": "link",  # GIB DRP Link
    # End Information From Group-IB DRP
    # Start Group-IB Dates
    "detected": "violation.detected",  # GIB DRP Detected
    "first_detected": "violation.firstDetected",  # GIB DRP First Detected
    "first_active": "violation.firstActive",  # GIB DRP First Active
    "first_solved": "violation.firstSolved",  # GIB DRP First Solved
    "dates_found_date": "violation.dates.foundDate",  # GIB DRP Found
    "dates_created_date": "violation.dates.createdDate",  # GIB DRP Created
    "dates_current_status_date": "violation.dates.currentStatusDate",  # GIB DRP Current Status Date
    "dates_approved_date": "violation.dates.approvedDate",  # GIB DRP Approved
    # End Group-IB Dates
    # Start Group-IB Images
    "images": "images",  # GIB DRP HTML Images
    # End Group-IB Images
    # Start Group-IB Tables
    "scores": {  # GIB DRP Scores Table
        "score": "violation.scores.score",
        "type": "violation.scores.type",
        "version": "violation.scores.version",
    },
    # End Group-IB Tables
}


TABLES_MAPPING = ["scores", "stages"]

STATUS_CODE_MSGS = {
    401: "Bad Credentials",
    403: "Something is wrong with your account, please, contact GIB.",
    404: "Not found. There is no such data on server.",
    500: "There are some troubles on server with your request.",
    301: "Verify that your public IP is whitelisted by Group IB.",
    302: "Verify that your public IP is whitelisted by Group IB.",
}
TIMEOUT = 360
RETRIES = 4
STATUS_LIST_TO_RETRY = [429, 500]


class Endpoints(Enum):
    VIOLATIONS = "violation/list"
    VIOLATION = "violation"
    BRANDS = "/settings/brands"
    SUBSCRIPTIONS = "/settings/subscriptions"
    RECEIVING_FILE = "/file/"
    CHANGE_APPROVE = "/violation/change-approve"


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, base_url, auth: tuple[str, str], verify=True, proxy=False):
        super().__init__(base_url=base_url, verify=verify, proxy=proxy, auth=auth)

        self.poller = DRPPoller(
            username=auth[0],
            api_key=auth[1],
            api_url=base_url,
        )
        self.poller.set_product(
            product_type="SOAR",
            product_name="CortexSOAR",
            product_version="unknown",
            integration_name="Group-IB Digital Risk Protection",
            integration_version="1.0.0",
        )
        self.additional_headers = {
            "Accept": "*/*",
            "User-Agent": f"SOAR/CortexSOAR_unknown/Group-IB Digital Risk Protection/{auth[0]}",
        }

    def generate_seq_update(self, first_fetch_time: str) -> str:
        date_from = dateparser_parse(date_string=first_fetch_time)
        if date_from is None:
            raise DemistoException(
                "Inappropriate first_fetch format, "
                f"please use a format such as: 2020-01-01 or January 1 2020 or 3 days. The format given is: {date_from}"
            )
        date_from = date_from.strftime("%Y-%m-%d")
        demisto.debug(f"date_from {date_from}")
        sequpdate = self.poller.get_seq_update_dict(
            date=date_from, collection=Endpoints.VIOLATIONS.value
        )
        demisto.debug(f"sequpdate {sequpdate}")
        return sequpdate

    def create_generator(
        self,
        first_fetch_time: str,
        last_run: dict,
        violation_subtypes: list[str] = None,
        brands: str = None,
        section: str = None,
    ):
        last_fetch = last_run.get("last_fetch", None)
        if last_run and last_fetch:
            sequpdate = last_fetch
        else:
            sequpdate = self.generate_seq_update(first_fetch_time)

        if section:
            section = section.strip()

        if brands:
            brands = brands.strip(",")

        demisto.debug(
            f"create_generator {Endpoints.VIOLATIONS.value} {violation_subtypes} {section} {sequpdate} brands {brands}"
        )
        try:

            return self.poller.create_update_generator(
                collection_name=Endpoints.VIOLATIONS.value,
                subtypes=violation_subtypes,
                section=section,
                brands=brands,
                sequpdate=sequpdate,
            )
        except ConnectionException as e:
            raise ConnectionException(
                f"Additional information: collection_name: {Endpoints.VIOLATIONS.value} "
                f"subtypes: {violation_subtypes} section: {section} sequpdate: {sequpdate} {str(e)}"
            ) from e

    def change_violation_status(self, feed_id: str, status: str) -> None:
        """
        Status could be approve or reject
        """
        self.poller.change_status(feed_id=feed_id, status=status)

    def get_brands(self):
        results = self._http_request(
            method="GET",
            url_suffix=Endpoints.BRANDS.value,
            timeout=TIMEOUT,
            retries=RETRIES,
            status_list_to_retry=STATUS_LIST_TO_RETRY,
            headers=self.additional_headers,
        )
        return results

    def get_formatted_brands(self) -> list[dict[str, str]]:
        results = self.get_brands()
        brands_data_raw = {
            "names": ParserHelper.find_element_by_key(results, "data.brands.name"),
            "ids": ParserHelper.find_element_by_key(results, "data.brands.id"),
        }
        brands_data = [
            {"name": name, "id": id_}
            for name, id_ in zip(brands_data_raw["names"], brands_data_raw["ids"])
        ]
        return brands_data

    def get_subscriptions(self):
        results = self._http_request(
            method="GET",
            url_suffix=Endpoints.SUBSCRIPTIONS.value,
            timeout=TIMEOUT,
            retries=RETRIES,
            status_list_to_retry=STATUS_LIST_TO_RETRY,
            headers=self.additional_headers,
        )
        return results

    def get_formatted_subscriptions(self) -> list[str]:
        results = self.get_subscriptions()
        return ParserHelper.find_element_by_key(results, "data.subscriptions")

    def get_file(self, file_sha: str) -> tuple[bytes, str] | None:
        try:
            response: Response = self._http_request(
                method="GET",
                url_suffix=Endpoints.RECEIVING_FILE.value + file_sha,
                timeout=TIMEOUT,
                retries=RETRIES,
                status_list_to_retry=STATUS_LIST_TO_RETRY,
                headers=self.additional_headers,
                resp_type="response",
            )
            data = response.content, CommonHelpers.extract_mime_type(
                response.headers.get("content-type", '')
            )
        except Exception:
            data = None
            demisto.debug(
                f"Could not download or the following image is not available: {file_sha}"
            )
        return data

    def get_violation_by_id(self, violation_id: str) -> Parser:
        results = self.poller.search_feed_by_id(
            collection_name=Endpoints.VIOLATION.value, feed_id=violation_id
        )
        return results

    def get_formatted_violation_by_id(
        self, violation_id: str, get_images: bool | None = True
    ) -> tuple[dict[Any, Any], list[dict[str, str | bytes]]]:
        results = self.get_violation_by_id(violation_id=violation_id)
        parse_result: dict[Any, Any] = results.parse_portion(
            keys=COMMON_VIOLATION_MAPPING, as_json=False
        )[0]
        updated_images = []
        if get_images:
            images = parse_result.get("images", [])
            if images and len(images) > 0:
                for image in images:
                    image_data_and_mime_type = self.get_file(file_sha=image)
                    if image_data_and_mime_type is not None:
                        image_data, mime_type = image_data_and_mime_type
                        demisto.debug(f"mime_type {mime_type}")
                        updated_images.append(
                            {
                                "file_sha": image,
                                "image_data": image_data,
                                "mime_type": mime_type,
                            }
                        )

        return parse_result, updated_images


""" Support functions """


class CommonHelpers:
    scores_tables_name_by_types = {
        "risk": "General Score ",
        "domain": "Domain Score ",
        "image": "Image Score ",
        "parking": "Parking Score ",
        "text": "Text Score ",
    }

    @staticmethod
    def transform_dict(
        input_dict: dict[str, list[str | list[Any]] | str | None]
    ) -> list[dict[str, Any]]:
        if not input_dict:
            return [{}]

        normalized_dict = {
            k: v if isinstance(v, list) else [v] for k, v in input_dict.items()  # type: ignore
        }

        max_length = max(
            (len(v) for v in normalized_dict.values() if isinstance(v, list)), default=1
        )

        result = []
        for i in range(max_length):
            result.append(
                {
                    k: (v[i] if i < len(v) else (v[0] if v else None))
                    for k, v in normalized_dict.items()
                }
            )

        return result

    @staticmethod
    def transform_additional_fields_to_markdown_tables(feed: dict):
        additional_tables = []
        delete_keys = []
        for key, value in feed.items():
            if key == "scores" and isinstance(value, dict):
                additional_data = CommonHelpers.transform_dict(value)
                position_score_dict = [
                    item for item in additional_data if item.get("type") == "position"
                ][0]
                additional_data = [
                    item for item in additional_data if item.get("type") != "position"
                ]

                for item in additional_data:
                    value_type = item.get("type")
                    table_name = "Table"
                    if value_type == "risk":
                        item.update(
                            {
                                "position_score": position_score_dict.get("score"),
                                "position_version": position_score_dict.get("version"),
                            }
                        )
                    elif value_type is not None:
                        table_name = CommonHelpers.scores_tables_name_by_types.get(value_type, "Table")

                    table = CommonHelpers.get_human_readable_feed(
                        table=item,
                        name=table_name,
                    )
                    additional_tables.append(
                        CommandResults(
                            readable_output=table,
                            ignore_auto_extract=True,
                        )
                    )

                delete_keys.append(key)

            elif isinstance(value, dict):
                additional_data = CommonHelpers.transform_dict(value)
                for index, item in enumerate(additional_data):
                    table = CommonHelpers.get_human_readable_feed(
                        table=item, name=f"{key} table {index}"
                    )
                    additional_tables.append(
                        CommandResults(
                            readable_output=table,
                            ignore_auto_extract=True,
                        )
                    )
                delete_keys.append(key)

        for key in delete_keys:
            feed.pop(key)

        return feed, additional_tables

    @staticmethod
    def get_human_readable_feed(table: dict[Any, Any], name: str):
        return tableToMarkdown(
            name=name,
            t=table,
            removeNull=True,
        )

    @staticmethod
    def get_table_data(
        feed: dict[Any, Any],
    ):
        updated_feed, additional_tables = (
            CommonHelpers.transform_additional_fields_to_markdown_tables(feed)
        )

        return updated_feed, additional_tables

    @staticmethod
    def violation_source_mapping(feed: dict) -> dict:
        source = feed.get("source")
        feed["source"] = ViolationTypeMapping(source).name
        return feed

    @staticmethod
    def convert_iso8601_with_timezone(date_str: str):

        if not re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+\d{4}$", date_str):
            raise ValueError(
                "Invalid date format. A string in the following format is expected 'YYYY-MM-DDTHH:MM:SS+0000'."
            )

        date_part = date_str[:19]  # '2024-10-30T15:12:34'
        timezone_part = date_str[19:]  # '+0000'

        formatted_timezone = f"{timezone_part[:3]}:{timezone_part[3:]}"  # '+00:00'

        formatted_date = f"{date_part}{formatted_timezone}"

        return formatted_date

    @staticmethod
    def format_dates_in_dict(data: dict):
        date_keys = [
            "dates_created_date",
            "dates_found_date",
            "dates_approved_date",
            "dates_current_status_date",
            "datetime",
            "first_detected",
            "first_active",
            "first_solved",
            "detected",
            "stages",
        ]
        for key, value in data.items():
            if key in date_keys and value is not None:
                if isinstance(value, str):
                    data[key] = CommonHelpers.convert_iso8601_with_timezone(value)
                elif isinstance(value, dict):
                    CommonHelpers.format_dates_in_dict(value)
                elif isinstance(value, list):
                    data[key] = list(
                        map(CommonHelpers.convert_iso8601_with_timezone, value)
                    )
        return data

    @staticmethod
    def all_lists_empty(data: dict[str, Any] | list[Any]) -> bool:
        all_empty = True

        if isinstance(data, dict):
            for value in data.values():
                if isinstance(value, list):
                    if value:
                        all_empty = False
                elif isinstance(value, dict) and not CommonHelpers.all_lists_empty(
                    value
                ):
                    all_empty = False
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and not CommonHelpers.all_lists_empty(item):
                    all_empty = False

        return all_empty

    @staticmethod
    def replace_empty_values(
        data: dict[str, Any] | list[dict[str, Any]]
    ) -> dict[str, Any] | list[dict[str, Any]]:

        if isinstance(data, dict):
            return {
                key: CommonHelpers.replace_empty_values(value)
                for key, value in data.items()
            }

        elif isinstance(data, list):
            if not data:
                return None  # type: ignore

            if all(isinstance(item, list) and not item for item in data):
                return None  # type: ignore

            return [CommonHelpers.replace_empty_values(item) for item in data]  # type: ignore

        else:
            if data == "":
                return None
            return data

    @staticmethod
    def remove_underscore_and_lowercase_keys(
        dict_list: list[dict[str, Any]] | list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        updated_dicts = []

        for d in dict_list:
            new_dict = {}
            for key, value in d.items():
                new_key = key.replace("_", "").lower()
                new_dict[new_key] = value

            updated_dicts.append(new_dict)

        return updated_dicts

    @staticmethod
    def data_pre_cleaning(violation: dict[str, Any]) -> dict[str, Any]:
        demisto.debug(f"data_pre_cleaning {violation}")
        violation_uri: str = violation.get("violation_uri", "")
        if violation_uri.startswith("//"):
            violation_uri = violation_uri[2:]

        violation["violation_uri"] = violation_uri

        tags = violation.get("tags")
        if tags:
            tags = [item for item in tags if item is not None]

        violation["tags"] = tags

        demisto.debug(f"return_data_pre_cleaning {violation}")
        return violation

    @staticmethod
    def extract_mime_type(content_type: str) -> str:
        match = re.match(r"^\s*([^;]+)", content_type)
        return match.group(1).strip() if match else "image/jpeg"


class IncidentBuilder:
    def __init__(
        self,
        client: Client,
        last_run: dict,
        first_fetch_time: str,
        max_requests: int,
        download_images: bool,
        violation_subtypes: list[str] | list | None,
        violation_section: str | None,
        brands: str | None,
    ) -> None:
        self.client = client
        self.last_run = last_run
        self.first_fetch_time = first_fetch_time
        self.max_requests = max_requests
        self.violation_subtypes = violation_subtypes
        self.violation_section = violation_section
        self.brands = brands
        self.download_images = download_images

    def transform_fields_to_grid_table(self, incident: dict):
        if TABLES_MAPPING:
            for field in TABLES_MAPPING:
                field_data = incident.get(field, {})
                if field_data and CommonHelpers.all_lists_empty(field_data) is False:
                    transformed_data = CommonHelpers.transform_dict(
                        input_dict=field_data
                    )

                    transformed_and_replaced_empty_values_data = (
                        CommonHelpers.replace_empty_values(transformed_data)
                    )
                    clean_data = CommonHelpers.remove_underscore_and_lowercase_keys(
                        transformed_and_replaced_empty_values_data  # type: ignore
                    )
                    if field == "scores":
                        clean_data = [
                            item for item in clean_data if item["type"] != "position"
                        ]
                        for score in clean_data:
                            score_type = score.get("type")
                            if isinstance(score_type, str):
                                score["type"] = CommonHelpers.scores_tables_name_by_types.get(score_type, "Unknown")
                            else:
                                score["type"] = "Unknown"

                        demisto.debug(f"clean_data {clean_data} {type(clean_data)}")

                    incident[field] = clean_data
                else:
                    incident[field] = None

        return incident

    def build(self) -> tuple[dict[str, int | Any], list]:
        next_run: dict[str, int | Any] = {"last_fetch": {}}
        violations = []
        requests_count = 0

        portions = self.client.create_generator(
            violation_subtypes=self.violation_subtypes,
            section=self.violation_section,
            brands=self.brands,
            first_fetch_time=self.first_fetch_time,
            last_run=self.last_run,
        )
        for portion in portions:
            sequpdate = portion.sequpdate
            parse_result: list[dict[Any, Any]] = portion.parse_portion(
                keys=COMMON_VIOLATION_MAPPING, as_json=False
            )

            for feed in parse_result:
                feed = CommonHelpers.data_pre_cleaning(violation=feed)
                feed = CommonHelpers.violation_source_mapping(feed=feed)
                feed = CommonHelpers.format_dates_in_dict(data=feed)
                incident = self.transform_fields_to_grid_table(incident=feed)

                if self.download_images:
                    images = incident.get("images", [])
                    updated_images = []

                    if images and len(images) > 0:
                        for image in images:
                            image_data = self.client.get_file(file_sha=image)
                            if image_data:
                                image_bytes, mime_type = image_data
                                demisto.debug(f"mime_type {mime_type}")
                                image_base64_uri = f"data:{mime_type};base64,{base64.b64encode(image_bytes).decode('utf-8')}"
                                image_html = f'<img src="{image_base64_uri}" alt="Violation Incident Image" />'
                                updated_images.append(image_html)

                    if len(updated_images) > 0:
                        incident["images"] = "<br/>".join(updated_images)
                else:
                    incident.pop("images")

                incident.update(
                    {
                        "name": f"Violation {incident.get('id')}",
                        "occurred": incident.get("detected"),
                        "gibType": Endpoints.VIOLATIONS.value,
                    }
                )
                violations.append(
                    {
                        "name": incident.get("name"),
                        "occurred": incident.get("occurred"),
                        "rawJSON": json_dumps(incident),
                        "dbotMirrorId": incident.get("id"),
                    }
                )
            next_run["last_fetch"] = sequpdate
            requests_count += 1
            if requests_count > self.max_requests:
                break
        return next_run, violations


class BuilderCommandResponses:
    def __init__(
        self,
        requested_method: str,
        client: Client,
        args: dict,
        first_fetch: str,
        max_requests: int,
    ) -> None:
        self.requested_method = requested_method
        self.client = client
        self.args = args
        self.first_fetch = first_fetch
        self.max_requests = max_requests

    def get_brands(self) -> CommandResults:
        response_result = self.client.get_formatted_brands()
        readable_output = tableToMarkdown(
            name="Installed Brands",
            t=response_result,
            headers=["name", "id"],
            headerTransform=lambda x: x.capitalize(),
        )

        return CommandResults(
            outputs_prefix="GIBDRP.OtherInfo",
            outputs_key_field="id",
            outputs={"brands": response_result},
            readable_output=readable_output,
            ignore_auto_extract=True,
            raw_response=response_result,
        )

    def get_subscriptions(self) -> CommandResults:
        response_result = self.client.get_formatted_subscriptions()
        readable_output = tableToMarkdown(
            name="Purchased subscriptions",
            t=response_result,
            headers="Subscriptions",
        )
        return CommandResults(
            outputs_prefix="GIBDRP.OtherInfo",
            outputs_key_field="subscriptions",
            outputs={"subscriptions": response_result},
            readable_output=readable_output,
            ignore_auto_extract=True,
            raw_response=response_result,
        )

    def get_violation_by_id(self) -> list[CommandResults]:
        """
        the returned list has dict[str, Any], which is fileResult.
        And an important note, not necessarily picture files, i.e. fileResults definitely will be.
        """
        id_ = str(self.args.get("id"))
        parse_result, updated_images = self.client.get_formatted_violation_by_id(violation_id=id_)
        parse_result: dict = CommonHelpers.data_pre_cleaning(violation=parse_result)
        parse_result = CommonHelpers.violation_source_mapping(feed=parse_result)
        updated_feed, additional_tables = CommonHelpers.get_table_data(
            feed=parse_result
        )
        readable_output = CommonHelpers.get_human_readable_feed(
            table=updated_feed, name=f"Feed {id_}"
        )
        results = []
        results.append(
            CommandResults(
                outputs_key_field="id",
                outputs=updated_feed,
                readable_output=readable_output,
                raw_response=updated_feed,
                ignore_auto_extract=True,
            )
        )
        results.extend(additional_tables)
        if updated_images:
            for updated_image in updated_images:
                results.append(
                    fileResult(
                        filename=f"Attached image {updated_image.get('file_sha', 'default')}",  # type: ignore
                        data=updated_image.get("image_data", ""),
                    )
                )
        return results

    def change_violation_status(self) -> str:
        id_ = str(self.args.get("id"))
        status = str(self.args.get("status"))
        self.client.change_violation_status(feed_id=id_, status=status)
        demisto.debug(f"change_violation_status {id_} {status}")
        return f"Status has been successfully changed to {status}"

    def build(self) -> str | tuple[CommandResults, dict[str, Any]] | CommandResults:
        # Check if the method exists in the class
        if hasattr(self, self.requested_method) and callable(
            getattr(self, self.requested_method)
        ):
            # Call the method
            return getattr(self, self.requested_method)()
        else:
            raise AttributeError(f"Method {self.requested_method} is not implemented.")


""" Commands """


class Commands:
    methods_requiring_return_results = {
        "get_brands",
        "get_subscriptions",
        "get_violation_by_id",
        "change_violation_status",
        "test_module",
    }

    def __init__(
        self,
        client: Client,
        command: str,
        args: dict,
        first_fetch: str,
        max_requests: int,
        download_images: bool,
        violation_subtypes: list[str] | list | None,
        violation_section: str | None = None,
        brands: str | None = None,
    ) -> None:
        self.client = client
        self.command = command
        self.args = args
        self.first_fetch = first_fetch
        self.max_requests = max_requests
        self.last_run = demisto.getLastRun()
        self.requested_method = self.command.replace("gibdrp-", "").replace("-", "_")
        self.violation_subtypes = violation_subtypes
        self.violation_section = violation_section
        self.brands = brands
        self.download_images = download_images

    def get_brands(self) -> str | tuple[CommandResults, dict[str, Any]] | CommandResults:
        results = BuilderCommandResponses(
            self.requested_method,
            self.client,
            self.args,
            self.first_fetch,
            self.max_requests,
        ).build()
        return results

    def get_subscriptions(self) -> str | tuple[CommandResults, dict[str, Any]] | CommandResults:
        results = BuilderCommandResponses(
            self.requested_method,
            self.client,
            self.args,
            self.first_fetch,
            self.max_requests,
        ).build()
        return results

    def get_violation_by_id(self) -> str | tuple[CommandResults, dict[str, Any]] | CommandResults:
        results = BuilderCommandResponses(
            self.requested_method,
            self.client,
            self.args,
            self.first_fetch,
            self.max_requests,
        ).build()
        return results

    def change_violation_status(self) -> str | tuple[CommandResults, dict[str, Any]] | CommandResults:
        results = BuilderCommandResponses(
            self.requested_method,
            self.client,
            self.args,
            self.first_fetch,
            self.max_requests,
        ).build()
        return results

    def test_module(self) -> str:
        response = self.client.get_formatted_brands()
        if isinstance(response, list) and len(response) > 0:
            return "ok"
        return "Test failed, some problems with getting brands."

    def fetch_incidents(
        self,
    ) -> tuple[dict[str, int | Any], list]:
        next_run, violations = IncidentBuilder(
            client=self.client,
            last_run=self.last_run,
            first_fetch_time=self.first_fetch,
            max_requests=self.max_requests,
            violation_subtypes=self.violation_subtypes,
            violation_section=self.violation_section,
            brands=self.brands,
            download_images=self.download_images,
        ).build()
        return next_run, violations

    @staticmethod
    def get_avalible_commands():
        """
        Returns a list of available commands.
        Adds the prefix `gibdrp-` to all methods except `test_module` and `fetch_incidents`.
        """

        def format_method(method_name: str) -> str | None:
            # Exclude magic methods and the get_avalible_commands and get_results functions themselves
            if method_name.startswith("__") or method_name in (
                "get_avalible_commands",
                "get_results",
            ):
                return None
            # Exceptions: methods without a prefix but with hyphens
            if method_name in ["test_module", "fetch_incidents"]:
                return method_name.replace("_", "-")
            # For the others, add a prefix and replace `_` with `-`
            return f"gibdrp-{method_name.replace('_', '-')}"

        # Get and format all methods
        methods = [
            format_method(method)
            for method in dir(Commands)
            if callable(getattr(Commands, method))
        ]
        return list(filter(None, methods))

    def get_results(
        self,
    ) -> (
        tuple[CommandResults, str]
        | tuple[
            tuple[
                CommandResults, tuple[dict, list]
            ],
            str
        ]
        | tuple[str, str]
        | tuple[tuple[dict[str, int | Any], list], str]
    ):
        # Check if the method exists in the class
        if hasattr(self, self.requested_method) and callable(
            getattr(self, self.requested_method)
        ):
            # Call the method
            return getattr(self, self.requested_method)(), self.requested_method
        else:
            raise AttributeError(f"Command {self.command} is not implemented.")


def main():
    """
    PARSE AND VALIDATE INTEGRATION PARAMS
    """
    try:
        params = demisto.params()
        args = demisto.args()
        command = demisto.command()
        username, api_token = (
            params.get("credentials", {}).get("identifier", ""),
            params.get("credentials", {}).get("password", ""),
        )
        base_url = str(params.get("url"))
        proxy = params.get("proxy", False)
        verify_certificate = not params.get("insecure", False)
        first_fetch = params.get("first_fetch", "3 days").strip()
        max_requests = int(params.get("max_fetch", 3))
        # violation_subtypes = params.get("violationSubtypes") # At the moment this
        # filtering moment is not valid,
        # it can be used once the cyberintegrations library is updated
        violation_subtypes = None
        violation_section = params.get("violationSection")
        # Currently all brands are transferred, but filtering will only happen on the very
        # first brand because of the filtering in the library,
        # but after time it is planned to update the library and then it will be possible
        # to filter on multiple brands
        brands = params.get("brands")
        download_images = params.get("download_images", False)

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            auth=(username, api_token),
            proxy=proxy,
        )
        if command not in Commands.get_avalible_commands():
            raise Exception(f"{command} invalid")

        results, requested_method = Commands(
            client=client,
            command=command,
            args=args,
            first_fetch=first_fetch,
            max_requests=max_requests,
            violation_subtypes=violation_subtypes,
            violation_section=violation_section,
            brands=brands,
            download_images=download_images,
        ).get_results()
        if requested_method in Commands.methods_requiring_return_results:
            return_results(results)
        else:
            if isinstance(results, tuple) and len(results) == 2:
                next_run, violations = results
                demisto.setLastRun(next_run)
                demisto.incidents(violations)
            else:
                raise ValueError("Expected results to be a tuple containing next_run and violations")

    except Exception:
        return_error(
            f"Failed to execute {demisto.command()} command.\n"
            f"Error: {format_exc()}"
        )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
