import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

SCORE_TABLE_FILE = {
    "unknown": Common.DBotScore.NONE,
    "benign": Common.DBotScore.GOOD,
    "grayware": Common.DBotScore.SUSPICIOUS,
    "malicious": Common.DBotScore.BAD,
}


class ReputationType:
    FILE = "file"
    CVE = "cve"
    ANTIVIRUS = "antivirus"
    SPYWARE = "spyware"
    FILEFORMAT = "fileformat"
    VULNERABILITY = "vulnerability"
    DNS = "dns"
    RTDNS = "rtdns"
    SPYWAREC2 = "spywarec2"
    RELEASE_NOTES = "release_notes"


HEADERS_FILE = ["FileType", "MD5", "SHA256", "SHA1", "Size", "Status"]
HEADERS_CVE = ["ID", "Description", "Score", "Published", "Modified"]
HEADERS_SPYWARE = [
    "ThreatID",
    "Name",
    "Description",
    "Vendor",
    "Score",
    "Default action",
    "Details",
    "Reference",
    "Status",
    "Min version",
    "Max version",
    "CVE",
]
HEADERS_VULNERABILITY = [
    "ThreatID",
    "Name",
    "Description",
    "Category",
    "Score",
    "Default action",
    "Vendor",
    "Reference",
    "Status",
    "Published version",
    "Latest release version",
    "Published",
    "Latest release time",
    "CVE",
]
HEADERS_FILEFORMAT = [
    "ThreatID",
    "Name",
    "Description",
    "Category",
    "Score",
    "Default action",
    "Vendor",
    "Reference",
    "Status",
    "Published version",
    "Latest release version",
    "Published",
    "Latest release time",
]
HEADERS_ANTIVIRUS = [
    "ThreatID",
    "Name",
    "Description",
    "Subtype",
    "Score",
    "Action",
    "Creation Time",
    "Related SHA256 hashes",
    "Release",
]
HEADERS_DNS_RTDNS_SPYWAREC2 = [
    "ThreatID",
    "Name",
    "Description",
    "Severity",
    "Type",
    "Subtype",
    "Action",
    "Creation Time",
    "Status",
    "Release",
]

DATE_REGEX = r"\d{4}-[0-9]{2}-[0-9]{2}$"


class Client(BaseClient):
    """
    Client to use in the Threat Vault integration. Overrides BaseClient.
    """

    def __init__(
        self, base_url: str, api_key: str, verify: bool, proxy: bool, reliability: str
    ):
        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            headers={"Content-Type": "application/json", "X-API-KEY": api_key},
        )

        self.name = "ThreatVault"
        self.reliability = reliability

    def ip_feed_get_request(self, arg: str, value: str) -> dict:    # pragma: no cover
        suffix = "ip-feed"
        return self._http_request(method="GET", url_suffix=suffix, params={arg: value})

    def ip_feed_batch_post_request(self, arg: str, value: str) -> dict:    # pragma: no cover
        suffix = "ip-feed"
        payload = json.dumps({"ipaddr": value})
        return self._http_request(method="POST", url_suffix=suffix, data=payload)

    def antivirus_signature_get_request(self, arg: str, value: str) -> dict:    # pragma: no cover

        suffix = "threats"
        return self._http_request(method="GET", url_suffix=suffix, params={arg: value})

    def release_notes_get_request(self, type_: str, version: str) -> dict:  # pragma: no cover

        suffix = "release-notes"
        return self._http_request(
            method="GET", url_suffix=suffix, params={"type": type_, "version": version}
        )

    def threat_batch_search_request(self, arg: str, value: list, type_: str) -> dict:

        params: dict[str, Union[list, str]] = {arg: value}
        if type_:
            params["type"] = type_
        params = json.dumps(params)
        suffix = "threats"
        return self._http_request(method="POST", url_suffix=suffix, data=params)

    def threat_search_request(self, args: dict) -> dict:

        suffix = "threats"
        return self._http_request(method="GET", url_suffix=suffix, params=args)

    def atp_batch_report_request(self, args: str, value: list) -> dict:

        params: dict[str, Union[list, str]] = {args: value}
        params = json.dumps(params)
        suffix = "atp/reports"
        return self._http_request(method="POST", url_suffix=suffix, data=params)

    def atp_report_pcap_request(self, args: dict) -> dict:

        suffix = "atp/reports/pcaps"

        pcap_response = self._http_request(method="GET", url_suffix=suffix, params=args, resp_type="response")

        return pcap_response


"""
HELP FUNCTIONS
"""


def reputation_type_to_hr(reputation_type: str) -> str:

    match reputation_type:
        case ReputationType.RTDNS | ReputationType.DNS:
            return reputation_type.upper()
        case ReputationType.SPYWAREC2:
            return "SpywareC2"
        case _:
            return reputation_type.capitalize()


def validate_arguments_search_command(
    cve: str | None,
    vendor: str | None,
    name: str | None,
    from_release_date: str | None,
    to_release_date: str | None,
    from_release_version: str | None,
    to_release_version: str | None,
    release_date: str | None,
    release_version: str | None,
    type_: str | None,
) -> None:

    if sum(1 for x in (cve, vendor, name) if x) > 1:
        raise ValueError(
            "Only one of the following can be used at a time: cve, vendor, name"
        )

    if sum(1 for x in (from_release_date, to_release_date) if x) == 1:
        raise ValueError(
            "When using a release date range in a query, it must be used with the following two arguments: "
            "from-release-date, to-release-date"
        )

    if sum(1 for x in (from_release_version, to_release_version) if x) == 1:
        raise ValueError(
            "When using a release version range in a query, it must be used with the following two arguments: "
            "from-release-version, to-release-version"
        )

    if release_date and release_version:
        raise ValueError(
            "There can only be one argument from the following list in the command: "
            "release-date, release-version"
        )

    if (from_release_date or from_release_version) and (
        release_date or release_version
    ):
        raise ValueError(
            "When using a release version range or a release date range in a query"
            "it is not possible to use with the following arguments: release-date, release-version"
        )

    if from_release_date and from_release_version:
        raise ValueError(
            "from-release-version and from-release-date cannot be used together."
        )

    if not any(
        (
            cve,
            vendor,
            name,
            type_,
            from_release_date,
            from_release_version,
            release_date,
            release_version,
        )
    ):
        raise ValueError(
            "One of following arguments is required: cve, vendor, signature-name, type, "
            "from-release-version, from-release-date, release-date, release-version"
        )


def parse_date(date: str = None) -> str | None:

    if not date:
        return None
    if re.match(DATE_REGEX, date):
        return date

    date_time, _ = parse_date_range(date)

    return date_time.date().strftime("%Y-%m-%d")


def pagination(
    page: Optional[int], page_size: Optional[int], limit: Optional[int]
) -> tuple[int, Optional[int]]:
    """
    The page_size and page arguments are converted so they match the offset and limit parameters of the API call.
    """

    if page and page_size:
        if page < 0:
            raise ValueError("The page number must be a positive number")
        return page * page_size, page_size

    if not page and not page_size:
        return 0, limit

    raise ValueError(
        "When using a pagination, it must be used with the following two arguments -> "
        "[page, page_size]"
    )


def resp_to_hr(response: dict, type_: str, expanded: bool = False) -> dict:

    match type_:
        case ReputationType.FILE:
            antivirus = response.get("signatures", {}).get("antivirus", ({},))[0]
            table_for_md = {
                "Status": antivirus.get("status"),
                "FileType": response.get("filetype"),
                "MD5": response.get("md5"),
                "SHA256": response.get("sha256"),
                "SHA1": response.get("sha1"),
                "Size": response.get("size"),
            }
            if expanded:
                table_for_md.update(
                    {
                        "Release": antivirus.get("release"),
                        "Creation Time": response.get("create_time"),
                        "SignatureId": antivirus.get("id"),
                        "Family": response.get("family"),
                        "Platform": response.get("platform"),
                        "Signature Name": antivirus.get("name"),
                        "Score": antivirus.get("severity"),
                        "Description": antivirus.get("description"),
                        "Wildfire verdict": response.get("wildfire_verdict"),
                    }
                )

        case ReputationType.CVE:
            table_for_md = {
                "ID": response.get("cve"),
                "Score": response.get("severity"),
                "Published": response.get("ori_release_time"),
                "Modified": response.get("latest_release_time"),
                "Description": response.get("description"),
            }

        case ReputationType.FILEFORMAT:
            table_for_md = {
                "ThreatID": response.get("id"),
                "Name": response.get("name"),
                "Description": response.get("description"),
                "Category": response.get("category"),
                "Score": response.get("severity"),
                "Default action": response.get("default_action"),
                "Vendor": response.get("vendor"),
                "Reference": response.get("reference"),
                "Status": response.get("status"),
                "Published version": response.get("ori_release_version"),
                "Latest release version": response.get("latest_release_version"),
                "Published": response.get("ori_release_time"),
                "Latest release time": response.get("latest_release_time"),
            }

        case ReputationType.VULNERABILITY:
            table_for_md = {
                "ThreatID": response.get("id"),
                "Name": response.get("name"),
                "Description": response.get("description"),
                "Category": response.get("category"),
                "Score": response.get("severity"),
                "Default action": response.get("default_action"),
                "Vendor": response.get("vendor"),
                "Reference": response.get("reference"),
                "Status": response.get("status"),
                "Published version": response.get("ori_release_version"),
                "Latest release version": response.get("latest_release_version"),
                "Published": response.get("ori_release_time"),
                "Latest release time": response.get("latest_release_time"),
                "CVE": response.get("cve"),
            }

        case ReputationType.ANTIVIRUS:
            table_for_md = {
                "ThreatID": response.get("id"),
                "Name": response.get("name"),
                "Description": response.get("description"),
                "Subtype": response.get("subtype"),
                "Score": response.get("severity"),
                "Action": response.get("action"),
                "Creation Time": response.get("create_time"),
                "Related SHA256 hashes": response.get("related_sha256_hashes"),
                "Release": response.get("release"),
            }

        case ReputationType.SPYWARE:
            table_for_md = {
                "ThreatID": response.get("id"),
                "Name": response.get("name"),
                "Description": response.get("description"),
                "Vendor": response.get("vendor"),
                "Score": response.get("severity"),
                "Default action": response.get("default_action"),
                "Details": response.get("details"),
                "Reference": response.get("reference"),
                "Status": response.get("status"),
                "Min version": response.get("min_version"),
                "Max version": response.get("max_version"),
                "CVE": response.get("cve"),
            }

        case ReputationType.RTDNS | ReputationType.DNS | ReputationType.SPYWAREC2:
            table_for_md = {
                "ThreatID": response.get("id"),
                "Name": response.get("name"),
                "Description": response.get("description"),
                "Severity": response.get("severity"),
                "Type": response.get("type"),
                "Subtype": response.get("subtype"),
                "Action": response.get("action"),
                "Creation Time": response.get("create_time"),
                "Status": response.get("status"),
                "Release": response.get("release"),
            }

        case ReputationType.RELEASE_NOTES:
            applications = response.get("release_notes", {}).get("applications", {})
            spyware = response.get("release_notes", {}).get("spyware", {})
            vulnerability = response.get("release_notes", {}).get("vulnerability", {})
            table_for_md = {
                "Release version": response.get("release_version"),
                "Content version": response.get("content_version"),
                "type": response.get("type"),
                "Notes": response.get("release_notes", {}).get("notes"),
                "New applications": applications.get("new"),
                "Modified applications": applications.get("modified"),
                "Obsoleted applications": applications.get("obsoleted"),
                "New Spyware": spyware.get("new"),
                "Modified Spyware": spyware.get("modified"),
                "Disabled Spyware": spyware.get("disabled"),
                "New Vulnerability": vulnerability.get("new")[0]
                if vulnerability.get("new")
                else None,
                "Modified Vulnerability": vulnerability.get("modified")[0]
                if vulnerability.get("modified")
                else None,
                "Disabled Vulnerability": vulnerability.get("disabled")[0]
                if vulnerability.get("disabled")
                else None,
                "Release time": response.get("release_time"),
            }

        case _:
            demisto.debug(f"Unexpected item type {type_}")
            return {}

    return table_for_md


def parse_resp_by_type(response: dict, expanded: bool = False) -> List[CommandResults]:

    command_results_list: List[CommandResults] = []
    reputation_types = (
        (ReputationType.ANTIVIRUS, HEADERS_ANTIVIRUS),
        (ReputationType.SPYWARE, HEADERS_SPYWARE),
        (ReputationType.VULNERABILITY, HEADERS_VULNERABILITY),
        (ReputationType.FILEFORMAT, HEADERS_FILEFORMAT),
        (ReputationType.DNS, HEADERS_DNS_RTDNS_SPYWAREC2),
        (ReputationType.RTDNS, HEADERS_DNS_RTDNS_SPYWAREC2),
        (ReputationType.SPYWAREC2, HEADERS_DNS_RTDNS_SPYWAREC2),
    )

    for rep_type, headers_type in reputation_types:
        if rep_type in response["data"]:
            if expanded:
                responses = response.get("data", {}).get(rep_type, [])
            else:
                responses = [response.get("data", {}).get(rep_type, ([],))[0]]

            reputation_types_readable = reputation_type_to_hr(rep_type)
            for result in responses:
                table_for_md = resp_to_hr(response=result, type_=rep_type)
                readable_output = tableToMarkdown(
                    name=f"{reputation_types_readable} Reputation: {result.get('id')}",
                    t=table_for_md,
                    headers=headers_type,
                    removeNull=True,
                )
                command_results_list.append(
                    CommandResults(
                        outputs_prefix=f"ThreatVault.{reputation_types_readable}",
                        outputs_key_field="id",
                        outputs=result
                        if expanded
                        else response.get("data", {}).get(rep_type, []),
                        readable_output=readable_output,
                    )
                )

    return command_results_list


"""
COMMANDS
"""


def ip_command(client: Client, args: dict) -> List[CommandResults]:
    """Retrieve information about the inputted IP from ThreatVault

    Args:
        client (Client): An instance of the client to call the GET commands.
        args (dict): The arguments inputted by the user.

    Returns:
        List[CommandResults]: A list of CommandResults objects to be returned to XSOAR.
    """

    def headers_transform(header):
        headers = {"ipaddr": "IP",
                   "geo": "Country",
                   "asn": "ASN",
                   "name": "Feed Name"}
        return headers[header]

    ips = argToList(args["ip"])
    command_results_list: List[CommandResults] = []
    dbot_reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(
        client.reliability
    )

    try:
        if len(ips) == 1:
            # Call single IP info
            response = client.ip_feed_get_request(arg="ipaddr", value=ips[0])

        else:
            # Call batch command
            response = client.ip_feed_batch_post_request(arg="ipaddr", value=ips)

    except DemistoException:
        raise

    if response:
        for data in response["data"]:
            ip_type = FeedIndicatorType.ip_to_indicator_type(data["ipaddr"])

            dbot_score = Common.DBotScore(
                indicator=data["ipaddr"],
                indicator_type=DBotScoreType.IP,
                integration_name=client.name,
                score=3 if data["status"] == "released" else 0,
                reliability=dbot_reliability,
            )

            ip = Common.IP(
                ip_type=ip_type,
                ip=data["ipaddr"],
                asn=data["asn"].split(" ")[0],
                as_owner=re.sub("[()]", "", data["asn"].split(" ")[1]),
                geo_country=data["geo"].split(" ")[0],
                geo_description=re.sub("[()]", "", data["geo"].split(" ")[1]),
                dbot_score=dbot_score,
            )

            readable_output = tableToMarkdown(
                name="IP Feed Information",
                t=data,
                headers=["ipaddr", "geo", "asn", "name"],
                headerTransform=headers_transform,
                removeNull=True,
            )

            command_results = CommandResults(
                readable_output=readable_output,
                outputs=data,
                outputs_prefix="ThreatVault.IP",
                indicator=ip,
            )

            command_results_list.append(command_results)

    return command_results_list


def file_command(client: Client, args: Dict) -> List[CommandResults]:
    """
    Get the reputation of a sha256 or a md5 representing an antivirus
    """
    readable_output = ""
    file_info: dict = {}
    hashes = argToList(args.get("file"))
    command_results_list: List[CommandResults] = []
    dbot_reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(
        client.reliability
    )

    for _hash in hashes:
        type_hash = get_hash_type(_hash)
        try:
            response = client.antivirus_signature_get_request(
                arg=type_hash, value=_hash
            )
        except DemistoException as err:
            if err.res is not None and err.res.status_code == 404:
                response = {}
                dbot_score = Common.DBotScore(
                    indicator=_hash,
                    indicator_type=DBotScoreType.FILE,
                    integration_name=client.name,
                    reliability=dbot_reliability,
                    score=Common.DBotScore.NONE,
                )
                file = Common.File(
                    sha256=_hash if type_hash == "sha256" else None,
                    md5=_hash if type_hash == "md5" else None,
                    dbot_score=dbot_score,
                )

                readable_output = (
                    f"Hash {_hash} antivirus reputation is unknown to Threat Vault."
                )
                file_info = {}
            else:
                raise

        if response:
            file_info = response.get("data", {}).get("fileinfo", ({},))[0]
            dbot_score = Common.DBotScore(
                indicator=_hash,
                indicator_type=DBotScoreType.FILE,
                integration_name=client.name,
                score=SCORE_TABLE_FILE[file_info.get("wildfire_verdict", "unknown")],
                reliability=dbot_reliability,
            )
            file = Common.File(
                sha256=file_info.get("sha256"),
                md5=file_info.get("md5"),
                sha1=file_info.get("sha1"),
                dbot_score=dbot_score,
            )

            table_for_md = resp_to_hr(
                response=file_info, type_="file", expanded=args.get("expanded", False)
            )

            readable_output = tableToMarkdown(
                name=f"Antivirus Reputation for hash: {_hash}",
                t=table_for_md,
                headers=HEADERS_FILE,
                removeNull=True,
            )
        else:
            file = Common.File(dbot_score=0)
            demisto.debug("No response. Initialized file variable.")

        command_results = CommandResults(
            readable_output=readable_output,
            outputs=file_info,
            outputs_prefix="ThreatVault.FileInfo",
            indicator=file,
        )

        command_results_list.append(command_results)

    return command_results_list


def cve_command(client: Client, args: Dict) -> List[CommandResults]:
    readable_output = ""
    _cve = None
    cves = argToList(args.get("cve"))
    command_results_list: List[CommandResults] = []

    for cve in cves:
        try:
            response = client.antivirus_signature_get_request(arg="cve", value=cve)
        except DemistoException as err:
            if err.res is not None and err.res.status_code == 404:
                response = {}
                readable_output = (
                    f"CVE {cve} vulnerability reputation is unknown to Threat Vault."
                )
                _cve = None
                vulnerability = None
            else:
                raise

        if response:
            vulnerability = response.get("data", {}).get("vulnerability", ({},))[0]
            _cve = Common.CVE(
                id=vulnerability.get("cve")[0],
                cvss=vulnerability.get("severity"),
                published=vulnerability.get("ori_release_time"),
                modified=vulnerability.get("latest_release_time"),
                description=vulnerability.get("description"),
            )
            table_for_md = resp_to_hr(response=vulnerability, type_="cve")
            readable_output = tableToMarkdown(
                name=f"CVE Vulnerability Reputation: {cve}",
                t=table_for_md,
                headers=HEADERS_CVE,
                removeNull=True,
            )

        command_results = CommandResults(
            readable_output=readable_output,
            outputs=vulnerability,
            outputs_prefix="ThreatVault.Vulnerability",
            indicator=_cve,
        )
        command_results_list.append(command_results)

    return command_results_list


def threat_signature_get_command(client: Client, args: Dict) -> List[CommandResults]:

    args["file"] = args.get("sha256", "")
    if md5 := args.get("md5"):
        args["file"] += f",{md5}" if args["file"] else md5
    args["expanded"] = True
    ids = argToList(args.get("signature_id"))

    if not any((ids, args["file"])):
        raise ValueError(
            "One of following arguments is required: signature_id, sha256, md5"
        )

    if ids and args["file"]:
        raise ValueError("The command cannot be run with more than one argument.")

    command_results_list: List[CommandResults] = []

    if args["file"]:
        command_results_list.extend(file_command(client=client, args=args))
        return command_results_list

    for _id in ids:
        try:
            response = client.antivirus_signature_get_request(arg="id", value=_id)
        except DemistoException as err:
            if err.res is not None and err.res.status_code == 404:
                response = {}
                readable_output = f"{_id} reputation is unknown to Threat Vault."
                command_results_list.append(
                    CommandResults(readable_output=readable_output)
                )
            else:
                raise

        if response:
            command_results_list.extend(parse_resp_by_type(response=response))

    return command_results_list


def release_note_get_command(client: Client, args: Dict) -> CommandResults:

    if not args.get("version"):
        raise ValueError("The version argument is required")

    version = args["version"]
    try:
        response = client.release_notes_get_request("content", version)
    except DemistoException as err:
        if err.res is not None and err.res.status_code == 404:
            return CommandResults(
                readable_output=f"Release note {version} was not found."
            )
        else:
            raise

    data = response.get("data", ({},))[0]
    table_for_md = resp_to_hr(response=data, type_="release_notes")
    readable_output = tableToMarkdown(
        name="Release notes:", t=table_for_md, removeNull=True
    )
    return CommandResults(
        outputs_prefix="ThreatVault.ReleaseNote",
        outputs_key_field="release_version",
        outputs=data,
        readable_output=readable_output,
    )


def threat_batch_search_command(client: Client, args: Dict) -> List[CommandResults]:

    ids = argToList(args.get("id"))
    md5 = argToList(args.get("md5"))
    sha256 = argToList(args.get("sha256"))
    names = argToList(args.get("name"))
    threat_type = args.get("type", "")

    argument_count = sum(1 for x in (ids, md5, sha256, names) if x)
    if argument_count != 1:
        raise ValueError(
            "Only one of the following can be used at a time: id, md5, sha256, name"
        )

    command_results_list: List[CommandResults] = []

    if ids or names:
        type_ = "id" if ids else "name"
        try:
            response = client.threat_batch_search_request(
                arg=type_, value=ids if ids else names, type_=threat_type
            )
        except DemistoException as err:
            if err.res is not None and err.res.status_code == 404:
                response = {}
                readable_output = f"There is no information about the {str(ids) if ids else str(names)}"
                command_results_list.append(
                    CommandResults(readable_output=readable_output)
                )
            else:
                raise

        if response:
            command_results_list.extend(parse_resp_by_type(response, True))

    elif md5 or sha256:
        dbot_reliability = DBotScoreReliability.get_dbot_score_reliability_from_str(
            client.reliability
        )
        type_ = "md5" if md5 else "sha256"
        try:
            response = client.threat_batch_search_request(
                arg=type_, value=md5 or sha256, type_=threat_type
            )
        except DemistoException as err:
            if err.res is not None and err.res.status_code == 404:
                response = {}
                readable_output = f"There is no information about the {str(md5) if md5 else str(sha256)}"
                command_results_list.append(
                    CommandResults(readable_output=readable_output)
                )
            else:
                raise

        if response:
            files_info: List[dict] = response.get("data", {}).get("fileinfo", [])
            for file_info in files_info:

                dbot_score = Common.DBotScore(
                    indicator=file_info.get("sha256"),
                    indicator_type=DBotScoreType.FILE,
                    integration_name=client.name,
                    score=SCORE_TABLE_FILE[
                        file_info.get("wildfire_verdict", "unknown")
                    ],
                    reliability=dbot_reliability,
                )
                file = Common.File(
                    sha256=file_info.get("sha256"),
                    md5=file_info.get("md5"),
                    sha1=file_info.get("sha1"),
                    dbot_score=dbot_score,
                )

                table_for_md = resp_to_hr(
                    response=file_info, type_="file", expanded=True
                )
                readable_output = tableToMarkdown(
                    name=f"File {file_info.get('sha256')}:",
                    t=table_for_md,
                    removeNull=True,
                )
                command_results_list.append(
                    CommandResults(
                        outputs_prefix="ThreatVault.FileInfo",
                        readable_output=readable_output,
                        outputs_key_field="sha256",
                        outputs=file_info,
                        indicator=file,
                    )
                )

    return command_results_list


def threat_search_command(client: Client, args: Dict) -> List[CommandResults]:

    cve = args.get("cve")
    vendor = args.get("vendor")
    name = args.get("signature-name")
    from_release_date = parse_date(args.get("from-release-date"))
    to_release_date = parse_date(args.get("to-release-date"))
    from_release_version = args.get("from-release-version")
    to_release_version = args.get("to-release-version")
    release_date = parse_date(args.get("release-date"))
    release_version = args.get("release-version")
    type_ = args.get("type")
    page = arg_to_number(args.get("page"))
    page_size = arg_to_number(args.get("page_size"))
    offset, limit = pagination(page, page_size, arg_to_number(args.get("limit", 50)))

    validate_arguments_search_command(
        cve,
        vendor,
        name,
        from_release_date,
        to_release_date,
        from_release_version,
        to_release_version,
        release_date,
        release_version,
        type_,
    )

    query = assign_params(
        cve=cve,
        vendor=vendor,
        name=name,
        fromReleaseDate=from_release_date,
        toReleaseDate=to_release_date,
        fromReleaseVersion=from_release_version,
        toRelaseVersion=to_release_version,
        releaseDate=release_date,
        releaseVersion=release_version,
        type=type_,
        offset=offset,
        limit=limit,
    )

    command_results_list: List[CommandResults] = []

    try:
        response = client.threat_search_request(args=query)
    except DemistoException as err:
        if err.res is not None and err.res.status_code == 404:
            response = {}
            readable_output = "There is no information for your search."
            command_results_list.append(CommandResults(readable_output=readable_output))
        else:
            raise

    if response:
        command_results_list.extend(parse_resp_by_type(response, True))
    return command_results_list


def atp_batch_report_command(client: Client, args: Dict) -> List[CommandResults]:  # pragma: no cover

    report_ids = argToList(args.get("report_id"))

    command_results_list: List[CommandResults] = []

    if report_ids:
        try:
            response = client.atp_batch_report_request(args='id', value=report_ids)
        except DemistoException as err:
            if err.res is not None and err.res.status_code == 404:
                response = {}
                readable_output = f"There is no information about the {str(report_ids)}"
                command_results_list.append(
                    CommandResults(readable_output=readable_output)
                )
            else:
                raise

        if response:

            report_infos: List[dict] = response.get("data", {}).get("reports", [])
            for report_info in report_infos:

                readable_output = tableToMarkdown(
                    name=f"Advanced Threat Prevention Report ID: {report_info.get('report_id')}:",
                    t=report_info,
                    removeNull=True,
                )
                command_results_list.append(
                    CommandResults(
                        outputs_prefix="ThreatVault.ATP.Report",
                        readable_output=readable_output,
                        # outputs_key_field="sha256",
                        outputs=report_info,
                    )
                )

    return command_results_list


def atp_report_pcap_command(client: Client, args: Dict) -> List[CommandResults]:  # pragma: no cover

    report_id = args.get("report_id")

    if report_id:
        query = assign_params(
            id=report_id
        )

        command_results_list: List[CommandResults] = []

        try:
            response = client.atp_report_pcap_request(args=query)
            response_data_headers = json.loads(json.dumps(dict(response.headers)))  # type: ignore
            response_content = response.content  # type: ignore

        except DemistoException as err:
            if err.res is not None and err.res.status_code == 404:
                response = {}
                readable_output = f"There is no information about the {str(report_id)}"
                command_results_list.append(
                    CommandResults(readable_output=readable_output)
                )
            else:
                raise

        # check for octet-stream response for PCAP
        if response_data_headers.get("Content-Type") == 'application/octet-stream':

            # set the pcap filename to the report_id.pcap
            pcap_name = report_id + ".pcap"

            # write the file prperties to the context
            return_results(fileResult(pcap_name, response_content))

            ec = {'ID': report_id, 'Name': pcap_name}

            readable_output = tableToMarkdown(
                name="Advanced Threat Prevention PCAP Download:",
                t=ec,
                removeNull=True,
            )
            command_results_list.append(
                CommandResults(
                    outputs_prefix="ThreatVault.ATP.PCAP",
                    readable_output=readable_output,
                    # outputs_key_field="sha256",
                    outputs=ec,
                )
            )
        else:
            return_results({
                'Type': entryTypes['note'],
                'ContentsFormat': formats['text'],
                'Contents': f'No PCAP response for ID: {str(report_id)}'
            })

    return command_results_list


"""
FETCH INCIDENT
"""


def fetch_incidents(client: Client, args: dict) -> List:
    """
    Retrieving release notes that contain all the information about vulnerabilities, antivirus, spyware, and more.
    """

    last_run = demisto.getLastRun()
    first_fetch = args.get("first_fetch", "3 Days")
    if not last_run.get("scound_fetch"):
        if first_fetch.strip().split(" ")[1].lower() not in frozenset(
            ("days", "month", "months", "year", "years")
        ):  # only these are allowed
            raise ValueError(
                "The unit of date_range is invalid. Must be days, months or years."
            )
        start_time, now = parse_date_range(first_fetch)
    else:
        _, now = parse_date_range(first_fetch)
        start_time = now

    current = start_time.date()
    now = now.date()
    incidents: List[dict] = []
    while current <= now:
        try:
            # Bringing the daily date for the first api call
            demisto.debug(f"Time for request fetch-incidents -> {current}")
            response = client.threat_search_request(
                {"releaseDate": current.strftime("%Y-%m-%d")}
            )
        except DemistoException as err:
            if err.res is not None and err.res.status_code == 404:
                current += timedelta(days=1)
                continue
            else:
                raise

        if keys_of_resp := tuple(
            {"spyware", "vulnerability", "fileformat", "antivirus"}.intersection(
                response["data"].keys()
            )
        ):

            # The version of the release notes for the second API call can be extracted
            try:
                number_version = response["data"][keys_of_resp[0]][0][
                    "latest_release_version"
                ]
            except KeyError as err:
                raise Exception(
                    f"Error parsing release note latest_release_version: {str(err)}"
                )
            # The API is called by the version number
            release = client.release_notes_get_request("content", number_version)

            # Adds source name to the incident
            release["data"][0]["Source name"] = "THREAT VAULT - RELEASE NOTES"

            # Incident organization and arrangement
            incidents.append(
                {
                    "name": f"ThreatVault Release {release['data'][0]['release_version']}",
                    "occurred": release["data"][0]["release_time"],
                    "rawJSON": json.dumps(release),
                }
            )
        current += timedelta(days=1)

    demisto.setLastRun({"scound_fetch": "true"})
    return incidents


def test_module(client: Client, *_) -> str:
    """Performs basic get request to get ip geo data.

    Args:
        client: Client object with request.

    Returns:
        string.
    """

    client.threat_search_request({"type": "ips"})
    return "ok"


def main():

    params = demisto.params()
    """PARAMS"""
    base_url = params.get("url", "") + "service/v1/"
    api_key = params.get("credentials", {}).get("password")
    verify = not params.get("insecure", False)
    proxy = params.get("proxy")
    reliability = params.get("integrationReliability", "D - Not usually reliable")

    if not DBotScoreReliability.is_valid_type(reliability):
        raise Exception(
            "Please provide a valid value for the Source Reliability parameter."
        )

    try:
        command = demisto.command()
        demisto.debug(f"Command being called is {demisto.command()}")
        client = Client(
            base_url=base_url,
            api_key=api_key,
            verify=verify,
            proxy=proxy,
            reliability=reliability,
        )

        commands = {
            "file": file_command,
            "cve": cve_command,
            "ip": ip_command,
            "threatvault-threat-signature-get": threat_signature_get_command,
            "threatvault-release-note-get": release_note_get_command,
            "threatvault-threat-batch-search": threat_batch_search_command,
            "threatvault-threat-search": threat_search_command,
            "threatvault-atp-batch-report-get": atp_batch_report_command,
            "threatvault-atp-report-pcap-get": atp_report_pcap_command,
        }

        if demisto.command() == "test-module":
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client))

        elif command == "fetch-incidents":
            incidents = fetch_incidents(client, params)
            demisto.incidents(incidents)

        elif command in commands:
            return_results(commands[command](client, demisto.args()))
        else:
            raise NotImplementedError(f'Command "{command}" was not implemented.')

    except Exception as err:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute {command} command.\nError:\n{str(err)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
