from CommonServerPython import *


VERSION = "v1.0.0"
USER_AGENT = f"ReversingLabs XSOAR Ransomware Feed {VERSION}"

MAX_HOURS_HISTORICAL = 4

ALLOWED_INDICATOR_TYPES = ("ipv4", "domain", "hash", "uri")

INDICATOR_TYPE_MAP = {
    "ipv4": FeedIndicatorType.IP,
    "domain": FeedIndicatorType.Domain,
    "hash": FeedIndicatorType.File,
    "uri": FeedIndicatorType.URL,
}


class Client(BaseClient):
    RANSOMWARE_INDICATORS_ENDPOINT = (
        "/api/public/v1/ransomware/indicators?hours={hours}&" "indicatorTypes={indicator_types}&tagFormat=dict"
    )

    def __init__(self, base_url, auth, headers, verify):
        super().__init__(base_url=base_url, auth=auth, headers=headers, verify=verify)

    def query_indicators(self, hours, indicator_types, timeout, retries):
        endpoint = self.RANSOMWARE_INDICATORS_ENDPOINT.format(
            hours=hours,
            indicator_types=indicator_types,
        )

        try:
            response = self._http_request(
                method="GET", url_suffix=endpoint, timeout=timeout, auth=self._auth, retries=retries, resp_type="json"
            )
        except Exception as e:
            return_error(f"Request towards the defined endpoint {endpoint} did not succeed. {str(e)}")

        return response


def confidence_to_score(confidence):
    if confidence >= 70:
        return 3
    elif 69 >= confidence >= 2:
        return 2
    else:
        return None


def calculate_hours_historical(hours_param):
    last_run = get_feed_last_run()

    if not last_run:
        return hours_param

    try:
        time_delta = datetime.now() - datetime.strptime(last_run.get("last_run"), "%Y-%m-%dT%H:%M:%S.%f")

        time_delta_hours_rounded = round((time_delta.seconds / 3600) + 1)

        return time_delta_hours_rounded

    except Exception:
        return 2


def return_validated_params(params):
    hours_param = params.get("hours")

    try:
        hours_param = int(hours_param)
    except ValueError:
        return_error("The First fetch time parameter must be integer.")

    hours_historical = calculate_hours_historical(hours_param)

    if hours_historical > MAX_HOURS_HISTORICAL:
        hours_historical = MAX_HOURS_HISTORICAL

    indicator_types_param = params.get("indicatorTypes")

    for indicator_type in indicator_types_param:
        if indicator_type not in ALLOWED_INDICATOR_TYPES:
            return_error(f"Selected indicator type '{indicator_type}' is not supported.")

    indicator_types_param = ",".join(indicator_types_param)

    return hours_historical, indicator_types_param


def fetch_indicators_command(client, params):
    hours_historical, indicator_types_param = return_validated_params(params)

    new_last_run = datetime.now().isoformat()

    response = client.query_indicators(
        hours=hours_historical, indicator_types=indicator_types_param, timeout=(30, 300), retries=3
    )

    tlp_color_param = params.get("tlp_color", None)

    user_tag_list = []
    user_tags_param = params.get("feedTags", None)
    if user_tags_param:
        user_tags_param = user_tags_param.split(",")
        for user_tag in user_tags_param:
            user_tag_list.append(user_tag.strip())

    data = response.get("data", [])

    indicators = []

    for rl_indicator in data:
        indicator = create_indicator_object(rl_indicator, user_tag_list, tlp_color_param)

        indicators.append(indicator)

    return indicators, new_last_run


def map_file_info(indicator, tag_list, file_info):
    if file_info:
        if isinstance(file_info, list):
            tag_list.extend(file_info)

        elif isinstance(file_info, dict):
            file_name = file_info.get("fileName")

            file_info_fields = assign_params(
                size=file_info.get("fileSize"), filetype=file_info.get("fileType"), associatedfilenames=[file_name]
            )

            indicator["fields"].update(file_info_fields)

            if file_name and isinstance(file_name, str):
                file_name_parts = file_name.split(".")

                if len(file_name_parts) > 1:
                    file_extension = file_name_parts[-1]
                    indicator["fields"]["fileextension"] = file_extension


def create_indicator_object(rl_indicator, user_tag_list, tlp_color_param):
    last_update = rl_indicator.get("lastUpdate", None)
    last_seen = datetime.strptime(last_update, "%Y-%m-%dT%H:%M:%SZ") if last_update else datetime.now()
    last_seen = last_seen.strftime("%Y-%m-%dT%H:%M:%S+00:00")
    indicator_type = rl_indicator.get("indicatorType").lower()

    indicator = {
        "value": rl_indicator.get("indicatorValue"),
        "type": INDICATOR_TYPE_MAP.get(indicator_type),
        "rawJSON": rl_indicator,
        "fields": {"lastseenbysource": last_seen},
        "score": confidence_to_score(rl_indicator.get("confidence", 0)),
    }

    indicator_tags = rl_indicator.get("indicatorTags")

    if not indicator_tags:
        return indicator

    tag_list = []

    mitre = indicator_tags.get("mitre")
    if mitre:
        tag_list.extend(mitre)

    lifecycle_stage = indicator_tags.get("lifecycleStage")
    if lifecycle_stage:
        tag_list.append(lifecycle_stage)

    source = indicator_tags.get("source")
    if source:
        tag_list.append(source)

    additional_fields = assign_params(
        malwaretypes=indicator_tags.get("malwareType"),
        malwarefamily=indicator_tags.get("malwareFamilyName"),
        trafficlightprotocol=tlp_color_param,
    )

    indicator["fields"].update(additional_fields)

    if indicator_type == "hash":
        hashes = rl_indicator.get("hash")
        if hashes:
            hash_fields = assign_params(sha1=hashes.get("sha1"), sha256=hashes.get("sha256"), md5=hashes.get("md5"))

            indicator["fields"].update(hash_fields)

        map_file_info(indicator, tag_list, indicator_tags.get("fileInfo"))

    elif indicator_type in ("ipv4", "uri", "domain"):
        port = indicator_tags.get("port")
        if port:
            indicator["fields"]["port"] = port

        protocol = indicator_tags.get("Protocol")
        if protocol:
            tag_list.extend(protocol)

        if indicator_type == "ipv4":
            asn = indicator_tags.get("asn")
            if asn:
                indicator["fields"]["asn"] = asn

    tag_list.extend(user_tag_list)

    if len(tag_list) > 0:
        indicator["fields"]["tags"] = tag_list

    return indicator


def get_indicators_command(client):
    hours_arg = demisto.args().get("hours_back", 2)

    try:
        hours_arg = int(hours_arg)

    except ValueError:
        return_error("The hours_back argument must be a whole number.")

    if hours_arg > MAX_HOURS_HISTORICAL:
        hours_arg = MAX_HOURS_HISTORICAL

    indicator_types_arg = demisto.args().get("indicator_types", "ipv4,domain,hash,uri").replace(" ", "")

    for indicator_type in indicator_types_arg.split(","):
        if indicator_type not in ALLOWED_INDICATOR_TYPES:
            return_error(f"Selected indicator type '{indicator_type}' is not supported.")

    limit = int(demisto.args().get("limit", 50))

    response = client.query_indicators(hours=hours_arg, indicator_types=indicator_types_arg, timeout=(30, 300), retries=3)

    indicator_list = response.get("data", [])[:limit]

    readable_output = format_readable_output(response, indicator_list)

    command_result = CommandResults(
        readable_output=readable_output,
        raw_response=response,
        outputs_prefix="ReversingLabs",
        outputs={"indicators": indicator_list},
    )

    return command_result


def format_readable_output(response, indicator_list):
    indicator_types = response.get("request").get("indicatorTypes", [])
    hours = response.get("request").get("hours", "")

    markdown = f"""## ReversingLabs Ransomware and Related Tools Feed\n **Indicator types**: {', '.join(indicator_types)}
    **Hours**: {hours}
    """

    indicator_table = tableToMarkdown(
        name="Indicators",
        t=indicator_list,
        headers=[
            "indicatorValue",
            "indicatorType",
            "daysValid",
            "confidence",
            "rating",
            "indicatorTags",
            "lastUpdate",
            "deleted",
            "hash",
        ],
        headerTransform=pascalToSpace,
    )

    markdown = f"{markdown}\n{indicator_table}"

    return markdown


def test_module_command(client, params):
    hours_param, indicator_types_param = return_validated_params(params)

    client.query_indicators(hours=hours_param, indicator_types=indicator_types_param, timeout=(30, 300), retries=1)

    return "ok"


def main():
    params = demisto.params()

    host = params.get("host")
    username = params.get("credentials", {}).get("identifier")
    password = params.get("credentials", {}).get("password")
    verify = params.get("insecure")

    command = demisto.command()

    demisto.debug(f"Command being called is {command}")

    try:
        client = Client(base_url=host, verify=verify, auth=(username, password), headers={"User-Agent": USER_AGENT})

        if command == "test-module":
            result = test_module_command(client, params)

            return_results(result)

        elif command == "reversinglabs-get-indicators":
            command_result = get_indicators_command(client)

            return_results(command_result)

        elif command == "fetch-indicators":
            indicators, new_last_run = fetch_indicators_command(client, params)

            for indicator_batch in batch(indicators, 200):
                demisto.createIndicators(indicator_batch)

            set_feed_last_run({"last_run": new_last_run})

        else:
            raise NotImplementedError(f"Command {command} is not implemented.")

    except Exception as e:
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
