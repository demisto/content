import json
from datetime import UTC, datetime, timedelta

from anyrun import RunTimeException
from anyrun.connectors import SandboxConnector
from anyrun.connectors.sandbox.base_connector import BaseSandboxConnector
from anyrun.connectors.sandbox.operation_systems import (
    AndroidConnector,
    LinuxConnector,
    WindowsConnector,
)

import demistomock as demisto
from CommonServerPython import *

VERSION = "PA-XSOAR:2.5.0"

SCORE_TO_VERDICT = {0: "Unknown", 1: "Suspicious", 2: "Malicious"}
XDR_REPUTATION = {0: "UNKNOWN", 1: "SUSPICIOUS", 2: "BAD"}
XDR_SEVERITY = {0: "INFO", 1: "MEDIUM", 2: "HIGH"}

SCORE_BY_REPUTATION = {
    0: Common.DBotScore.NONE,
    1: Common.DBotScore.SUSPICIOUS,
    2: Common.DBotScore.BAD,
}

ANYRUN_TO_SOAR_INDICATOR = {
    "ip": "IP",
    "url": "URL",
    "domain": "Domain",
    "md5": "File MD5",
    "sha1": "File SHA-1",
    "sha256": "File SHA-256",
}

ANYRUN_TO_XDR_INDICATOR = {
    "ip": "IP",
    "url": "URL",
    "domain": "DOMAIN_NAME",
    "md5": "HASH",
    "sha1": "HASH",
    "sha256": "HASH",
}

XDR_INDICATOR_CLASS = {
    "IP": "IP",
    "URL": "URL",
    "DOMAIN_NAME": "Domain",
    "HASH": "Malware",
}

DEFAULT_ROOT_URL = "any.run"
IOC_EXPIRATION_DAYS = 30


def test_module(params: dict) -> str:  # pragma: no cover
    """Performs ANY.RUN API call to verify integration is operational"""
    try:
        with BaseSandboxConnector(
            get_authentication(params),
            trust_env=argToBoolean(params.get("proxy", False)),
            root_url=params.get("root_url") or DEFAULT_ROOT_URL,
        ) as connector:
            connector.check_authorization()
            return "ok"
    except RunTimeException as exception:
        return str(exception)


def get_authentication(params: dict) -> str:
    """
    Builds API verification data using demisto params

    :param params: Demisto params
    :return: API-KEY verification string
    """
    return f"API-KEY {params.get('credentials', {}).get('password')}"


def get_file_content(args: dict) -> dict:  # pragma: no cover
    entry_id = args.pop("file")
    file_obj = demisto.getFilePath(entry_id)

    filepath = file_obj["path"]
    with open(filepath, "rb") as file:
        args["file_content"] = file.read()

    args["filename"] = file_obj["name"]
    return args


def build_context_path(analysis_type: str, connector: WindowsConnector | LinuxConnector | AndroidConnector) -> str | None:
    if analysis_type == "file":
        if isinstance(connector, WindowsConnector):
            return "ANYRUN_DetonateFileWindows.TaskID"
        elif isinstance(connector, LinuxConnector):
            return "ANYRUN_DetonateFileLinux.TaskID"
        elif isinstance(connector, AndroidConnector):
            return "ANYRUN_DetonateFileAndroid.TaskID"
        return None
    elif analysis_type == "url":
        if isinstance(connector, WindowsConnector):
            return "ANYRUN_DetonateUrlWindows.TaskID"
        elif isinstance(connector, LinuxConnector):
            return "ANYRUN_DetonateUrlLinux.TaskID"
        elif isinstance(connector, AndroidConnector):
            return "ANYRUN_DetonateUrlAndroid.TaskID"
        return None
    return None


def start_analyse(
    params: dict,
    args: dict,
    analysis_type: str,
    connector: WindowsConnector | LinuxConnector | AndroidConnector,
) -> None:  # pragma: no cover
    """
    Process Sandbox analysis

    :param params: Demisto params
    :param args: Demisto args
    :param analysis_type: ANY.RUN Sandbox submission type
    :param connector: ANY.RUN connector instance
    :return: Task uuid
    """
    if analysis_type == "file":
        args = get_file_content(args)
        task_uuid = connector.run_file_analysis(**args)
    else:
        task_uuid = connector.run_url_analysis(**args)

    root_url = params.get("root_url") or DEFAULT_ROOT_URL

    return_results(
        [
            CommandResults(
                outputs_prefix="ANYRUN.SandboxURL",
                outputs=f"Link to the interactive analysis: https://app.{root_url}/tasks/{task_uuid}",
                ignore_auto_extract=True,
            ),
            CommandResults(
                outputs_prefix=build_context_path(analysis_type, connector),
                outputs=task_uuid,
                ignore_auto_extract=True,
            ),
        ]
    )


def detonate_entity_windows(params: dict, args: dict, analysis_type: str) -> None:  # pragma: no cover
    with SandboxConnector.windows(
        get_authentication(params),
        integration=VERSION,
        trust_env=argToBoolean(params.get("proxy", False)),
        verify_ssl=not argToBoolean(params.get("insecure", False)),
        root_url=params.get("root_url") or DEFAULT_ROOT_URL,
    ) as connector:
        start_analyse(params, args, analysis_type, connector)


def detonate_entity_linux(params: dict, args: dict, analysis_type: str) -> None:  # pragma: no cover
    with SandboxConnector.linux(
        get_authentication(params),
        integration=VERSION,
        trust_env=argToBoolean(params.get("proxy", False)),
        verify_ssl=not argToBoolean(params.get("insecure", False)),
        root_url=params.get("root_url") or DEFAULT_ROOT_URL,
    ) as connector:
        start_analyse(params, args, analysis_type, connector)


def detonate_entity_android(params: dict, args: dict, analysis_type: str) -> None:  # pragma: no cover
    with SandboxConnector.android(
        get_authentication(params),
        integration=VERSION,
        trust_env=argToBoolean(params.get("proxy", False)),
        verify_ssl=not argToBoolean(params.get("insecure", False)),
        root_url=params.get("root_url") or DEFAULT_ROOT_URL,
    ) as connector:
        start_analyse(params, args, analysis_type, connector)


def detonate_file_windows(params: dict, args: dict) -> None:  # pragma: no cover
    detonate_entity_windows(params, args, "file")


def detonate_url_windows(params: dict, args: dict) -> None:  # pragma: no cover
    detonate_entity_windows(params, args, "url")


def detonate_file_linux(params: dict, args: dict) -> None:  # pragma: no cover
    detonate_entity_linux(params, args, "file")


def detonate_url_linux(params: dict, args: dict) -> None:  # pragma: no cover
    detonate_entity_linux(params, args, "url")


def detonate_file_android(params: dict, args: dict) -> None:  # pragma: no cover
    detonate_entity_android(params, args, "file")


def detonate_url_android(params: dict, args: dict) -> None:  # pragma: no cover
    detonate_entity_android(params, args, "url")


def delete_task(params: dict, args: dict) -> None:  # pragma: no cover
    task_uuid = args.get("task_uuid")

    with SandboxConnector.windows(
        get_authentication(params),
        integration=VERSION,
        trust_env=argToBoolean(params.get("proxy", False)),
        verify_ssl=not params.get("insecure"),
        root_url=params.get("root_url") or DEFAULT_ROOT_URL,
    ) as connector:
        connector.delete_task(task_uuid)

    return_results(f"Task {task_uuid} successfully deleted")


def download_analysis_sample(params: dict, args: dict, download_type: str) -> None:  # pragma: no cover
    task_uuid = args.get("task_uuid")

    with SandboxConnector.windows(
        get_authentication(params),
        integration=VERSION,
        trust_env=argToBoolean(params.get("proxy", False)),
        verify_ssl=not params.get("insecure"),
        root_url=params.get("root_url") or DEFAULT_ROOT_URL,
    ) as connector:
        if download_type == "pcap":
            return_results(fileResult(f"{task_uuid}_traffic_dump.pcap", connector.download_pcap(task_uuid)))
        else:
            return_results(fileResult(f"{task_uuid}_sample.zip", connector.download_file_sample(task_uuid)))


def get_analysis_verdict(params: dict, args: dict) -> None:  # pragma: no cover
    task_uuid = args.get("task_uuid")

    with SandboxConnector.windows(
        get_authentication(params),
        integration=VERSION,
        trust_env=argToBoolean(params.get("proxy", False)),
        verify_ssl=not params.get("insecure"),
        root_url=params.get("root_url") or DEFAULT_ROOT_URL,
    ) as connector:
        for _ in connector.get_task_status(task_uuid):
            pass

        verdict = connector.get_analysis_verdict(task_uuid)

        return_results(
            CommandResults(
                outputs_prefix="ANYRUN.SandboxAnalysisReportVerdict",
                outputs=verdict,
                ignore_auto_extract=True,
            )
        )


def get_user_limits(params: dict) -> None:  # pragma: no cover
    with SandboxConnector.windows(
        get_authentication(params),
        integration=VERSION,
        trust_env=argToBoolean(params.get("proxy", False)),
        verify_ssl=not params.get("insecure"),
        root_url=params.get("root_url") or DEFAULT_ROOT_URL,
    ) as connector:
        user_limits = connector.get_user_limits()

    return_results(
        CommandResults(
            outputs_prefix="ANYRUN.SandboxLimits",
            outputs=user_limits,
            ignore_auto_extract=True,
        )
    )


def get_analysis_history(params: dict, args: dict) -> None:  # pragma: no cover
    with SandboxConnector.windows(
        get_authentication(params),
        integration=VERSION,
        trust_env=argToBoolean(params.get("proxy", False)),
        verify_ssl=not params.get("insecure"),
        root_url=params.get("root_url") or DEFAULT_ROOT_URL,
    ) as connector:
        analysis_history = connector.get_analysis_history(**args)

    return_results(
        CommandResults(
            outputs_prefix="ANYRUN.SandboxHistory",
            outputs=analysis_history,
            ignore_auto_extract=True,
        )
    )


def create_indicators(report: dict, task_uuid: str, root_url: str) -> None:  # pragma: no cover
    """
    Excludes IOCs from the analysis report. Sends them to Threat Intel

    :param report: Analysis report
    :param task_uuid: ANY.RUN task UUID
    :return XDR IOCDetails, readable output, comma-separated IOC values
    """
    output: list[dict[str, str]] = []
    indicators: list[dict] = []
    ioc_details: list[dict] = []
    ioc_values: list[str] = []

    expiration_date = int((datetime.now(UTC) + timedelta(days=IOC_EXPIRATION_DAYS)).timestamp() * 1000)

    for indicator in report:
        reputation = indicator.get("reputation")
        indicator_value = indicator.get("ioc")
        anyrun_indicator_type = indicator.get("type")
        xsoar_indicator_type = ANYRUN_TO_SOAR_INDICATOR.get(anyrun_indicator_type)
        verdict = SCORE_TO_VERDICT.get(reputation)
        score = SCORE_BY_REPUTATION.get(reputation)

        xdr_indicator_type = ANYRUN_TO_XDR_INDICATOR.get(anyrun_indicator_type, "")
        xdr_severity = XDR_SEVERITY.get(reputation, "HIGH")
        xdr_reputation = XDR_REPUTATION.get(reputation, "UNKNOWN")
        _xdr_indicator_class = XDR_INDICATOR_CLASS.get(xdr_indicator_type)

        if reputation is None or not indicator_value or not xsoar_indicator_type or score is None or verdict is None:
            continue

        indicators.append(
            {
                "type": xsoar_indicator_type,
                "value": indicator_value,
                "score": score,
                "fields": {
                    "vendor": "ANY.RUN",
                    "service": "ANY.RUN Cloud Sandbox",
                    "description": f"https://app.{root_url}/tasks/{task_uuid}",
                },
            }
        )

        output.append(
            {
                "type": xsoar_indicator_type,
                "value": indicator_value,
                "verdict": verdict,
            }
        )

        ioc_values.append(indicator_value)

        if not xdr_indicator_type or not _xdr_indicator_class:
            continue

        ioc_object = {
            "indicator": indicator_value,
            "type": xdr_indicator_type,
            "severity": xdr_severity,
            "expiration_date": expiration_date,
            "comment": f"ANY.RUN Cloud Sandbox | https://app.{root_url}/tasks/{task_uuid}",
            "reputation": xdr_reputation,
            "reliability": "A - Completely reliable",
            "class": _xdr_indicator_class,
            "vendors": [
                {
                    "vendor_name": "ANY.RUN",
                    "reputation": "GOOD",
                    "reliability": "A - Completely reliable",
                }
            ],
        }

        ioc_details.append(
            {
                "ioc_object": json.dumps(ioc_object),
            }
        )

    if indicators:
        demisto.createIndicators(indicators)

    readable_output = tableToMarkdown(
        "Indicators from ANY.RUN Cloud Sandbox",
        output,
        headers=["type", "value", "verdict"],
        headerTransform=string_to_table_header,
    )

    ioc_values = ",".join(ioc_values)

    return ioc_details, readable_output, ioc_values


def get_analysis_report(params: dict, args: dict) -> None:  # pragma: no cover
    task_uuid = args.get("task_uuid", "")
    report_format = args.get("report_format", "summary")
    root_url = params.get("root_url") or DEFAULT_ROOT_URL

    with SandboxConnector.windows(
        get_authentication(params),
        integration=VERSION,
        trust_env=argToBoolean(params.get("proxy", False)),
        verify_ssl=not params.get("insecure"),
        root_url=root_url,
    ) as connector:
        if report_format == "summary":
            report_format = "json"

        report = connector.get_analysis_report(task_uuid, report_format=report_format)

        if report_format == "html":
            return_results(fileResult(f"anyrun_report_{task_uuid}.html", report))
        elif report_format == "json":
            return_results(fileResult(f"anyrun_report_{task_uuid}.json", json.dumps(report)))
        elif report_format == "ioc" and report:
            ioc_details, readable_output, ioc_values = create_indicators(report, task_uuid, root_url)

            return_results(
                CommandResults(
                    readable_output=readable_output,
                    outputs_prefix="ANYRUN",
                    outputs={
                        "IOCDetails": ioc_details,
                    },
                    ignore_auto_extract=True,
                )
            )

            return_results(
                CommandResults(
                    readable_output=ioc_values,
                    outputs_prefix="ANYRUN.IOCs",
                    outputs=ioc_values,
                    ignore_auto_extract=True,
                )
            )


def main():  # pragma: no cover
    """Main Execution block"""
    params = demisto.params()
    args = demisto.args()

    if params.get("proxy"):
        handle_proxy()

    try:
        if demisto.command() == "anyrun-delete-task":
            delete_task(params, args)
        elif demisto.command() == "anyrun-download-analysis-pcap":
            download_analysis_sample(params, args, "pcap")
        elif demisto.command() == "anyrun-download-analysis-sample":
            download_analysis_sample(params, args, "file")
        elif demisto.command() == "anyrun-get-analysis-verdict":
            get_analysis_verdict(params, args)
        elif demisto.command() == "anyrun-get-user-limits":
            get_user_limits(params)
        elif demisto.command() == "anyrun-get-analysis-history":
            get_analysis_history(params, args)
        elif demisto.command() == "anyrun-detonate-file-windows":
            detonate_file_windows(params, args)
        elif demisto.command() == "anyrun-detonate-url-windows":
            detonate_url_windows(params, args)
        elif demisto.command() == "anyrun-detonate-file-linux":
            detonate_file_linux(params, args)
        elif demisto.command() == "anyrun-detonate-url-linux":
            detonate_url_linux(params, args)
        elif demisto.command() == "anyrun-detonate-file-android":
            detonate_file_android(params, args)
        elif demisto.command() == "anyrun-detonate-url-android":
            args.pop("obj_ext_browser", None)
            detonate_url_android(params, args)
        elif demisto.command() == "anyrun-get-analysis-report":
            get_analysis_report(params, args)
        elif demisto.command() == "test-module":
            result = test_module(params)
            return_results(result)
        else:
            raise NotImplementedError(f"Command {demisto.command()} is not implemented")
    except RunTimeException as exception:
        return_error(exception.description, error=str(exception.json))
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{str(e)}", error=traceback.format_exc())


if __name__ in ["__main__", "builtin", "builtins"]:
    main()
