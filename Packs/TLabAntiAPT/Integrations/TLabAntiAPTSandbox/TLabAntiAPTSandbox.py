"""tLab Anti-APT Sandbox integration for Cortex XSOAR.

Submits files and URLs for analysis, waits for a verdict and pulls the
resulting reports and artifacts into the war room.
"""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa: F401

from TLabAntiAPTApiModule import *  # noqa: F401,E402

OUTPUT_ANALYSIS = "TLabAntiAPT.Analysis"
OUTPUT_SUBMISSION = "TLabAntiAPT.Submission"
OUTPUT_REPORT = "TLabAntiAPT.Report"
OUTPUT_THREAT = "TLabAntiAPT.ThreatIndicator"
OUTPUT_ATTACK = "TLabAntiAPT.AttackMatrix"
OUTPUT_PRESET = "TLabAntiAPT.EnvPreset"
OUTPUT_SOURCE = "TLabAntiAPT.Source"

# Polling defaults. The blocking fallback used on servers below 6.2.0 holds an
# engine worker, so it is capped far lower than the scheduled path.
DEFAULT_INTERVAL = 30
DEFAULT_TIMEOUT = 1800
BLOCKING_TIMEOUT_CAP = 600


# --------------------------------------------------------------------------
# Output shaping
# --------------------------------------------------------------------------
def analysis_outputs(report: dict, params: dict, access_code: str = "", request_status: str | None = "") -> dict:
    """Normalize a report into the TLabAntiAPT.Analysis context object."""
    file_dto = report.get("file") or {}
    score, score_present = score_value(report)
    verdict = canonical_verdict(
        report,
        suspicious_from=float(params.get("score_threshold_suspicious") or DEFAULT_SUSPICIOUS_FROM),
        malicious_from=float(params.get("score_threshold_malicious") or DEFAULT_MALICIOUS_FROM),
        early_verdict=argToBoolean(params.get("early_verdict") or False),
    )
    classifier = report.get("malwareClassifierResult") or {}

    outputs = {
        "AccessCode": access_code or None,
        "AnalysisRequestId": report.get("analysisRequestId"),
        "AnalysisRequestStatus": request_status or None,
        "SampleReportId": report.get("sampleReportId"),
        "SampleReportType": report.get("sampleReportType"),
        "Completeness": report.get("sampleReportCompleteness"),
        "Score": score if score_present else None,
        "MaxScore": report.get("maxSampleReportScore"),
        # Both raw enumerations are kept: an analyst must be able to see what
        # the server actually said, not only our canonical value.
        "ScoreLevel": report.get("verdict"),
        # Set by hand in tLab; absent while nobody has set it.
        "FileVerdict": stored_file_verdict(file_dto.get("fileVerdict")),
        "Verdict": verdict,
        "DBotScore": verdict_to_dbot_score(verdict),
        "Whitelisted": bool(report.get("whitelisted")),
        "DetectedByAv": bool((report.get("avReportSummary") or {}).get("detected")),
        "UploadedFilename": report.get("uploadedFilename"),
        "CreateTime": epoch_to_iso(report.get("createTime")),
        "UpdateTime": epoch_to_iso(report.get("updateTime")),
        "DynReportId": (report.get("dynReportSummary") or {}).get("dynReportId"),
        "StatReportId": (report.get("statReportSummary") or {}).get("staticAnalysisReportId"),
        "ParentReportId": report.get("parentReportId"),
        "Tags": report.get("tags") or [],
        "ReportUrl": report_url(params, report.get("sampleReportId")),
        "File": {
            "HashSha256": file_dto.get("hashSha256"),
            "HashSha1": file_dto.get("hashSha1"),
            "HashMd5": file_dto.get("hashMd5"),
            "Size": file_dto.get("size"),
            "FileType": file_dto.get("fileType"),
            "MimeType": file_dto.get("mimeType"),
            "InferredExtension": file_dto.get("inferredExtension"),
            "UploadedExtension": file_dto.get("uploadedExtension"),
            "FileVerdict": stored_file_verdict(file_dto.get("fileVerdict")),
            "Signed": file_dto.get("signed"),
        },
    }
    if classifier:
        outputs["MalwareClassifier"] = {
            "PrimaryType": classifier.get("primaryType"),
            "Confidence": classifier.get("confidence"),
            "MultiStage": classifier.get("multiStage"),
            "SecondaryTypes": classifier.get("secondaryTypes") or [],
            "KeyIndicators": classifier.get("keyIndicators") or [],
        }

    source = report.get("source") or {}
    if source:
        outputs["Source"] = {
            "SourceId": source.get("sourceId"),
            # Serialized through @JsonValue, so this is the display code
            # ("Cortex XSOAR"), never the enum name.
            "Type": source.get("sourceType"),
            "Uid": source.get("sourceUid"),
        }

    requested, not_run = requested_but_not_run(report)
    if not_run:
        # The server mutates the request: AV_ANALYSIS is always added and
        # DYN_ANALYSIS is stripped on a LITE license or the mailer preset. A
        # request asking for dynamic analysis can silently come back static
        # only, so the difference is surfaced rather than hidden.
        outputs["RequestedButNotRun"] = sorted(not_run)
    outputs["AnalyzedReportTypes"] = sorted(requested)
    return remove_empty_elements(outputs)


def requested_but_not_run(report: dict) -> tuple[set, set]:
    requested = {str(x).upper() for x in (report.get("analysisTypes") or []) if x}
    completed = {str(x).upper() for x in (report.get("completedAnalyzes") or []) if x}
    return requested, requested - completed


def report_url(params: dict, sample_report_id: Any) -> str | None:
    base = (params.get("report_url_base") or "").rstrip("/")
    if not base or not sample_report_id:
        return None
    return f"{base}/reports/{sample_report_id}"


def build_file_indicator(outputs: dict, reliability: str) -> Common.File | None:
    """Attach a DBotScore so stock enrichment playbooks keep working."""
    file_part = outputs.get("File") or {}
    sha256 = file_part.get("HashSha256")
    if not sha256:
        return None
    dbot = Common.DBotScore(
        indicator=sha256,
        indicator_type=DBotScoreType.FILE,
        integration_name="tLab Anti-APT",
        score=outputs.get("DBotScore", Common.DBotScore.NONE),
        malicious_description=f"tLab Anti-APT verdict: {outputs.get('Verdict')}",
        reliability=reliability,
    )
    return Common.File(
        dbot_score=dbot,
        md5=file_part.get("HashMd5"),
        sha1=file_part.get("HashSha1"),
        sha256=sha256,
        name=outputs.get("UploadedFilename"),
        size=file_part.get("Size"),
        file_type=file_part.get("FileType"),
        extension=file_part.get("InferredExtension"),
    )


def analysis_readable(outputs: dict) -> str:
    row = {
        "Report ID": outputs.get("SampleReportId"),
        "Verdict": outputs.get("Verdict"),
        "Score": outputs.get("Score"),
        "Completeness": outputs.get("Completeness"),
        "File": outputs.get("UploadedFilename"),
        "SHA256": (outputs.get("File") or {}).get("HashSha256"),
        "Malware family": (outputs.get("MalwareClassifier") or {}).get("PrimaryType"),
        "Detected by AV": outputs.get("DetectedByAv"),
    }
    md = tableToMarkdown("tLab Anti-APT analysis", row, removeNull=True)
    if outputs.get("RequestedButNotRun"):
        md += (
            "\n**Note:** the server did not run "
            f"{', '.join(outputs['RequestedButNotRun'])}. This happens on a LITE license or with the "
            "`mailer` preset, where dynamic analysis is removed from the request.\n"
        )
    if outputs.get("ReportUrl"):
        md += f"\n[Open the full report in tLab Anti-APT]({outputs['ReportUrl']})\n"
    return md


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------
# tLab stores the uid in sources.source_uid VARCHAR(45). A longer value does
# not fail the submit: the server logs the truncation error and runs the
# analysis without a source, so the limit is enforced here.
SOURCE_UID_MAX_LEN = 45


def source_uid(params: dict) -> str:
    """Return the uid this XSOAR is known by on the tLab side.

    A configured value is sent as is and must fit the column. The default is
    the XSOAR license ID (CUID<64 hex>CUID, 72 characters) cut to the column
    size: its start stays readable against Settings > About > License ID, and
    41 hex digits still tell XSOAR servers apart.
    """
    configured = (params.get("source_uid") or "").strip()
    if configured:
        if len(configured) > SOURCE_UID_MAX_LEN:
            raise DemistoException(
                f"Source UID is {len(configured)} characters long; tLab Anti-APT accepts at most "
                f"{SOURCE_UID_MAX_LEN}. Shorten it or leave it empty to use the XSOAR license ID."
            )
        return configured
    return (demisto.getLicenseID() or "")[:SOURCE_UID_MAX_LEN]


def test_module_command(client: TLabClient, params: dict) -> str:
    """Probe connectivity and the role, because a wrong role fails silently later."""
    source_uid(params)
    try:
        identity = client.whoami()
    except DemistoException as exc:
        raise DemistoException(f"Could not reach the tLab Anti-APT API. {exc}") from exc

    role = str(identity.get("userRole") or "").lower()
    login = identity.get("userLogin") or identity.get("login") or "unknown"
    if role and role not in ("admin", "developer"):
        # Not fatal for this integration: submission and public polling work
        # with a lower role. Artifact endpoints will not. XSOAR accepts only an
        # exact "ok" as a passed test, so the warning goes to the log.
        demisto.info(
            f"tLab Anti-APT: connected as {login} with role '{role}'. Report artifacts (PCAP, memory dump, "
            "dropped files, extra logs) require the admin or developer role and will return 403."
        )
    # XSOAR treats any other string — even "ok - …" — as a failed test.
    return "ok"


def submit_settings_from_args(args: dict, params: dict) -> SubmitSettings:
    analysis_types = argToList(args.get("analysis_types") or params.get("analysis_types")) or None
    properties = {}
    raw_properties = args.get("properties")
    if raw_properties:
        properties = json.loads(raw_properties) if isinstance(raw_properties, str) else dict(raw_properties)
    # Provenance: lets an analyst pivot from a tLab report back to the incident.
    incident = demisto.incident() or {}
    if incident.get("id"):
        properties.setdefault("xsoar_incident_id", str(incident["id"]))

    research_time = arg_to_number(args.get("research_time") or params.get("research_time") or 120)
    return SubmitSettings(
        analysis_types=analysis_types,
        analysis_priority=args.get("analysis_priority") or params.get("analysis_priority") or "LOW",
        research_time=research_time if research_time is not None else 120,
        env_preset=args.get("env_preset") or params.get("env_preset") or "",
        user_preset=argToBoolean(args.get("user_preset") or params.get("user_preset") or False),
        enable_network=argToBoolean(args.get("enable_network") or params.get("enable_network") or False),
        create_dump=argToBoolean(args.get("create_dump") or params.get("create_dump") or False),
        enable_acceleration=argToBoolean(args.get("enable_acceleration") or params.get("enable_acceleration") or False),
        enable_antievasion=argToBoolean(args.get("enable_antievasion") or params.get("enable_antievasion") or False),
        use_original_filename=argToBoolean(args.get("use_original_filename") or params.get("use_original_filename") or True),
        command_line_args=args.get("command_line_args") or "",
        uas_script=args.get("uas_script") or "",
        extract_archive=argToBoolean(args.get("extract_archive") or params.get("extract_archive") or True),
        include_archive_siblings=argToBoolean(
            args.get("include_archive_siblings") or params.get("include_archive_siblings") or True
        ),
        archive_password=args.get("archive_password") or "",
        ignore_whitelist=argToBoolean(args.get("ignore_whitelist") or params.get("ignore_whitelist") or False),
        static_prefilter=argToBoolean(args.get("static_prefilter") or params.get("static_prefilter") or False),
        public_access=argToBoolean(args.get("public_access") or params.get("public_access") or False),
        main_filename=args.get("main_filename") or "",
        tags=argToList(args.get("tags")),
        properties=properties,
        source_type=params.get("source_type") or SOURCE_TYPE_NAME,
        source_uid=source_uid(params),
    )


def submission_outputs(response: dict, submitted: str = "") -> dict:
    rejection = response.get("rejectionCode")
    return remove_empty_elements(
        {
            "AnalysisRequestId": response.get("analysisRequestId"),
            "AnalysisRequestStatus": response.get("analysisRequestStatus"),
            "AccessCode": response.get("accessCode"),
            "RejectionCode": rejection,
            "RejectionReason": describe_rejection(rejection) if rejection else None,
            "Whitelisted": bool(response.get("whitelisted")),
            "Submitted": submitted or None,
        }
    )


def submit_file_command(client: TLabClient, args: dict, params: dict) -> CommandResults:
    entry_id = args.get("entry_id")
    if not entry_id:
        raise DemistoException("entry_id is required: it identifies the war room file to submit.")
    file_info = demisto.getFilePath(entry_id)
    file_name = args.get("file_name") or file_info.get("name")

    additional = []
    for extra_id in argToList(args.get("additional_files_entry_ids")):
        extra = demisto.getFilePath(extra_id)
        additional.append({"path": extra["path"], "name": extra["name"]})

    settings = submit_settings_from_args(args, params)
    if not settings.main_filename:
        settings.main_filename = file_name

    response = client.submit("file", settings, file_path=file_info["path"], file_name=file_name, additional_files=additional)
    outputs = submission_outputs(response, submitted=file_name)
    return CommandResults(
        outputs_prefix=OUTPUT_SUBMISSION,
        outputs_key_field="AccessCode",
        outputs=outputs,
        raw_response=response,
        readable_output=tableToMarkdown(f"Submitted {file_name} to tLab Anti-APT", outputs, removeNull=True),
    )


def submit_url_command(client: TLabClient, args: dict, params: dict) -> CommandResults:
    url = args.get("url")
    if not url:
        raise DemistoException("url is required.")
    settings = submit_settings_from_args(args, params)
    response = client.submit("url", settings, url=url)
    outputs = submission_outputs(response, submitted=url)
    return CommandResults(
        outputs_prefix=OUTPUT_SUBMISSION,
        outputs_key_field="AccessCode",
        outputs=outputs,
        raw_response=response,
        readable_output=tableToMarkdown(f"Submitted {url} to tLab Anti-APT", outputs, removeNull=True),
    )


def resolve_status(client: TLabClient, access_code: str, args: dict, params: dict) -> tuple[bool, CommandResults]:
    """Check one submission. Returns (terminal, results)."""
    early = argToBoolean(args.get("early_verdict") or params.get("early_verdict") or False)
    status = client.request_status(access_code, early_verdict=early)
    request_status = status.get("analysisRequestStatus")

    if request_status == REQUEST_STATUS_REJECTED:
        outputs = submission_outputs(status)
        code = status.get("rejectionCode") or ""
        if code in NON_ERROR_REJECTIONS:
            # Whitelisted and already-analyzed are outcomes, not failures: the
            # caller gets a result rather than an exception.
            return True, CommandResults(
                outputs_prefix=OUTPUT_SUBMISSION,
                outputs_key_field="AccessCode",
                outputs=outputs,
                raw_response=status,
                readable_output=f"### tLab Anti-APT\n{describe_rejection(code)}",
            )
        raise TLabRejection(code, status.get("message") or "", status)

    reports = status.get("reports") or []
    main = select_main_report(reports)
    if not main:
        # Reports appear only once the request reaches ACCEPTED.
        return False, CommandResults(
            readable_output=f"Waiting for tLab Anti-APT: request status is {request_status or 'unknown'}."
        )

    verdict = canonical_verdict(
        main,
        suspicious_from=float(params.get("score_threshold_suspicious") or DEFAULT_SUSPICIOUS_FROM),
        malicious_from=float(params.get("score_threshold_malicious") or DEFAULT_MALICIOUS_FROM),
        early_verdict=early,
    )
    terminal = is_terminal(main.get("sampleReportCompleteness") or "", verdict)

    if terminal and argToBoolean(args.get("extended") or False):
        # The public status endpoint returns SampleReportShortBean, which has
        # no dynReportSummary or statReportSummary. Sub-report ids live only on
        # GET /sample_reports/{id}.
        try:
            main = client.get_sample_report(main["sampleReportId"])
        except DemistoException as exc:
            demisto.debug(f"tLab: could not enrich report {main.get('sampleReportId')}: {exc}")

    outputs = analysis_outputs(main, params, access_code=access_code, request_status=request_status)
    siblings = [r for r in reports if r.get("sampleReportId") != main.get("sampleReportId")]
    if siblings:
        outputs["ChildReports"] = [
            {
                "SampleReportId": r.get("sampleReportId"),
                "SampleReportType": r.get("sampleReportType"),
                "UploadedFilename": r.get("uploadedFilename"),
                "Score": r.get("sampleScore"),
                "Completeness": r.get("sampleReportCompleteness"),
            }
            for r in siblings
        ]

    results = CommandResults(
        outputs_prefix=OUTPUT_ANALYSIS,
        outputs_key_field="SampleReportId",
        outputs=outputs,
        raw_response=status,
        readable_output=analysis_readable(outputs),
        indicator=build_file_indicator(outputs, params.get("reliability") or DBotScoreReliability.B),
    )
    return terminal, results


def poll_status_command(client: TLabClient, args: dict, params: dict) -> CommandResults:
    """Poll a submission to a terminal verdict.

    Scheduled commands need server 6.2.0. Below that the loop runs inline,
    which holds a worker, so the timeout is capped.
    """
    access_code = args.get("access_code")
    if not access_code:
        raise DemistoException("access_code is required.")
    interval = arg_to_number(args.get("interval_in_seconds") or DEFAULT_INTERVAL) or DEFAULT_INTERVAL
    timeout = arg_to_number(args.get("timeout_in_seconds") or DEFAULT_TIMEOUT) or DEFAULT_TIMEOUT

    terminal, results = resolve_status(client, access_code, args, params)
    if terminal:
        return results

    if supports_scheduled_commands():
        results.scheduled_command = schedule_next_poll("tlab-get-submission-status", args, interval, timeout)
        return results

    capped = min(timeout, BLOCKING_TIMEOUT_CAP)
    demisto.debug(f"tLab: server does not support scheduled commands; polling inline for up to {capped}s")

    def check():
        done, res = resolve_status(client, access_code, args, params)
        return done, res

    return blocking_poll(check, interval, capped)


def detonate_command(client: TLabClient, args: dict, params: dict, kind: str) -> CommandResults:
    """Submit and then poll, reusing the standalone status command."""
    if args.get("access_code"):
        # A scheduled re-run lands here with the access code already known.
        return poll_status_command(client, args, params)

    submitted = submit_file_command(client, args, params) if kind == "file" else submit_url_command(client, args, params)
    outputs = submitted.outputs if isinstance(submitted.outputs, dict) else {}
    access_code = outputs.get("AccessCode")
    if not access_code:
        return submitted

    poll_args = dict(args)
    poll_args["access_code"] = access_code
    return poll_status_command(client, poll_args, params)


def get_report_command(client: TLabClient, args: dict, params: dict) -> CommandResults:
    sample_report_id = arg_to_number(args.get("sample_report_id"))
    if not sample_report_id:
        raise DemistoException("sample_report_id is required.")
    report = client.get_sample_report(sample_report_id)
    outputs = analysis_outputs(report, params)
    return CommandResults(
        outputs_prefix=OUTPUT_REPORT,
        outputs_key_field="SampleReportId",
        outputs=outputs,
        raw_response=report,
        readable_output=analysis_readable(outputs),
        indicator=build_file_indicator(outputs, params.get("reliability") or DBotScoreReliability.B),
    )


def get_threat_indicators_command(client: TLabClient, args: dict, params: dict) -> CommandResults:
    sample_report_id = arg_to_number(args.get("sample_report_id"))
    if not sample_report_id:
        raise DemistoException("sample_report_id is required.")
    level_filter = {x.upper() for x in argToList(args.get("level"))}
    source_filter = {x.upper() for x in argToList(args.get("source"))}
    limit = arg_to_number(args.get("limit") or 100) or 100

    payload = client.get_threat_indicators(sample_report_id)
    rows = []
    for indicator in payload.get("indicators") or []:
        if level_filter and str(indicator.get("level") or "").upper() not in level_filter:
            continue
        if source_filter and str(indicator.get("source") or "").upper() not in source_filter:
            continue
        rows.append(
            {
                "Id": indicator.get("id"),
                "Source": indicator.get("source"),
                "AnalysisType": indicator.get("analysisType"),
                "Key": indicator.get("key"),
                "Level": indicator.get("level"),
                "Title": indicator.get("title"),
                "Count": indicator.get("count"),
                "ObjectsTotal": indicator.get("objectsTotal"),
                "Objects": [{"Kind": obj.get("kind"), "Name": obj.get("name")} for obj in (indicator.get("objects") or [])],
                "Attack": indicator.get("attack") or [],
            }
        )
        if len(rows) >= limit:
            break

    outputs = {"SampleReportId": sample_report_id, "Indicators": rows, "Totals": payload.get("totals") or {}}
    table = [{"Level": r["Level"], "Source": r["Source"], "Title": r["Title"], "Count": r["Count"]} for r in rows]
    return CommandResults(
        outputs_prefix=OUTPUT_THREAT,
        outputs_key_field="SampleReportId",
        outputs=outputs,
        raw_response=payload,
        readable_output=tableToMarkdown(f"tLab Anti-APT threat indicators for report {sample_report_id}", table, removeNull=True),
    )


def get_attack_matrix_command(client: TLabClient, args: dict, params: dict) -> CommandResults:
    sample_report_id = arg_to_number(args.get("sample_report_id"))
    if not sample_report_id:
        raise DemistoException("sample_report_id is required.")
    payload = client.get_attack_matrix(sample_report_id)
    techniques = [
        {
            "Id": t.get("id"),
            "Name": t.get("name"),
            "Url": t.get("url"),
            "Level": t.get("level"),
            "Tactics": t.get("tactics") or [],
            "PrimarySource": t.get("primarySource"),
            "StaticOnly": t.get("staticOnly"),
        }
        for t in (payload.get("techniques") or [])
    ]
    outputs = {
        "SampleReportId": sample_report_id,
        "CatalogVersion": payload.get("catalogVersion"),
        "Totals": payload.get("totals") or {},
        "Techniques": techniques,
        "Tactics": payload.get("tactics") or [],
    }
    return CommandResults(
        outputs_prefix=OUTPUT_ATTACK,
        outputs_key_field="SampleReportId",
        outputs=outputs,
        raw_response=payload,
        readable_output=tableToMarkdown(
            f"MITRE ATT&CK techniques for report {sample_report_id}",
            [{"Technique": t["Id"], "Name": t["Name"], "Level": t["Level"]} for t in techniques],
            removeNull=True,
        ),
    )


def get_pcap_command(client: TLabClient, args: dict, params: dict) -> Any:
    """Network capture, as bytes or as the analyzer's JSON report.

    DynReportsController maps two handlers to ``{id}/pcap`` differing only by
    ``produces``, so the Accept header decides which one answers.
    """
    dyn_report_id = arg_to_number(args.get("dyn_report_id"))
    if not dyn_report_id:
        raise DemistoException("dyn_report_id is required.")
    fmt = (args.get("format") or "pcap").lower()
    max_bytes = (arg_to_number(params.get("max_artifact_size_mb") or 50) or 50) * 1024 * 1024

    if fmt == "json":
        payload = client.request("GET", f"/dyn_reports/{dyn_report_id}/pcap", headers={"Accept": "application/json"})
        return CommandResults(
            outputs_prefix="TLabAntiAPT.PcapReport",
            outputs_key_field="DynReportId",
            outputs={"DynReportId": dyn_report_id, "Report": payload},
            raw_response=payload,
            readable_output=f"Retrieved the PCAP analysis report for dynamic report {dyn_report_id}.",
        )

    data = client.download(f"/dyn_reports/{dyn_report_id}/pcap", "application/octet-stream", max_bytes=max_bytes)
    return fileResult(f"tlab_{dyn_report_id}.pcap", data, file_type=EntryType.FILE)


def get_report_pdf_command(client: TLabClient, args: dict, params: dict) -> Any:
    """Rendered PDF report.

    This endpoint is a POST, not a GET, and renders synchronously with no
    status endpoint, so it gets its own timeout.
    """
    sample_report_id = arg_to_number(args.get("sample_report_id"))
    if not sample_report_id:
        raise DemistoException("sample_report_id is required.")
    timeout = arg_to_number(args.get("timeout") or params.get("pdf_timeout") or 180) or 180
    max_bytes = (arg_to_number(params.get("max_artifact_size_mb") or 50) or 50) * 1024 * 1024

    data = client.download(
        f"/report-pdf/{sample_report_id}",
        "application/pdf",
        max_bytes=max_bytes,
        method="POST",
        json_data={"imgBase64": ""},
        timeout=timeout,
    )
    return fileResult(f"tlab_report_{sample_report_id}.pdf", data, file_type=EntryType.ENTRY_INFO_FILE)


def list_env_presets_command(client: TLabClient, args: dict) -> CommandResults:
    scope = (args.get("scope") or "global").lower()
    payload = client.list_env_presets(scope)
    names = payload if isinstance(payload, list) else (payload or {}).get("content") or []
    rows = [{"Name": p.get("name") if isinstance(p, dict) else p, "Scope": scope} for p in names]
    return CommandResults(
        outputs_prefix=OUTPUT_PRESET,
        outputs_key_field="Name",
        outputs=rows,
        raw_response=payload,
        readable_output=tableToMarkdown(f"tLab Anti-APT {scope} environment presets", rows, removeNull=True),
    )


def list_sources_command(client: TLabClient) -> CommandResults:
    payload = client.list_sources()
    rows = payload if isinstance(payload, list) else (payload or {}).get("content") or []
    table = [
        {"SourceId": s.get("sourceId"), "Type": s.get("sourceType"), "Uid": s.get("sourceUid")}
        for s in rows
        if isinstance(s, dict)
    ]
    return CommandResults(
        outputs_prefix=OUTPUT_SOURCE,
        outputs_key_field="SourceId",
        outputs=table,
        raw_response=payload,
        readable_output=tableToMarkdown("tLab Anti-APT submission sources", table, removeNull=True),
    )


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------
def build_client(params: dict) -> TLabClient:
    return TLabClient(
        base_url=params.get("url") or "",
        auth_mode=params.get("auth_mode") or AUTH_TLAB_ACCOUNT,
        credentials=params.get("credentials") or {},
        client_name=params.get("client_name") or "xsoar",
        verify=not params.get("insecure", False),
        proxy=params.get("proxy", False),
        auth_url=params.get("auth_url") or "",
    )


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    try:
        client = build_client(params)

        if command == "test-module":
            return_results(test_module_command(client, params))
        elif command == "tlab-submit-file":
            return_results(submit_file_command(client, args, params))
        elif command == "tlab-submit-url":
            return_results(submit_url_command(client, args, params))
        elif command == "tlab-get-submission-status":
            return_results(poll_status_command(client, args, params))
        elif command == "tlab-detonate-file":
            return_results(detonate_command(client, args, params, "file"))
        elif command == "tlab-detonate-url":
            return_results(detonate_command(client, args, params, "url"))
        elif command == "tlab-get-report":
            return_results(get_report_command(client, args, params))
        elif command == "tlab-get-threat-indicators":
            return_results(get_threat_indicators_command(client, args, params))
        elif command == "tlab-get-attack-matrix":
            return_results(get_attack_matrix_command(client, args, params))
        elif command == "tlab-get-pcap":
            return_results(get_pcap_command(client, args, params))
        elif command == "tlab-get-report-pdf":
            return_results(get_report_pdf_command(client, args, params))
        elif command == "tlab-list-env-presets":
            return_results(list_env_presets_command(client, args))
        elif command == "tlab-list-sources":
            return_results(list_sources_command(client))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except TLabRejection as rejection:
        return_error(str(rejection))
    except Exception as exc:  # noqa: BLE001 - XSOAR requires a single catch-all in main
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command}. Error: {exc}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
