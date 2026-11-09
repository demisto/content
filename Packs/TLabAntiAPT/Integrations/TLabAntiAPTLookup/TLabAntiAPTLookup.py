"""tLab Anti-APT Lookup integration for Cortex XSOAR.

Answers "has tLab Anti-APT already seen this file?" without submitting
anything. Runs with the lowest tLab role, so it can be given a restricted
account while detonation keeps a privileged one.
"""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa: F401

from TLabAntiAPTApiModule import *  # noqa: F401,E402

OUTPUT_FILE = "TLabAntiAPT.File"
OUTPUT_SCAN = "TLabAntiAPT.ScanResult"
OUTPUT_INFO = "TLabAntiAPT.FileInfo"
OUTPUT_REPORT = "TLabAntiAPT.Report"
OUTPUT_HASH_SEARCH = "TLabAntiAPT.HashSearch"
OUTPUT_INDICATOR_CODE = "TLabAntiAPT.IndicatorCode"

# Report filters the server accepts from every role. Anything outside this set
# is silently discarded for company_admin and user, which turns a narrow query
# into "return everything" with no error.
ROLE_SAFE_FILTERS = {
    "fileType",
    "completeness",
    "status",
    "dateFrom",
    "dateTo",
    "fileHashSha256",
    "fileHashSha1",
    "tags",
    "indicators",
}
ADMIN_ONLY_FILTERS = {"fileVerdict", "scoreLevel", "sourceId", "rootOnly", "minReportId", "minScore", "fileName"}


def score_thresholds(params: dict) -> tuple[float, float]:
    return (
        float(params.get("score_threshold_suspicious") or DEFAULT_SUSPICIOUS_FROM),
        float(params.get("score_threshold_malicious") or DEFAULT_MALICIOUS_FROM),
    )


def lookup_reports_by_hash(client: TLabClient, hash_value: str, hash_type: str, params: dict) -> list:
    """Find reports for one hash, verifying every result actually matches.

    MD5 is resolved through the hash search endpoint rather than the report
    filter: ``fileHashMd5`` is not in the server's role allow-list, so for a
    non-admin account it is dropped and the query matches unrelated samples.
    """
    completeness = argToList(params.get("completeness")) or [COMPLETENESS_COMPLETE]
    limit = arg_to_number(params.get("lookup_limit") or 1) or 1

    if hash_type == "md5":
        resolved = resolve_md5_to_sha256(client, hash_value)
        if not resolved:
            return []
        hash_value, hash_type = resolved, "sha256"

    query: dict[str, Any] = {"file_hash_sha256": hash_value} if hash_type == "sha256" else {"file_hash_sha1": hash_value}
    page = client.list_sample_reports(
        page=0,
        size=max(limit, 10),
        # Newest first: the most recent analysis is the relevant one.
        sort="sampleReportId,desc",
        completeness=completeness,
        status=["ACTIVE"],
        **query,
    )
    reports = page.get("content") or []
    # The hash filters are prefix matches OR'd against the archive hash, so the
    # server can legitimately return a different sample.
    verified = [r for r in reports if report_matches_hash(r, hash_type, hash_value)]
    dropped = len(reports) - len(verified)
    if dropped:
        demisto.debug(f"tLab: discarded {dropped} report(s) whose {hash_type} did not match {hash_value}")
    return verified[:limit]


def resolve_md5_to_sha256(client: TLabClient, md5: str) -> str:
    payload = client.hash_search("md5", md5)
    rows = payload if isinstance(payload, list) else (payload or {}).get("content") or []
    for row in rows:
        if str(row.get("hashMd5") or "").lower() == md5.lower():
            return str(row.get("hashSha256") or "")
    return ""


def file_outputs(report: dict, params: dict) -> dict:
    file_dto = report.get("file") or {}
    suspicious_from, malicious_from = score_thresholds(params)
    verdict = canonical_verdict(report, suspicious_from=suspicious_from, malicious_from=malicious_from)
    score, present = score_value(report)
    return remove_empty_elements(
        {
            "SampleReportId": report.get("sampleReportId"),
            "HashSha256": file_dto.get("hashSha256"),
            "HashSha1": file_dto.get("hashSha1"),
            "HashMd5": file_dto.get("hashMd5"),
            "Size": file_dto.get("size"),
            "FileType": file_dto.get("fileType"),
            "MimeType": file_dto.get("mimeType"),
            "UploadedFilename": report.get("uploadedFilename"),
            "Verdict": verdict,
            # Both raw enumerations are kept so an analyst can see what the server
            # said, not only the canonical value.
            "ScoreLevel": report.get("verdict"),
            # Set by hand in tLab; absent while nobody has set it.
            "FileVerdict": stored_file_verdict(file_dto.get("fileVerdict")),
            "Score": score if present else None,
            "Completeness": report.get("sampleReportCompleteness"),
            "AnalyzedAt": epoch_to_iso(report.get("createTime")),
            "Found": True,
        }
    )


def build_indicator(outputs: dict, params: dict, requested_hash: str) -> Common.File:
    verdict = outputs.get("Verdict", VERDICT_UNKNOWN)
    score = verdict_to_dbot_score(verdict, unknown_is_benign=argToBoolean(params.get("unknown_is_benign") or False))
    dbot = Common.DBotScore(
        indicator=requested_hash,
        indicator_type=DBotScoreType.FILE,
        integration_name="tLab Anti-APT",
        score=score,
        malicious_description=f"tLab Anti-APT verdict: {verdict}" if score == Common.DBotScore.BAD else None,
        reliability=params.get("reliability") or DBotScoreReliability.B,
    )
    return Common.File(
        dbot_score=dbot,
        md5=outputs.get("HashMd5"),
        sha1=outputs.get("HashSha1"),
        sha256=outputs.get("HashSha256"),
        name=outputs.get("UploadedFilename"),
        size=outputs.get("Size"),
        file_type=outputs.get("FileType"),
    )


def not_found_indicator(requested_hash: str, hash_type: str, params: dict) -> Common.File:
    """A hash tLab has never seen gets score 0, not Good.

    "We have no record" is not the same statement as "this is benign", and a
    Good score here would suppress other vendors' findings in the incident.
    """
    dbot = Common.DBotScore(
        indicator=requested_hash,
        indicator_type=DBotScoreType.FILE,
        integration_name="tLab Anti-APT",
        score=Common.DBotScore.NONE,
        reliability=params.get("reliability") or DBotScoreReliability.B,
    )
    kwargs = {hash_type: requested_hash}
    return Common.File(dbot_score=dbot, **kwargs)


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------
def test_module_command(client: TLabClient) -> str:
    identity = client.whoami()
    login = identity.get("userLogin") or identity.get("login") or "unknown"
    role = identity.get("userRole") or "unknown"
    demisto.debug(f"tLab Anti-APT: connected as {login} (role: {role})")
    # XSOAR treats any other string — even "ok - …" — as a failed test.
    return "ok"


def file_reputation_command(client: TLabClient, args: dict, params: dict) -> list:
    hashes = argToList(args.get("file"))
    if not hashes:
        raise DemistoException("The file argument is required.")

    results = []
    for raw in hashes:
        value = str(raw).strip().lower()
        hash_type = hash_type_of(value)
        if not hash_type:
            # Partial hashes are refused rather than searched: the server's
            # filters are prefix matches, so a short value would match
            # unrelated samples and produce a confident wrong verdict.
            results.append(
                CommandResults(
                    readable_output=(
                        f"### tLab Anti-APT\nSkipped {raw!r}: expected a full MD5, SHA1 or SHA256 hash. "
                        "Partial hashes are not looked up because the server matches hash filters by prefix."
                    )
                )
            )
            continue

        reports = lookup_reports_by_hash(client, value, hash_type, params)
        if not reports:
            results.append(
                CommandResults(
                    indicator=not_found_indicator(value, hash_type, params),
                    readable_output=f"### tLab Anti-APT\nNo analysis found for {value}.",
                )
            )
            continue

        outputs = file_outputs(reports[0], params)
        results.append(
            CommandResults(
                outputs_prefix=OUTPUT_FILE,
                outputs_key_field="HashSha256",
                outputs=outputs,
                raw_response=reports[0],
                indicator=build_indicator(outputs, params, value),
                readable_output=tableToMarkdown(
                    f"tLab Anti-APT reputation for {value}",
                    {
                        "Verdict": outputs.get("Verdict"),
                        "Score": outputs.get("Score"),
                        "Report ID": outputs.get("SampleReportId"),
                        "File name": outputs.get("UploadedFilename"),
                        "Analyzed at": outputs.get("AnalyzedAt"),
                    },
                    removeNull=True,
                ),
            )
        )
    return results


def scan_result_command(client: TLabClient, args: dict, params: dict) -> CommandResults:
    value = str(args.get("hash") or "").strip().lower()
    if not value:
        raise DemistoException("The hash argument is required.")
    hash_type = args.get("hash_type") or hash_type_of(value)
    if hash_type not in ("md5", "sha1", "sha256"):
        raise DemistoException(
            f"Could not determine the hash type of {value!r}. Provide a full MD5, SHA1 or SHA256 hash, "
            "or set hash_type explicitly."
        )

    limit = arg_to_number(args.get("limit") or params.get("lookup_limit") or 1) or 1
    reports = lookup_reports_by_hash(client, value, hash_type, {**params, "lookup_limit": limit})
    rows = [file_outputs(r, params) for r in reports]
    if not rows:
        return CommandResults(
            outputs_prefix=OUTPUT_SCAN,
            outputs_key_field="HashSha256",
            outputs={"Found": False, "Requested": value},
            readable_output=f"### tLab Anti-APT\nNo analysis found for {value}.",
        )
    return CommandResults(
        outputs_prefix=OUTPUT_SCAN,
        outputs_key_field="SampleReportId",
        outputs=rows,
        raw_response=reports,
        readable_output=tableToMarkdown(f"tLab Anti-APT scan results for {value}", rows, removeNull=True),
    )


def file_info_command(client: TLabClient, args: dict, params: dict) -> CommandResults:
    sha256 = str(args.get("sha256") or "").strip().lower()
    if hash_type_of(sha256) != "sha256":
        raise DemistoException("sha256 must be a full 64-character SHA256 hash.")
    payload = client.get_file_by_hash(sha256)
    outputs = remove_empty_elements(
        {
            "HashSha256": payload.get("hashSha256"),
            "HashSha1": payload.get("hashSha1"),
            "HashMd5": payload.get("hashMd5"),
            "Size": payload.get("size"),
            "FileType": payload.get("fileType"),
            "MimeType": payload.get("mimeType"),
            "InferredExtension": payload.get("inferredExtension"),
            "UploadedExtension": payload.get("uploadedExtension"),
            "SuggestedName": payload.get("suggestedName"),
            # The stored analyst verdict for this file. It is read here, never
            # written: the /verdict routes are POST setters guarded by @PreAuthorize.
            # Absent while nobody has set it.
            "FileVerdict": stored_file_verdict(payload.get("fileVerdict")),
            "Signed": payload.get("signed"),
            "DigitalSignatureCount": payload.get("digitalSignatureCount"),
        }
    )
    return CommandResults(
        outputs_prefix=OUTPUT_INFO,
        outputs_key_field="HashSha256",
        outputs=outputs,
        raw_response=payload,
        readable_output=tableToMarkdown(f"tLab Anti-APT file {sha256}", outputs, removeNull=True),
    )


def search_reports_command(client: TLabClient, args: dict, params: dict) -> CommandResults:
    sort = args.get("sort") or "sampleReportId,desc"
    # Rejects createTime, which the server ignores silently instead of failing.
    validate_sort(sort)

    used_admin_filters = sorted(
        name
        for name, value in (
            ("fileVerdict", args.get("file_verdict")),
            ("scoreLevel", args.get("score_level")),
            ("sourceId", args.get("source_id")),
            ("rootOnly", args.get("root_only")),
            ("minReportId", args.get("min_report_id")),
            ("minScore", args.get("min_score")),
            ("fileName", args.get("file_name")),
        )
        if value
    )

    limit = arg_to_number(args.get("limit") or 50) or 50
    page = client.list_sample_reports(
        page=arg_to_number(args.get("page") or 0) or 0,
        size=min(limit, 200),
        sort=sort,
        date_from=args.get("date_from"),
        date_to=args.get("date_to"),
        completeness=argToList(args.get("completeness")),
        status=argToList(args.get("status")) or ["ACTIVE"],
        file_verdicts=argToList(args.get("file_verdict")),
        score_levels=argToList(args.get("score_level")),
        file_types=argToList(args.get("file_type")),
        source_ids=argToList(args.get("source_id")),
        tags=argToList(args.get("tags")),
        indicators=argToList(args.get("indicators")),
        root_only=argToBoolean(args["root_only"]) if args.get("root_only") else None,
        min_report_id=arg_to_number(args.get("min_report_id")),
        min_score=arg_to_number(args.get("min_score")),
        file_name=args.get("file_name"),
        file_hash_sha256=args.get("file_hash_sha256"),
        file_hash_sha1=args.get("file_hash_sha1"),
    )
    rows = [file_outputs(r, params) for r in (page.get("content") or [])][:limit]

    readable = tableToMarkdown(f"tLab Anti-APT reports ({page.get('totalElements', len(rows))} total)", rows, removeNull=True)
    if used_admin_filters:
        # The server drops these for company_admin and user without an error,
        # so a narrow query silently becomes "everything".
        readable += (
            "\n**Warning:** the filters "
            f"{', '.join(used_admin_filters)} are only applied for accounts with the admin or developer "
            "role. With a lower role the server discards them without an error, so these results may be "
            "unfiltered. Verify the account role if the result set looks too broad.\n"
        )
    return CommandResults(
        outputs_prefix=OUTPUT_REPORT,
        outputs_key_field="SampleReportId",
        outputs=rows,
        raw_response=page,
        readable_output=readable,
    )


def hash_search_command(client: TLabClient, args: dict) -> CommandResults:
    hash_type = (args.get("hash_type") or "").lower()
    hash_part = str(args.get("hash_part") or "").strip().lower()
    if hash_type not in ("md5", "sha1", "sha256"):
        raise DemistoException("hash_type must be one of md5, sha1 or sha256.")
    if len(hash_part) < 3:
        raise DemistoException("hash_part must be at least 3 characters long.")

    payload = client.hash_search(hash_type, hash_part)
    rows = payload if isinstance(payload, list) else (payload or {}).get("content") or []
    outputs = [
        remove_empty_elements(
            {
                "HashValue": row.get(f"hash{hash_type.capitalize()}") or row.get("hashSha256"),
                "HashType": hash_type,
                "FileType": row.get("fileType"),
                "FileVerdict": stored_file_verdict(row.get("fileVerdict")),
            }
        )
        for row in rows
        if isinstance(row, dict)
    ]
    return CommandResults(
        outputs_prefix=OUTPUT_HASH_SEARCH,
        outputs_key_field="HashValue",
        outputs=outputs,
        raw_response=payload,
        readable_output=tableToMarkdown(
            f"tLab Anti-APT hash search for {hash_type} starting with {hash_part}", outputs, removeNull=True
        ),
    )


def list_indicator_codes_command(client: TLabClient, args: dict) -> CommandResults:
    analysis_type = (args.get("analysis_type") or "").upper()
    payload = client.list_indicator_codes()
    rows = payload if isinstance(payload, list) else (payload or {}).get("content") or []
    outputs = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        if analysis_type and str(row.get("analysisType") or "").upper() != analysis_type:
            continue
        outputs.append(
            {
                "Code": row.get("indicatorCode") or row.get("code"),
                "Name": row.get("name") or row.get("indicatorName"),
                "AnalysisType": row.get("analysisType"),
            }
        )
    return CommandResults(
        outputs_prefix=OUTPUT_INDICATOR_CODE,
        outputs_key_field="Code",
        outputs=outputs,
        raw_response=payload,
        readable_output=tableToMarkdown("tLab Anti-APT indicator codes", outputs, removeNull=True),
    )


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
            return_results(test_module_command(client))
        elif command == "file":
            return_results(file_reputation_command(client, args, params))
        elif command == "tlab-file-scan-result":
            return_results(scan_result_command(client, args, params))
        elif command == "tlab-file-info":
            return_results(file_info_command(client, args, params))
        elif command == "tlab-search-reports":
            return_results(search_reports_command(client, args, params))
        elif command == "tlab-hash-search":
            return_results(hash_search_command(client, args))
        elif command == "tlab-list-indicator-codes":
            return_results(list_indicator_codes_command(client, args))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception as exc:  # noqa: BLE001 - XSOAR requires a single catch-all in main
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command}. Error: {exc}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
