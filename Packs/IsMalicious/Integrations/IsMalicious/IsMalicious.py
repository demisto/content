import demistomock as demisto
from CommonServerPython import *

from typing import Any
from urllib.parse import quote, urlsplit
from ipaddress import ip_address

import requests

import re

API_URL = "https://api.ismalicious.com"
HASH_PATTERN = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")


def handle_http_error(response: Any) -> None:
    """Do not include credential-bearing requests or response bodies in errors."""
    message = f"IsMalicious HTTP {response.status_code}"
    if response.status_code in (401, 403):
        message += ": check the complete X-API-KEY credential and API permissions."
    elif response.status_code == 429:
        message += ": rate limited; retry after the provider's indicated delay."
    raise DemistoException(message)


class Client(BaseClient):
    def check(self, indicator: str) -> dict[str, Any]:
        if not indicator or not indicator.strip():
            raise ValueError("An indicator is required.")
        try:
            result = self._http_request(
                method="GET",
                url_suffix="/check",
                params={"query": indicator, "enrichment": "standard"},
                timeout=25,
                retries=0,
                ok_codes=(200,),
                allow_redirects=False,
                error_handler=handle_http_error,
            )
        except requests.Timeout as error:
            raise DemistoException("IsMalicious request timed out.") from error
        if not isinstance(result, dict) or not isinstance(result.get("malicious"), bool):
            raise DemistoException("IsMalicious returned an invalid response.")
        return result


def dbot_verdict(response: dict[str, Any]) -> tuple[int, str]:
    """Honor server evidence; absence of detections is never a good score."""
    if response.get("lookupStatus") == "unknown" or response.get("delisted") is True:
        return Common.DBotScore.NONE, "unknown"
    evidence = response.get("evidence") or {}
    verdict = evidence.get("verdict") if isinstance(evidence, dict) else None
    if verdict == "malicious":
        return Common.DBotScore.BAD, verdict
    if verdict == "suspicious":
        return Common.DBotScore.SUSPICIOUS, verdict
    if verdict in ("clean", "benign"):
        return Common.DBotScore.GOOD, verdict
    if verdict is None and response.get("malicious") is True:
        return Common.DBotScore.BAD, "malicious"
    return Common.DBotScore.NONE, "unknown"


def standard_indicator(value: str, kind: str, score: Common.DBotScore) -> Common.Indicator:
    if kind == "ip":
        return Common.IP(ip=value, dbot_score=score)
    if kind == "domain":
        return Common.Domain(domain=value, dbot_score=score)
    if kind == "url":
        return Common.URL(url=value, dbot_score=score)
    algorithm = {32: "md5", 40: "sha1", 64: "sha256"}[len(value)]
    return Common.File(dbot_score=score, **{algorithm: value})


def validate_indicator(value: str, kind: str) -> None:
    """Prevent /check autodetection from writing reputation on a different type."""
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("Indicators must be non-empty strings without surrounding whitespace.")
    if kind == "file":
        if not HASH_PATTERN.fullmatch(value):
            raise ValueError("The file argument must contain MD5, SHA1 or SHA256 hashes, not file paths.")
    elif kind == "ip":
        if "%" in value:
            raise ValueError("Scoped IPv6 addresses are not supported.")
        ip_address(value)
    elif kind == "domain":
        candidate = value.rstrip(".").encode("idna").decode("ascii")
        labels = candidate.split(".")
        if (
            len(candidate) > 253
            or len(labels) < 2
            or not all(re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", label) for label in labels)
        ):
            raise ValueError("The domain argument must contain fully qualified domain names.")
        try:
            ip_address(candidate)
        except ValueError:
            pass
        else:
            raise ValueError("Use the ip command for IP addresses.")
    elif kind == "url":
        parts = urlsplit(value)
        if parts.scheme.lower() not in ("http", "https") or not parts.hostname or any(char.isspace() for char in value):
            raise ValueError("The url argument must contain complete HTTP(S) URLs.")
        if parts.username is not None or parts.password is not None:
            raise ValueError("URLs containing credentials are not supported.")
        # Accessing port validates malformed ports and urlsplit validates IPv6 brackets.
        _ = parts.port
    else:
        raise ValueError("Unsupported indicator type.")


def reputation_command(client: Client, args: dict[str, Any], kind: str, reliability: str) -> list[CommandResults]:
    argument = args.get("file" if kind == "file" else kind)
    # Commas are valid in URLs. URL batches require an array, not CSV splitting.
    values = [argument] if kind == "url" and isinstance(argument, str) else argToList(argument)
    if not values:
        raise ValueError("At least one non-empty indicator is required.")
    if len(values) > 50:
        raise ValueError("At most 50 indicators are supported per command.")
    for value in values:
        validate_indicator(value, kind)
    results = []
    for value in values:
        raw = client.check(value)
        score, verdict = dbot_verdict(raw)
        dbot = Common.DBotScore(
            indicator=value,
            indicator_type=kind,
            integration_name="IsMalicious",
            score=score,
            reliability=reliability,
        )
        risk = raw.get("riskScore") or {}
        confidence = raw.get("confidence") or {}
        evidence = raw.get("evidence") or {}
        output = {
            "Indicator": value,
            "Type": kind,
            "Verdict": verdict,
            "RiskScore": risk.get("score") if isinstance(risk, dict) else None,
            "Confidence": confidence.get("score") if isinstance(confidence, dict) else None,
            "BlocklistHits": raw.get("blocklistHits"),
            "Evidence": evidence,
            "DataTrust": raw.get("dataTrust"),
            "Sources": raw.get("sources"),
            "LookupStatus": raw.get("lookupStatus"),
            "KnownGood": raw.get("knownGood"),
            "Delisted": raw.get("delisted"),
            "ReportURL": "https://ismalicious.com/report?query=" + quote(value, safe=""),
        }
        readable = tableToMarkdown(
            "IsMalicious reputation",
            output,
            headers=[
                "Indicator",
                "Type",
                "Verdict",
                "RiskScore",
                "Confidence",
                "BlocklistHits",
                "LookupStatus",
                "Delisted",
                "ReportURL",
            ],
            removeNull=True,
        )
        if isinstance(evidence, dict) and evidence.get("reasons"):
            readable += "\n\nEvidence reasons:\n" + "\n".join(f"- {reason}" for reason in evidence["reasons"])
        results.append(
            CommandResults(
                outputs_prefix="IsMalicious.Check",
                outputs_key_field="Indicator",
                outputs=output,
                raw_response=raw,
                readable_output=readable,
                indicator=standard_indicator(value, kind, dbot),
                ignore_auto_extract=True,
            )
        )
    return results


def main() -> None:  # pragma: no cover
    params = demisto.params()
    credential = (params.get("credentials") or {}).get("password")
    try:
        if not credential:
            raise ValueError("The complete X-API-KEY credential is required.")
        client = Client(
            base_url=API_URL,
            verify=True,
            proxy=params.get("proxy", False),
            headers={"X-API-KEY": credential, "Accept": "application/json"},
        )
        command = demisto.command()
        if command == "test-module":
            # A successful check validates authentication, not indicator safety.
            client.check("example.com")
            return_results("ok")
        elif command in ("ip", "domain", "url", "file"):
            reliability = params.get("integrationReliability") or DBotScoreReliability.F
            return_results(reputation_command(client, demisto.args(), command, reliability))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception as error:
        return_error(f"IsMalicious integration failed: {error}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
