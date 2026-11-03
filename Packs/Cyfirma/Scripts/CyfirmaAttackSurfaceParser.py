import json


def main():
    try:
        raw_data = demisto.incident().get("CustomFields") or {}
        if not raw_data:
            return_error("CustomFields is empty on this incident")
            return

        alert_details = raw_data.get("cyfirmaalertdetails") or []
        vulnerabilities = raw_data.get("cyfirmavulnerabilities") or []
        network_rows = raw_data.get("cyfirmanetworkattributes") or []

        result = {}
        for row in alert_details:
            if isinstance(row, dict) and row.get("fields"):
                result[row["fields"]] = row.get("values")

        network_attributes = {}
        for row in network_rows:
            if isinstance(row, dict) and row.get("fields"):
                network_attributes[row["fields"]] = row.get("values")
        if network_attributes:
            result["NetworkAttributes"] = network_attributes

        if vulnerabilities:
            cves = sorted({
                v.get("cve") for v in vulnerabilities
                if isinstance(v, dict) and v.get("cve")
            })
            result["CVEs"] = cves
            result["Vulnerabilities"] = vulnerabilities

        return_results(CommandResults(
            outputs_prefix="Cyfirma.Alert",
            outputs=result,
            readable_output=f"Parsed alert\n```\n{json.dumps(result, indent=2, default=str)}\n```",
        ))
    except Exception as e:
        return_error(f"Failed to parse Cyfirma alert: {e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
