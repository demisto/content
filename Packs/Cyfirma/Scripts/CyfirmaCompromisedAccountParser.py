import json


def main():
    try:
        raw_data = demisto.incident().get("CustomFields") or {}
        if not raw_data:
            return_error("CustomFields is empty on this incident")
            return

        ca_data = raw_data.get("cyfirmacompromisedaccountdetails") or []

        result = {}
        for row in ca_data:
            if isinstance(row, dict) and row.get("fields"):
                result[row["fields"]] = row.get("values")

        return_results(CommandResults(
            outputs_prefix="Cyfirma.CA",
            outputs=result,
            readable_output=f"Parsed alert\n```\n{json.dumps(result, indent=2, default=str)}\n```",
        ))
    except Exception as e:
        return_error(f"Failed to parse Cyfirma alert: {e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
