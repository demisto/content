import json


def grid_to_dict(rows):
    out = {}
    for row in rows or []:
        if isinstance(row, dict) and row.get("fields"):
            out[row["fields"]] = row.get("values")
    return out


def main():
    try:
        raw_data = demisto.incident().get("CustomFields") or {}
        if not raw_data:
            return_error("CustomFields is empty on this incident")
            return

        result = grid_to_dict(raw_data.get("cyfirmaalertdetails"))

        footprints = grid_to_dict(raw_data.get("cyfirmadigitalfootprints"))
        if footprints:
            result["DigitalFootprints"] = footprints

        return_results(CommandResults(
            outputs_prefix="Cyfirma.Alert",
            outputs=result,
            readable_output=f"Parsed alert\n```\n{json.dumps(result, indent=2, default=str)}\n```",
        ))
    except Exception as e:
        return_error(f"Failed to parse Cyfirma alert: {e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
