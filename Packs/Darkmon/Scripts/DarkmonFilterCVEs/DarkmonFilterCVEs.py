register_module_line('DarkmonFilterCVEs', 'start', __line__())


def main():
    args = demisto.args()
    items = argToList(args.get("items")) or []
    min_cvss = float(args.get("min_cvss", "9.0"))
    tech_list_name = args.get("tech_stack_list")

    res = demisto.executeCommand("getList", {"listName": tech_list_name}) if tech_list_name else None
    content = (res[0].get("Contents", "") if res else "") or ""
    tech = [t.strip().lower() for t in content.replace(",", "\n").splitlines() if t.strip()]

    out = []
    for it in items:
        try:
            score = float(it.get("cvssScore") or 0)
        except (TypeError, ValueError):
            score = 0
        if score < min_cvss:
            continue
        if tech:
            tags = [str(t).lower() for t in (it.get("tags") or [])]
            if not any(t in tags for t in tech):
                continue
        out.append(it)

    return_results({"FilteredCVEs": out})


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()


register_module_line('DarkmonFilterCVEs', 'end', __line__())
