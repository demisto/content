register_module_line('DarkmonScoreNRDs', 'start', __line__())


def main():
    args = demisto.args()
    domains = argToList(args.get("domains")) or []
    brands_list = args.get("brands_list")
    max_distance = int(args.get("max_distance", "2"))

    res = demisto.executeCommand("getList", {"listName": brands_list})
    content = (res[0].get("Contents", "") if res else "") or ""
    brands = [b.strip() for b in content.replace(",", "\n").splitlines() if b.strip()]
    if not brands:
        return_results({"Typosquats": []})
        return

    typosquats = []
    for d in domains:
        if isinstance(d, dict):
            value = d.get("value") or ""
            entry_id = d.get("id")
            timestamp = d.get("timestamp")
        else:
            value, entry_id, timestamp = str(d), "", ""
        out = demisto.executeCommand("DarkmonLevenshtein",
                                     {"domain": value, "brands": ",".join(brands)})
        ctx = out[0].get("EntryContext", {}).get("Darkmon.Levenshtein", {}) if out else {}
        distance = int(ctx.get("distance", 999))
        if distance <= max_distance:
            typosquats.append({
                "id": entry_id, "value": value, "timestamp": timestamp,
                "brand": ctx.get("brand"), "distance": distance,
            })

    return_results({"Typosquats": typosquats})


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()


register_module_line('DarkmonScoreNRDs', 'end', __line__())
