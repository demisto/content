register_module_line('DarkmonLevenshtein', 'start', __line__())


def levenshtein(a: str, b: str) -> int:
    """Plain Wagner-Fischer; small inputs (domain names), no need for optimization."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            curr[j] = min(
                prev[j] + 1,        # deletion
                curr[j - 1] + 1,    # insertion
                prev[j - 1] + (0 if ca == cb else 1),  # substitution
            )
        prev = curr
    return prev[-1]


def main():
    args = demisto.args()
    domain = (args.get("domain") or "").strip().lower()
    brands = argToList(args.get("brands"))
    if not domain or not brands:
        return_error("Both 'domain' and 'brands' are required.")
        return

    domain_root = domain.split(".")[0]
    best_brand = None
    best_distance = 10**9
    for b in brands:
        b_clean = b.strip().lower()
        if not b_clean:
            continue
        d = levenshtein(domain_root, b_clean)
        if d < best_distance:
            best_distance, best_brand = d, b_clean

    return_results({
        "Type": entryTypes["note"],
        "ContentsFormat": formats["json"],
        "Contents": {"domain": domain, "brand": best_brand, "distance": best_distance},
        "EntryContext": {"Darkmon.Levenshtein": {
            "domain": domain, "brand": best_brand, "distance": best_distance,
        }},
    })


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()


register_module_line('DarkmonLevenshtein', 'end', __line__())
