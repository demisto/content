import re
import unicodedata
from typing import Any

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

""" CONSTANTS """

INTEGRATION_NAME = "DarkEye"

HAVEIBEENRANSOM = "HaveIBeenRansom"
HAVEIBEENRANSOM_URL = "https://haveibeenransom.com"
# leak_type values of the HaveIBeenRansom metadata search.
HAVEIBEENRANSOM_CATEGORIES = {"ransomware_leak": "ransomware", "traditional_breach": "breach"}

BREACH_HOUSE = "Breach House"
BREACH_HOUSE_URL = "https://breach.house"
# Sections of the Breach House search and the category each record gets.
BREACH_HOUSE_CATEGORIES = {
    "ransomware": "ransomware",
    "breaches": "breach",
    "leads": "leads",
    "stealers": "stealer",
}

DEFAULT_MAX_PAGES = 5
MAX_PAGES_LIMIT = 20
DEFAULT_MAX_RECORDS = 100
MAX_RECORDS_LIMIT = 500
DEFAULT_LIMIT = 25
BREACH_HOUSE_MAX_LIMIT = 200

# Both APIs treat * and ? as wildcards, so only plain domain names are queried.
DOMAIN_REGEX = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$")

RECORD_HEADERS = ["Product", "Category", "Title", "Website", "Group", "Country", "Discovered", "ID"]

""" CLIENT """


class DarkEyeProductError(Exception):
    """A product lookup failed. The message is safe to show: it never holds the API key."""


class ProductClient(BaseClient):
    """Client for one DarkEye product. Each product has its own base URL and API key."""

    def __init__(self, product: str, base_url: str, api_key: str, verify: bool, proxy: bool):
        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Accept": "application/json",
                "User-Agent": "Cortex-XSOAR-DarkEye",
            },
        )
        self.product = product

    def _error_handler(self, response: requests.Response) -> None:
        raise DarkEyeProductError(status_message(self.product, response.status_code))

    def get_json(self, url_suffix: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            response = self._http_request(
                "GET",
                url_suffix=url_suffix,
                params=params,
                resp_type="response",
                error_handler=self._error_handler,
                timeout=30,
                allow_redirects=False,
            )
        except DemistoException as e:
            # Connection errors keep their own text (timeout, proxy, SSL), which never holds the key.
            raise DarkEyeProductError(f"{self.product} request failed: {e.message}") from None
        if response.status_code != 200:
            raise DarkEyeProductError(status_message(self.product, response.status_code))
        try:
            data = response.json()
        except ValueError:
            raise DarkEyeProductError(f"{self.product} returned invalid JSON.") from None
        if not isinstance(data, dict) or data.get("success") is False:
            raise DarkEyeProductError(f"{self.product} returned an unexpected response.")
        return data


""" HELPER FUNCTIONS """


def status_message(product: str, status_code: int) -> str:
    if status_code in (401, 403):
        return f"{product} authentication failed or the plan does not allow this request; check its API key."
    if status_code == 429:
        return f"{product} quota or rate limit reached; retry later."
    return f"{product} returned HTTP {status_code}."


def clean(value: Any) -> str:
    """NFKC-normalized single-line text, or "" for values that are not text or numbers.

    Some group and source names use styled Unicode characters and irregular spacing.
    """
    if isinstance(value, bool) or not isinstance(value, str | int):
        return ""
    return " ".join(unicodedata.normalize("NFKC", str(value)).split())


def bounded_int(value: Any, default: int, maximum: int) -> int:
    number = arg_to_number(value) if value not in (None, "") else None
    if number is None:
        return default
    return min(max(1, number), maximum)


def normalize_domain(value: str) -> str:
    domain = str(value).strip().lower().rstrip(".")
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    if not DOMAIN_REGEX.match(domain) or domain.rsplit(".", 1)[-1].isdigit():
        raise DemistoException(f"{value} is not a plain domain name.")
    return domain


def make_record(product: str, category: str, item: dict[str, Any]) -> dict[str, str]:
    """Keep listing metadata only. Leaked content, leak-site URLs and download links are never read."""
    website = clean(item.get("website"))
    return {
        "Product": product,
        "Category": category,
        "ID": clean(item.get("victim_id") or item.get("id_source") or item.get("id")),
        "Title": clean(item.get("post_title")) or clean(item.get("name")) or website,
        "Website": website,
        "Group": clean(item.get("group_name")),
        "Country": clean(item.get("country")),
        "Discovered": clean(item.get("discovered"))[:10],
    }


def is_about(record: dict[str, str], domain: str) -> bool:
    """True when a Breach House record is about the domain, not only near it.

    The Breach House search matches free text. With a website, it must be the domain or one of
    its subdomains. Without one, the domain must stand alone as a hostname in the title: not
    inside notexample.com or example.com.other.org, but still as mail.example.com.
    """
    website = record["Website"].lower().rstrip(".")
    if website:
        return website == domain or website.endswith("." + domain)
    title = record["Title"].lower()
    return bool(title) and re.search(rf"(?<![\w-]){re.escape(domain)}(?![\w-]|\.\w)", title) is not None


def has_next_page(data: dict[str, Any]) -> bool:
    pagination = data.get("pagination")
    if isinstance(pagination, dict) and "has_next" in pagination:
        return bool(pagination.get("has_next"))
    return bool(data.get("has_next"))


""" PRODUCT LOOKUPS """


def search_haveibeenransom(
    client: ProductClient, domain: str, max_pages: int, max_records: int
) -> tuple[list[dict[str, str]], bool]:
    """Metadata search on the domain, 20 sources per page. Returns (records, truncated)."""
    records: list[dict[str, str]] = []
    seen: set[str] = set()
    for page in range(1, max_pages + 1):
        suffix = f"/api/metadata/domain/{domain}" + (f"/{page}" if page > 1 else "")
        data = client.get_json(suffix)
        sources = data.get("sources", data.get("results")) or []
        if not isinstance(sources, list):
            raise DarkEyeProductError(f"{HAVEIBEENRANSOM} returned an unexpected response.")
        for leak in sources:
            if not isinstance(leak, dict):
                continue
            # A leak indexed while paging can show up again on the next page.
            leak_id = clean(leak.get("id_source") or leak.get("id"))
            if not leak_id or leak_id in seen:
                continue
            seen.add(leak_id)
            leak_type = clean(leak.get("leak_type"))
            category = HAVEIBEENRANSOM_CATEGORIES.get(leak_type, leak_type or "leak")
            records.append(make_record(HAVEIBEENRANSOM, category, leak))
        if len(records) >= max_records:
            return records[:max_records], len(records) > max_records or has_next_page(data)
        if not has_next_page(data):
            return records, False
    return records, True


def search_breach_house(client: ProductClient, domain: str, limit: int, max_records: int) -> tuple[list[dict[str, str]], bool]:
    """Cross-source search, one request. Returns (records, truncated)."""
    data = client.get_json("/api/v1/search", params={"q": domain, "limit": limit})
    records: list[dict[str, str]] = []
    truncated = False
    for section_name, category in BREACH_HOUSE_CATEGORIES.items():
        section = data.get(section_name)
        if isinstance(section, list):
            results, total = section, None
        elif isinstance(section, dict) and isinstance(section.get("results"), list):
            results, total = section["results"], section.get("total")
        else:
            continue
        if len(results) >= limit or (isinstance(total, int) and total > len(results)):
            truncated = True
        for item in results:
            if isinstance(item, dict):
                record = make_record(BREACH_HOUSE, category, item)
                if is_about(record, domain):
                    records.append(record)
    if len(records) > max_records:
        return records[:max_records], True
    return records, truncated


def build_lookups(params: dict[str, Any]) -> list[tuple[str, ProductClient]]:
    verify = not argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))
    hibr_key = ((params.get("haveibeenransom_credentials") or {}).get("password") or "").strip()
    bh_key = ((params.get("breachhouse_credentials") or {}).get("password") or "").strip()
    lookups = []
    if hibr_key:
        lookups.append((HAVEIBEENRANSOM, ProductClient(HAVEIBEENRANSOM, HAVEIBEENRANSOM_URL, hibr_key, verify, proxy)))
    if bh_key:
        lookups.append((BREACH_HOUSE, ProductClient(BREACH_HOUSE, BREACH_HOUSE_URL, bh_key, verify, proxy)))
    if not lookups:
        raise DemistoException("Configure a HaveIBeenRansom API key, a Breach House API key or both.")
    return lookups


""" COMMAND FUNCTIONS """


def test_module(lookups: list[tuple[str, ProductClient]]) -> str:
    """Checks every configured key. HaveIBeenRansom has no account endpoint, so it runs one domain search."""
    for product, client in lookups:
        try:
            if product == HAVEIBEENRANSOM:
                client.get_json("/api/metadata/domain/example.com")
            else:
                client.get_json("/api/v1/me")
        except DarkEyeProductError as e:
            return str(e)
    return "ok"


def search_domain(lookups: list[tuple[str, ProductClient]], domain: str, args: dict[str, Any]) -> dict[str, Any]:
    max_pages = bounded_int(args.get("max_pages"), DEFAULT_MAX_PAGES, MAX_PAGES_LIMIT)
    max_records = bounded_int(args.get("max_records"), DEFAULT_MAX_RECORDS, MAX_RECORDS_LIMIT)
    limit = bounded_int(args.get("limit"), DEFAULT_LIMIT, BREACH_HOUSE_MAX_LIMIT)

    records: list[dict[str, str]] = []
    answered: list[str] = []
    errors: list[dict[str, str]] = []
    truncated = False
    for product, client in lookups:
        try:
            if product == HAVEIBEENRANSOM:
                product_records, product_truncated = search_haveibeenransom(client, domain, max_pages, max_records)
            else:
                product_records, product_truncated = search_breach_house(client, domain, limit, max_records)
        except DarkEyeProductError as e:
            demisto.debug(f"{INTEGRATION_NAME}: {e}")
            errors.append({"Product": product, "Error": str(e)})
            continue
        answered.append(product)
        records.extend(product_records)
        truncated = truncated or product_truncated

    if not answered:
        # An empty result would read as "nothing found" when no product answered.
        raise DemistoException(" ".join(error["Error"] for error in errors))

    counts_by_product = dict.fromkeys(answered, 0)
    counts_by_category: dict[str, int] = {}
    for record in records:
        counts_by_product[record["Product"]] += 1
        counts_by_category[record["Category"]] = counts_by_category.get(record["Category"], 0) + 1

    return {
        "Name": domain,
        "Found": bool(records),
        "Count": len(records),
        "Products": answered,
        "CountsByProduct": counts_by_product,
        "CountsByCategory": counts_by_category,
        "Truncated": truncated,
        "Errors": errors,
        "Records": records,
    }


def readable_result(result: dict[str, Any]) -> str:
    summary = f"{result['Count']}{'+' if result['Truncated'] else ''} record(s) for {result['Name']}"
    summary += f" from {', '.join(result['Products'])}."
    output = f"### DarkEye search for {result['Name']}\n{summary}\n"
    if result["Errors"]:
        output += "\n" + tableToMarkdown("Products that failed", result["Errors"], headers=["Product", "Error"])
    if result["Records"]:
        output += "\n" + tableToMarkdown("Records", result["Records"], headers=RECORD_HEADERS, removeNull=True)
    return output


def domain_search_command(lookups: list[tuple[str, ProductClient]], args: dict[str, Any]) -> list[CommandResults]:
    domains = argToList(args.get("domain"))
    if not domains:
        raise DemistoException("The domain argument is required.")
    results = []
    for value in domains:
        result = search_domain(lookups, normalize_domain(value), args)
        results.append(
            CommandResults(
                outputs_prefix="DarkEye.Domain",
                outputs_key_field="Name",
                outputs=result,
                readable_output=readable_result(result),
                raw_response=result,
            )
        )
    return results


""" MAIN FUNCTION """


def main() -> None:  # pragma: no cover
    command = demisto.command()
    demisto.debug(f"Command being called is {command}")
    try:
        lookups = build_lookups(demisto.params())
        if command == "test-module":
            return_results(test_module(lookups))
        elif command == "darkeye-domain-search":
            return_results(domain_search_command(lookups, demisto.args()))
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{e}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
