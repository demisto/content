import demistomock as demisto
from CommonServerPython import *
from collections import OrderedDict

""" CONSTANTS """

TAXII_API_ROOT = "externalApi/taxii"
TOKEN_URL_SUFFIX = "externalApi/v2/realm/{account_id}/token"
TOKEN_SCOPE = "externalAPI/stix.readonly"
TOKEN_REFRESH_MARGIN_SEC = 60
TAXII_PAGE_LIMIT = 9999
# Sliding-window fetch: batches of PAGES_PER_BATCH pages, a window of
# [prev, center, next] batches for reference resolution, plus a bounded LRU
# of hydrated objects for references outside the window. At ~15MB per page
# in memory, 4 pages/batch x 3 batches + a 50k-object LRU stays under ~300MB.
PAGES_PER_BATCH = 4
HYDRATED_OBJECTS_MAX_SIZE = 50000
MATCH_ID_BATCH_SIZE = 100
# Abort stale-cursor recovery after this many consecutive rebuilds that fail
# to advance X-TAXII-Date-Added-Last (guards against a no-progress loop).
MAX_STALE_REBUILDS_WITHOUT_PROGRESS = 5
# Effectively no request timeout - fetches of old data can take a long
# time; a request runs until it succeeds or errors out.
REQUESTS_TIMEOUT_SEC = 86400
DUMMY_INDICATOR_VALUE = "$$DummyIndicator$$"
DATE_ADDED_LAST_HEADER = "X-TAXII-Date-Added-Last"
LEAKED_CREDENTIAL = "LEAKED CREDENTIAL"
# The Luminar TAXII collections that are always fetched.
IOCS_COLLECTION = "IOCs"
LEAKED_RECORDS_COLLECTION = "Leaked Records"
COLLECTION_TITLES = [IOCS_COLLECTION, LEAKED_RECORDS_COLLECTION]

# Every field this integration can populate, mapped to its empty value.
# XSOAR merges fields on re-create, so a field absent from the latest STIX
# object is sent empty to clear the stale value. Text -> "", list -> [],
# number -> 0, boolean -> False.
LUMINAR_FIELD_DEFAULTS = {
    "stixid": "",
    "confidence": "",
    "creationdate": "",
    "updateddate": "",
    "validfrom": "",
    "description": "",
    "shortdescription": "",
    "trafficlightprotocol": "",
    "asn": "",
    "geocountry": "",
    "region": "",
    "countrycode": "",
    "version": "",
    "category": "",
    "accounttype": "",
    "username": "",
    "displayname": "",
    "emailaddress": "",
    "actor": "",
    "malwarefamily": "",
    "md5": "",
    "sha1": "",
    "sha256": "",
    "sha512": "",
    "ssdeep": "",
    "luminarcity": "",
    "luminarcollectiondate": "",
    "luminarcomputername": "",
    "luminarconvictionreasons": "",
    "luminarincidentname": "",
    "luminarincidentdescription": "",
    "luminariptype": "",
    "luminarlastseen": "",
    "luminarleakedcredential": "",
    "luminarleaksource": "",
    "luminarleakurl": "",
    "luminarmitreids": "",
    "luminarmonitoringplanterms": "",
    "luminarprotocols": "",
    "luminarresolvingdomains": "",
    "luminartargetedindustries": "",
    "luminartargetedlocations": "",
    "luminartargetedsystems": "",
    "luminarthreattypes": "",
    "luminarvaliduntil": "",
    "tags": [],
    "aliases": [],
    "identityclass": [],
    "reportedby": [],
    "luminarscore": 0,
    "luminarthreatscore": 0,
    "luminarcloudprovider": False,
    "luminarcredentialisfresh": False,
}

# Title-case labels for war-room table headers (mirrors the IndicatorFields
# display names). Related '<stix-type>-<field>' columns are rendered by
# header_label() as 'Threat Actor - Aliases'.
HEADER_LABELS = {
    "type": "Type",
    "value": "Value",
    "occurred": "Occurred",
    "stixid": "STIX ID",
    "confidence": "Confidence",
    "creationdate": "Creation Date",
    "updateddate": "Updated Date",
    "validfrom": "Valid From",
    "description": "Description",
    "shortdescription": "Short Description",
    "trafficlightprotocol": "TLP",
    "asn": "ASN",
    "geocountry": "Geo Country",
    "region": "Region",
    "countrycode": "Country Code",
    "version": "Version",
    "category": "Category",
    "accounttype": "Account Type",
    "username": "Username",
    "displayname": "Display Name",
    "emailaddress": "Email Address",
    "actor": "Actor",
    "malwarefamily": "Malware Family",
    "md5": "MD5",
    "sha1": "SHA1",
    "sha256": "SHA256",
    "sha512": "SHA512",
    "ssdeep": "SSDeep",
    "tags": "Tags",
    "aliases": "Aliases",
    "identityclass": "Identity Class",
    "reportedby": "Reported By",
    "ismalwarefamily": "Is Malware Family",
    "comment": "Comment",
    "name": "Name",
    "relationship": "Relationship",
    "is_family": "Is Family",
    "luminar_threat_score": "Luminar Threat Score",
    "collection_date": "Collection Date",
    "computer_name": "Computer Name",
    "luminarcity": "Luminar City",
    "luminarcloudprovider": "Luminar Cloud Provider",
    "luminarcollectiondate": "Luminar Collection Date",
    "luminarcomputername": "Luminar Computer Name",
    "luminarconvictionreasons": "Luminar Conviction Reasons",
    "luminarcredentialisfresh": "Luminar Credential Is Fresh",
    "luminarincidentname": "Luminar Incident Name",
    "luminarincidentdescription": "Luminar Incident Description",
    "luminariptype": "Luminar IP Type",
    "luminarlastseen": "Luminar Last Seen",
    "luminarleakedcredential": "Luminar Leaked Credential",
    "luminarleaksource": "Luminar Leak Source",
    "luminarleakurl": "Luminar Leak URL",
    "luminarmitreids": "Luminar MITRE ATT&CK IDs",
    "luminarmonitoringplanterms": "Luminar Monitoring Plan Terms",
    "luminarprotocols": "Luminar Protocols",
    "luminarresolvingdomains": "Luminar Resolving Domains",
    "luminarscore": "Luminar Score",
    "luminartargetedindustries": "Luminar Targeted Industries",
    "luminartargetedlocations": "Luminar Targeted Locations",
    "luminartargetedsystems": "Luminar Targeted Systems",
    "luminarthreatscore": "Luminar Threat Score",
    "luminarthreattypes": "Luminar Threat Types",
    "luminarvaliduntil": "Luminar Valid Until",
}

# STIX pattern term parser: (object-type):(property) <op> '<value>'
# Handles single/double-quoted and unquoted values and multi-term
# (AND/OR) patterns - the first term is used as the indicator value.
STIX_PATTERN_TERM = re.compile(
    r"([\w-]+):([\w'.\[\]-]+?)\s*(?:[=!><]=?|IN|MATCHES|LIKE|ISSUBSET|ISSUPERSET)\s*" r"(?:'(.*?)'|\"(.*?)\"|([^\s\]]+))"
)

# STIX object-type -> Cortex XSOAR indicator type (for SCOs / patterns)
STIX_TYPE_TO_XSOAR_TYPE = {
    "ipv4-addr": FeedIndicatorType.IP,
    "ipv6-addr": FeedIndicatorType.IPv6,
    "domain-name": FeedIndicatorType.Domain,
    "url": FeedIndicatorType.URL,
    "email-addr": FeedIndicatorType.Email,
    "user-account": FeedIndicatorType.Account,
    "windows-registry-key": FeedIndicatorType.Registry,
    "mutex": FeedIndicatorType.MUTEX,
    "autonomous-system": FeedIndicatorType.AS,
    "file": FeedIndicatorType.File,
    "identity": FeedIndicatorType.Identity,
    "location": FeedIndicatorType.Location,
    "software": FeedIndicatorType.Software,
    "malware": ThreatIntel.ObjectsNames.MALWARE,
    "threat-actor": ThreatIntel.ObjectsNames.THREAT_ACTOR,
    "tool": ThreatIntel.ObjectsNames.TOOL,
    "attack-pattern": ThreatIntel.ObjectsNames.ATTACK_PATTERN,
    "campaign": ThreatIntel.ObjectsNames.CAMPAIGN,
    "infrastructure": ThreatIntel.ObjectsNames.INFRASTRUCTURE,
    "intrusion-set": ThreatIntel.ObjectsNames.INTRUSION_SET,
    "report": ThreatIntel.ObjectsNames.REPORT,
    "course-of-action": ThreatIntel.ObjectsNames.COURSE_OF_ACTION,
    "vulnerability": FeedIndicatorType.CVE,
    "incident": "Luminar Incident",
}

# File hash property names inside a file pattern -> XSOAR File hash fields
FILE_HASH_FIELDS = {
    "md5": "md5",
    "sha-1": "sha1",
    "sha1": "sha1",
    "sha-256": "sha256",
    "sha256": "sha256",
    "sha-512": "sha512",
    "sha512": "sha512",
    "ssdeep": "ssdeep",
}

# STIX relationship_type -> XSOAR relationship name.
# STIX "indicates" (indicator -> target) maps to "indicator-of".
STIX_RELATIONSHIP_TO_XSOAR = {
    "indicates": EntityRelationship.Relationships.INDICATOR_OF,
    "originates-from": EntityRelationship.Relationships.ORIGINATED_FROM,
}

# Allowed relations for IOC comment rendering, by source STIX type.
# Only comments are filtered by this map; created relationship edges are not.
COMMENT_RELATION_ALLOWLIST = {
    "indicator": {
        "indicates": {"threat-actor", "malware", "software"},
        "related-to": {"location", "identity"},
    },
}

# STIX object types that never produce a Cortex XSOAR indicator
NON_INDICATOR_TYPES = {"relationship", "extension-definition", "directory", "marking-definition"}

# STIX domain object types (named entities) - shown only as related columns
# in the war-room commands, not as rows.
SDO_STIX_TYPES = {
    "malware",
    "threat-actor",
    "identity",
    "location",
    "software",
    "tool",
    "attack-pattern",
    "campaign",
    "infrastructure",
    "intrusion-set",
    "report",
    "course-of-action",
    "vulnerability",
    "incident",
}

# Fields dropped from related-object columns - redundant or constant noise
# (the column prefix already carries the type, reportedby is always Luminar).
RELATED_DROP_FIELDS = {
    "Type",
    "Occurred",
    "creationdate",
    "updateddate",
    "firstseenbysource",
    "lastseenbysource",
    "reportedby",
    "created",
    "modified",
}

# XSOAR indicator types the standard 'shortdescription' field is associated to
SHORT_DESCRIPTION_TYPES = {
    FeedIndicatorType.IP,
    FeedIndicatorType.File,
    FeedIndicatorType.URL,
    ThreatIntel.ObjectsNames.MALWARE,
    ThreatIntel.ObjectsNames.TOOL,
    ThreatIntel.ObjectsNames.REPORT,
    ThreatIntel.ObjectsNames.THREAT_ACTOR,
    ThreatIntel.ObjectsNames.CAMPAIGN,
    ThreatIntel.ObjectsNames.COURSE_OF_ACTION,
    ThreatIntel.ObjectsNames.INFRASTRUCTURE,
    ThreatIntel.ObjectsNames.INTRUSION_SET,
    ThreatIntel.ObjectsNames.ATTACK_PATTERN,
}


class PaginationExpiredError(Exception):
    """Raised when the TAXII server answers 410 Expired pagination token."""


class LuminarAuthError(Exception):
    """Raised when authentication against the Luminar API fails."""


""" CLIENT """


class Client(BaseClient):
    """Client for the Luminar external API (OAuth2 + TAXII 2.1)."""

    def __init__(
        self,
        base_url: str,
        account_id: str,
        client_id: str,
        client_secret: str,
        verify: bool = True,
        proxy: bool = False,
        tags: Optional[list] = None,
        tlp_color: Optional[str] = None,
    ):
        super().__init__(base_url=base_url.rstrip("/"), verify=verify, proxy=proxy, timeout=REQUESTS_TIMEOUT_SEC)
        self.account_id = account_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.feed_tags = tags or []
        self.tlp_color = tlp_color
        self._access_token: Optional[str] = None
        self._token_expiry: float = 0
        # Bounded LRU of cross-batch referenced objects (sliding-window fetch).
        self.hydrated_objects: OrderedDict = OrderedDict()

    def fetch_access_token(self) -> str:
        """Fetch (and cache) an OAuth2 access token using client credentials."""
        if self._access_token and time.time() < self._token_expiry - TOKEN_REFRESH_MARGIN_SEC:
            return self._access_token

        url_suffix = TOKEN_URL_SUFFIX.format(account_id=self.account_id)
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "grant_type": "client_credentials",
            "scope": TOKEN_SCOPE,
        }
        try:
            response = self._http_request(
                "POST",
                url_suffix,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                resp_type="json",
            )
        except DemistoException as e:
            status = getattr(getattr(e, "res", None), "status_code", None)
            if status == 404:
                raise LuminarAuthError(
                    "Luminar realm does not exist - check the 'Luminar API Account ID' " "and 'Luminar Base URL' parameters."
                ) from e
            raise LuminarAuthError(f"Authentication with the Luminar API failed ({e}).") from e

        token = response.get("access_token")
        if not token:
            raise LuminarAuthError("Luminar token endpoint did not return an access_token.")
        self._access_token = token
        expires_in = arg_to_number(response.get("expires_in"), "expires_in") or 3600
        self._token_expiry = time.time() + expires_in
        return token

    def _taxii_headers(self) -> dict:
        # NOTE: the Luminar TAXII API answers 406 if Content-Type/Accept
        # application/json headers are sent - only Authorization is allowed.
        return {"Authorization": f"Bearer {self.fetch_access_token()}"}

    def get_collections(self) -> list:
        """Return the list of available TAXII collections."""
        response = self._http_request(
            "GET",
            f"{TAXII_API_ROOT}/collections/",
            headers=self._taxii_headers(),
            resp_type="json",
        )
        return response.get("collections", [])

    def resolve_collection_id(self, title: str) -> Optional[str]:
        """Resolve a collection title or alias (e.g. 'IOCs'/'iocs',
        'Leaked Records'/'leakedrecords') to its collection id."""
        wanted = title.strip().lower().replace(" ", "")
        for collection in self.get_collections():
            candidates = (
                str(collection.get("title") or "").strip().lower().replace(" ", ""),
                str(collection.get("alias") or "").strip().lower().replace(" ", ""),
            )
            if wanted in candidates:
                return collection.get("id")
        return None

    def get_objects(
        self,
        collection_id: str,
        added_after: Optional[str] = None,
        next_token: Optional[str] = None,
    ) -> tuple[list, Optional[str], Optional[str]]:
        """
        Fetch a single page of STIX objects from a collection.

        Returns:
            (objects, next_token, x_taxii_date_added_last)
        """
        params: dict[str, Any] = {"limit": TAXII_PAGE_LIMIT}
        if next_token:
            params["next"] = next_token
        elif added_after:
            params["added_after"] = added_after

        try:
            response = self._http_request(
                "GET",
                f"{TAXII_API_ROOT}/collections/{collection_id}/objects/",
                headers=self._taxii_headers(),
                params=params,
                resp_type="response",
                ok_codes=(200,),
            )
        except DemistoException as e:
            status = getattr(getattr(e, "res", None), "status_code", None)
            if status == 410:
                raise PaginationExpiredError(str(e)) from e
            if status == 401:
                # Token rejected or expired - drop it so the next call re-authenticates
                self._access_token = None
                self._token_expiry = 0
                raise
            if status == 403:
                raise LuminarAuthError(
                    "The Luminar token was issued without the 'externalAPI/stix.readonly' "
                    "scope - check the client configuration on the Luminar side."
                ) from e
            raise

        body = response.json()
        return (
            body.get("objects", []),
            body.get("next"),
            response.headers.get(DATE_ADDED_LAST_HEADER),
        )

    def get_objects_by_match_id(self, collection_id: str, object_ids: list) -> list:
        """Fetch objects by STIX id via the TAXII match[id] filter, in chunks.

        Used to hydrate relationship endpoints that were not found inside the
        sliding window or the hydrated-object cache. Failures are non-fatal:
        unresolved refs simply stay unresolved."""
        all_objects: list = []
        url_suffix = f"{TAXII_API_ROOT}/collections/{collection_id}/objects/"
        for i in range(0, len(object_ids), MATCH_ID_BATCH_SIZE):
            chunk = object_ids[i : i + MATCH_ID_BATCH_SIZE]
            try:
                response = self._http_request(
                    "GET",
                    url_suffix,
                    headers=self._taxii_headers(),
                    params={"match[id]": ",".join(chunk), "limit": len(chunk)},
                    resp_type="json",
                )
                objects = response.get("objects", [])
                if isinstance(objects, list):
                    all_objects.extend(o for o in objects if isinstance(o, dict))
            except DemistoException as e:
                demisto.debug(f"match[id] chunk fetch failed for collection {collection_id}: {e}")
                continue
        return all_objects

    def iter_collection_objects(
        self,
        collection_id: str,
        added_after: Optional[str] = None,
    ):
        """
        Iterate over all pages of STIX objects of a collection.

        Yields (objects, x_taxii_date_added_last) per page. When a `next`
        cursor expires (410 'Expired pagination token') pagination resumes
        from `added_after = last_seen - 1s` instead of restarting from the
        original checkpoint, so already-fetched pages are not re-downloaded.
        A stall guard aborts after MAX_STALE_REBUILDS_WITHOUT_PROGRESS
        consecutive rebuilds that fail to advance the last-seen timestamp.
        """
        next_token = None
        current_added_after = added_after
        last_added_seen: Optional[str] = None
        last_added_at_prev_rebuild: Optional[str] = None
        rebuilds_without_progress = 0

        while True:
            try:
                objects, next_token, date_added_last = self.get_objects(
                    collection_id,
                    added_after=current_added_after if not next_token else None,
                    next_token=next_token,
                )
            except PaginationExpiredError as e:
                if last_added_seen and last_added_seen != last_added_at_prev_rebuild:
                    rebuilds_without_progress = 0
                else:
                    rebuilds_without_progress += 1
                last_added_at_prev_rebuild = last_added_seen

                if rebuilds_without_progress >= MAX_STALE_REBUILDS_WITHOUT_PROGRESS:
                    raise DemistoException(
                        f"Stale-cursor recovery made no progress across {rebuilds_without_progress} "
                        f"consecutive rebuilds for collection {collection_id} "
                        f"(last_added={last_added_seen}) - aborting; the saved checkpoint is unchanged."
                    ) from e

                # Resume from the last observed X-TAXII-Date-Added-Last minus a
                # 1-second overlap buffer (sub-second boundary safety). Any
                # duplicate objects this re-fetches are harmless.
                rebuild_anchor = subtract_one_second(last_added_seen) if last_added_seen else current_added_after
                demisto.info(
                    f"Pagination token expired for collection {collection_id}; "
                    f"resuming with added_after={rebuild_anchor} "
                    f"(last_added={last_added_seen} minus 1s buffer)."
                )
                current_added_after = rebuild_anchor
                next_token = None
                continue

            if date_added_last:
                last_added_seen = date_added_last

            yield objects, date_added_last

            if not next_token:
                break

    def iter_page_batches(self, collection_id: str, added_after: Optional[str]):
        """
        Group pages into batches of PAGES_PER_BATCH pages.

        Yields (batch_objects, last_added_seen). The trailing partial batch is
        also yielded. If a page fetch fails mid-iteration, whatever was
        accumulated is yielded before the error propagates so the caller can
        ingest it and checkpoint instead of losing it.
        """
        batch: list = []
        pages_in_batch = 0
        last_added_seen: Optional[str] = None
        page_iter = self.iter_collection_objects(collection_id, added_after)
        while True:
            try:
                page_objects, last_added = next(page_iter)
            except StopIteration:
                break
            except Exception:
                if batch:
                    yield batch, (last_added_seen or added_after)
                raise
            batch.extend(page_objects)
            pages_in_batch += 1
            if last_added:
                last_added_seen = last_added
            if pages_in_batch >= PAGES_PER_BATCH:
                yield batch, (last_added_seen or added_after)
                batch = []
                pages_in_batch = 0
        if batch:
            yield batch, (last_added_seen or added_after)

    def resolve_context(
        self, collection_id: str, target_batch: list, prev_batch: Optional[list], next_batch: Optional[list]
    ) -> list:
        """
        Resolve objects referenced by the target batch's relationships/reports
        that are not in the batch itself, looking up (in order) prev/next
        window batches, the hydrated-object LRU, and match[id] API hydration.

        Returns context objects for the target batch: the resolved objects
        plus the prev/next batches' relationship objects (so indicator
        comments can show second-level relations resolved objects take part
        in). LRU eviction is correctness-safe: everything this batch needs is
        held in the local `resolved` dict, the cache only serves future
        batches.
        """
        target_ids = {o.get("id") for o in target_batch if o.get("id")}
        window = (prev_batch or []) + (next_batch or [])
        window_lookup = {o.get("id"): o for o in window if o.get("id")}
        target_rels = [o for o in target_batch if o.get("type") == "relationship"]
        window_rels = target_rels + [o for o in window if o.get("type") == "relationship"]

        def other_end(rel: dict, ids: set) -> Optional[str]:
            source_ref, target_ref = rel.get("source_ref"), rel.get("target_ref")
            if source_ref in ids:
                return target_ref
            if target_ref in ids:
                return source_ref
            return None

        # Endpoints of the target batch's own relationships (for the dummy
        # relationship indicator), of window relationships touching target
        # objects (level 1, for comments), and of relationships touching those
        # endpoints (level 2, so comments can show nested relations like
        # threat-actor 'targets' location).
        target_rel_ends = {r.get(k) for r in target_rels for k in ("source_ref", "target_ref") if r.get(k)}
        level1 = {e for r in window_rels if (e := other_end(r, target_ids))} - target_ids
        level2 = {e for r in window_rels if (e := other_end(r, level1))} - target_ids - level1
        needed = target_rel_ends | level1 | level2
        for record in target_batch:
            if record.get("type") == "report":
                needed.update(record.get("object_refs") or [])
        needed -= target_ids

        resolved: dict = {}
        missing = []
        for oid in needed:
            if oid in window_lookup:
                resolved[oid] = window_lookup[oid]
            elif oid in self.hydrated_objects:
                self.hydrated_objects.move_to_end(oid)
                resolved[oid] = self.hydrated_objects[oid]
            else:
                missing.append(oid)

        if missing:
            demisto.debug(f"Hydrating {len(missing)} referenced ids via match[id] for collection {collection_id}.")
            for obj in self.get_objects_by_match_id(collection_id, missing):
                oid = obj.get("id")
                if oid:
                    resolved[oid] = obj

        for oid, obj in resolved.items():
            if oid in self.hydrated_objects:
                self.hydrated_objects.move_to_end(oid)
            self.hydrated_objects[oid] = obj
            while self.hydrated_objects and len(self.hydrated_objects) > HYDRATED_OBJECTS_MAX_SIZE:
                evicted_id, _ = self.hydrated_objects.popitem(last=False)
                demisto.debug(f"Hydrated-object cache evicted least-recently-used id={evicted_id}")

        context = list(resolved.values())
        context += [o for o in window if o.get("type") == "relationship"]
        return context

    def iter_resolved_batches(self, collection_id: str, added_after: Optional[str]):
        """
        Sliding-window fetch of a collection, bounded memory.

        Holds at most 3 batches ([prev, center, next]) plus the hydrated-object
        LRU. Yields (target_objects, context_objects, last_added) per batch:

          - target: the batch's own objects - these get turned into indicators
          - context: referenced objects resolved from the window/LRU/match[id]
                     plus window relationship objects - used for comments and
                     enrichment, not turned into indicators again
          - last_added: X-TAXII-Date-Added-Last of the target batch, for
                        per-batch checkpointing

        On a mid-run fetch error the batches already in memory are still
        yielded before the error propagates, so progress is never lost.
        """
        self.hydrated_objects.clear()
        batch_iter = self.iter_page_batches(collection_id, added_after)
        batches: list = []
        lasts: list = []
        exhausted = False
        pending_error: Optional[Exception] = None

        # Preload up to 3 batches.
        for _ in range(3):
            try:
                b, last_added = next(batch_iter)
                batches.append(b)
                lasts.append(last_added)
            except StopIteration:
                exhausted = True
                break
            except Exception as e:
                pending_error = e
                exhausted = True
                break

        if not batches:
            if pending_error:
                raise pending_error
            return

        # Small dataset (<=3 batches): merge and resolve in one shot.
        if exhausted:
            merged = [o for b in batches for o in b]
            yield merged, self.resolve_context(collection_id, merged, None, None), lasts[-1]
            if pending_error:
                raise pending_error
            return

        prev, center, nxt = batches

        # Startup: resolve the first batch using the next two as context.
        yield prev, self.resolve_context(collection_id, prev, None, center + nxt), lasts[0]

        # Steady state: yield each center batch once, with prev+next context.
        idx = 1
        while True:
            yield center, self.resolve_context(collection_id, center, prev, nxt), lasts[idx]
            prev = center
            center = nxt
            idx += 1
            try:
                nxt, last_added = next(batch_iter)
                lasts.append(last_added)
            except StopIteration:
                # Tail: the last batch still needs yielding, with prev context.
                yield center, self.resolve_context(collection_id, center, prev, None), lasts[idx]
                break
            except Exception:
                # Flush the last in-memory batch, then propagate the error.
                yield center, self.resolve_context(collection_id, center, prev, None), lasts[idx]
                raise


""" STIX HELPERS """


def to_csv(value) -> Any:
    """Join list values into a comma-separated string for text-type fields."""
    if value is None:
        return None
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return str(value)


def get_extension_fields(stix_object: dict) -> dict:
    """Flatten the Luminar property-extension block into a plain dict."""
    flat: dict = {}
    for ext_data in (stix_object.get("extensions") or {}).values():
        if isinstance(ext_data, dict) and ext_data.get("extension_type") == "property-extension":
            for key, value in ext_data.items():
                if key not in ("extension_type", "luminar_tenant_id"):
                    flat[key] = value
    return flat


def parse_stix_pattern(pattern: str) -> list:
    """
    Parse a STIX pattern into a list of (stix_type, property_path, value) tuples.
    Only simple equality patterns are produced by Luminar; for multi-term
    patterns the first term wins downstream.
    """
    if not pattern:
        return []

    terms = []
    for m in STIX_PATTERN_TERM.finditer(pattern):
        value = next((g for g in m.groups()[2:] if g is not None), "")
        terms.append((m.group(1).lower(), m.group(2).strip().strip("'"), value.strip().rstrip("]")))

    # Fallback for trivially simple patterns the regex may have missed
    if not terms and pattern.startswith("[") and pattern.endswith("]"):
        inner = pattern[1:-1]
        if "=" in inner:
            lhs, rhs = inner.split("=", 1)
            if ":" in lhs:
                stix_type, prop = lhs.split(":", 1)
                terms.append((stix_type.strip().lower(), prop.strip(), rhs.strip().strip("'\"")))

    return terms


def get_indicator_type_and_value(stix_object: dict) -> tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Resolve (xsoar_type, value, file_hash_field) from an indicator's pattern
    or from a SCO object.
    """
    stix_type = stix_object.get("type", "")

    if stix_type == "indicator":
        for term_type, prop, value in parse_stix_pattern(stix_object.get("pattern", "")):
            if term_type == "file":
                hash_key = prop.split(".")[-1].strip("'").lower()
                if hash_key in FILE_HASH_FIELDS:
                    return FeedIndicatorType.File, value, FILE_HASH_FIELDS[hash_key]
                continue
            if term_type in ("ipv4-addr", "ipv6-addr"):
                ip_type = FeedIndicatorType.ip_to_indicator_type(value)
                return ip_type or STIX_TYPE_TO_XSOAR_TYPE[term_type], value, None
            xsoar_type = STIX_TYPE_TO_XSOAR_TYPE.get(term_type)
            if xsoar_type:
                return xsoar_type, value, None
        return None, None, None

    # Plain STIX cyber-observables (SCOs) such as ipv4-addr, url, file
    if stix_type in ("ipv4-addr", "ipv6-addr"):
        value = stix_object.get("value")
        if not value:
            return None, None, None
        return FeedIndicatorType.ip_to_indicator_type(value) or STIX_TYPE_TO_XSOAR_TYPE[stix_type], value, None
    if stix_type == "file":
        hashes = stix_object.get("hashes") or {}
        for hash_name, field in FILE_HASH_FIELDS.items():
            if hash_name.lower() in {k.lower() for k in hashes}:
                hash_value = next(v for k, v in hashes.items() if k.lower() == hash_name.lower())
                return FeedIndicatorType.File, hash_value, field
        return None, None, None
    if stix_type in STIX_TYPE_TO_XSOAR_TYPE:
        value = (
            stix_object.get("value")
            or stix_object.get("name")
            or stix_object.get("account_login")
            or stix_object.get("country")
            or stix_object.get("city")
        )
        return STIX_TYPE_TO_XSOAR_TYPE[stix_type], value, None

    return None, None, None


def get_entity_value_and_type(stix_object: dict) -> tuple[Optional[str], Optional[str]]:
    """Resolve the XSOAR (value, type) of a STIX object for relationship ends."""
    stix_type = stix_object.get("type", "")
    if stix_type == "user-account":
        return stix_object.get("account_login") or stix_object.get("display_name"), FeedIndicatorType.Account
    xsoar_type, value, _ = get_indicator_type_and_value(stix_object)
    return value, xsoar_type


def get_external_reference_ids(stix_object: dict) -> list:
    """Extract external references as 'source_name:external_id' pairs
    (e.g. 'mitre-attack:T1071')."""
    return [
        f"{ref.get('source_name')}:{ref['external_id']}"
        for ref in stix_object.get("external_references") or []
        if ref.get("source_name") and ref.get("external_id")
    ]


def build_common_fields(stix_object: dict, feed_tags: list, tlp_color: Optional[str], ext: Optional[dict] = None) -> dict:
    """Fields shared by every indicator created from a STIX object."""
    ext = ext if ext is not None else get_extension_fields(stix_object)
    fields: dict[str, Any] = {
        "stixid": stix_object.get("id"),
        "confidence": str(stix_object.get("confidence", "")) if stix_object.get("confidence") is not None else None,
        "creationdate": stix_object.get("created"),
        "updateddate": stix_object.get("modified"),
        "description": stix_object.get("description"),
        "reportedby": ["Luminar"],
        "tags": list(feed_tags),
        "luminarcollectiondate": ext.get("collection_date"),
        "validfrom": stix_object.get("valid_from"),
    }
    if tlp_color:
        fields["trafficlightprotocol"] = tlp_color
    return {k: v for k, v in fields.items() if v not in (None, "", [])}


def build_indicator_from_stix(stix_object: dict, feed_tags: list, tlp_color: Optional[str]) -> Optional[dict]:
    """Create a Cortex XSOAR indicator dict from a STIX 'indicator' or SCO object."""
    xsoar_type, value, hash_field = get_indicator_type_and_value(stix_object)
    if not xsoar_type or not value:
        demisto.debug(f"Skipping STIX object {stix_object.get('id')} - could not resolve indicator value/type.")
        return None

    ext = get_extension_fields(stix_object)
    fields = build_common_fields(stix_object, feed_tags, tlp_color, ext)

    tags = list(
        dict.fromkeys(
            (stix_object.get("labels") or [])
            + (ext.get("threat_types") or [])
            + (ext.get("conviction_reasons") or [])
            + feed_tags
        )
    )
    if tags:
        fields["tags"] = tags

    targeted_systems = (
        (ext.get("targeted_system_names") or [])
        + (ext.get("targeted_system_types") or [])
        + (ext.get("targeted_system_versions") or [])
    )

    extra_fields = {
        "actor": ext.get("threat_actors"),
        "malwarefamily": ext.get("malware_names"),
        "luminarscore": ext.get("score"),
        "luminarvaliduntil": stix_object.get("valid_until"),
        "luminarresolvingdomains": to_csv(ext.get("resolving_domains")),
        "luminarconvictionreasons": to_csv(ext.get("conviction_reasons")),
        "luminarprotocols": to_csv(ext.get("protocols")),
        "luminarthreattypes": to_csv(ext.get("threat_types")),
        "luminartargetedsystems": to_csv(targeted_systems),
        "luminartargetedlocations": to_csv(ext.get("targeted_locations")),
        "luminartargetedindustries": to_csv(ext.get("targeted_industries")),
        "luminarcloudprovider": ext.get("cloud_provider"),
        "luminarmitreids": to_csv(get_external_reference_ids(stix_object)),
        "luminariptype": ext.get("ip_type"),
        "luminarlastseen": ext.get("last_seen"),
    }
    if hash_field:
        extra_fields[hash_field] = value
    if ext.get("malware_names"):
        extra_fields["category"] = "Malware"
    if xsoar_type in SHORT_DESCRIPTION_TYPES and stix_object.get("description"):
        extra_fields["shortdescription"] = stix_object["description"]

    # These standard fields are only associated to specific network indicator types
    if xsoar_type in (FeedIndicatorType.IP, FeedIndicatorType.IPv6, FeedIndicatorType.URL):
        extra_fields["asn"] = to_csv(ext.get("asn"))
        extra_fields["geocountry"] = to_csv(ext.get("country"))
    if xsoar_type in (FeedIndicatorType.IP, FeedIndicatorType.IPv6, FeedIndicatorType.CIDR, FeedIndicatorType.IPv6CIDR):
        extra_fields["region"] = to_csv(ext.get("region"))

    fields.update({k: v for k, v in extra_fields.items() if v not in (None, "", [])})

    raw_json = dict(stix_object)
    raw_json["value"] = value
    indicator = {
        "value": value,
        "type": xsoar_type,
        "rawJSON": raw_json,
        "fields": fields,
    }
    occurred = stix_object.get("valid_from") or stix_object.get("created")
    if occurred:
        indicator["occurred"] = occurred
    return indicator


def build_sdo_indicator(stix_object: dict, feed_tags: list, tlp_color: Optional[str]) -> Optional[dict]:
    """Create an indicator from a STIX domain object (malware, threat-actor,
    identity, location, software, tool, incident, ...)."""
    stix_type = stix_object.get("type", "")
    xsoar_type = STIX_TYPE_TO_XSOAR_TYPE.get(stix_type)
    value = stix_object.get("name") or stix_object.get("country")
    if not xsoar_type or not value:
        return None

    ext = get_extension_fields(stix_object)
    fields = build_common_fields(stix_object, feed_tags, tlp_color, ext)
    fields["tags"] = list(dict.fromkeys((stix_object.get("labels") or []) + feed_tags)) or fields.get("tags")

    if stix_type == "malware":
        fields["ismalwarefamily"] = bool(stix_object.get("is_family"))
        malware_tags = (stix_object.get("malware_types") or []) + (stix_object.get("capabilities") or [])
        if malware_tags:
            fields["tags"] = list(dict.fromkeys((fields.get("tags") or []) + malware_tags))
        if stix_object.get("aliases"):
            fields["aliases"] = stix_object["aliases"]
    elif stix_type == "threat-actor":
        if stix_object.get("aliases"):
            fields["aliases"] = stix_object["aliases"]
        if stix_object.get("threat_actor_types"):
            fields["tags"] = list(dict.fromkeys((fields.get("tags") or []) + stix_object["threat_actor_types"]))
    elif stix_type == "identity":
        if stix_object.get("identity_class"):
            fields["identityclass"] = [stix_object["identity_class"]]
    elif stix_type == "location":
        if stix_object.get("country"):
            fields["countrycode"] = stix_object["country"]
        if stix_object.get("city"):
            fields["luminarcity"] = stix_object["city"]
    elif stix_type == "software":
        if stix_object.get("version"):
            fields["version"] = stix_object["version"]
    elif stix_type == "incident":
        if ext.get("luminar_threat_score") is not None:
            fields["luminarthreatscore"] = ext["luminar_threat_score"]
        if ext.get("computer_name"):
            fields["luminarcomputername"] = ext["computer_name"]

    if xsoar_type in SHORT_DESCRIPTION_TYPES and stix_object.get("description"):
        fields["shortdescription"] = stix_object["description"]

    external_reference_ids = get_external_reference_ids(stix_object)
    if external_reference_ids:
        fields["luminarmitreids"] = to_csv(external_reference_ids)

    raw_json = dict(stix_object)
    raw_json["value"] = value
    indicator = {
        "value": value,
        "type": xsoar_type,
        "rawJSON": raw_json,
        "fields": fields,
    }
    if stix_object.get("created"):
        indicator["occurred"] = stix_object["created"]
    return indicator


""" LIGHT OBJECT INDEX

Per-batch light index of STIX objects (id -> type/name/value) plus light
relationship records, used to resolve comments and relationship endpoints
without keeping full objects around.
"""


def index_object(obj: dict, light_map: dict, incident_map: dict, rel_records: list) -> None:
    """Index one STIX object into the light structures.

    light_map:   id -> (stix_type, display_name, xsoar_value, xsoar_type)
    incident_map: id -> full incident object (needed to enrich accounts)
    rel_records: list of light relationship dicts."""
    obj_type = obj.get("type", "")
    obj_id = obj.get("id")
    if obj_type == "relationship":
        rel_records.append(
            {
                "source_ref": obj.get("source_ref"),
                "target_ref": obj.get("target_ref"),
                "relationship_type": obj.get("relationship_type"),
                "created": obj.get("created"),
                "modified": obj.get("modified"),
            }
        )
        return
    if not obj_id or obj_type in ("marking-definition", "extension-definition"):
        return
    if obj_type == "incident":
        incident_map[obj_id] = obj
    xvalue, xtype = get_entity_value_and_type(obj)
    name = obj.get("name") or obj.get("value") or obj.get("account_login") or obj.get("country") or obj.get("city")
    light_map[obj_id] = (obj_type, name, xvalue, xtype)


def index_objects(objects: list) -> tuple[dict, dict, list]:
    """Build (light_map, incident_map, rel_records) for a list of objects."""
    light_map: dict = {}
    incident_map: dict = {}
    rel_records: list = []
    for obj in objects:
        index_object(obj, light_map, incident_map, rel_records)
    return light_map, incident_map, rel_records


def iter_related_ids(stix_id: str, rel_records: list):
    """Yield (relationship_type, other_stix_id) for every relationship the
    STIX object takes part in (both directions), deduplicated."""
    seen = set()
    for rel in rel_records:
        source_ref, target_ref = rel.get("source_ref"), rel.get("target_ref")
        if source_ref == stix_id:
            other_id = target_ref
        elif target_ref == stix_id:
            other_id = source_ref
        else:
            continue
        dedup_key = (other_id, rel.get("relationship_type"))
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        yield rel.get("relationship_type") or "related-to", other_id


def find_related_incident(account_id: str, rel_records: list, incident_map: dict) -> Optional[dict]:
    """Find the incident object related to a user-account object."""
    for _rel_type, other_id in iter_related_ids(account_id, rel_records):
        incident = incident_map.get(other_id)
        if incident and incident.get("type") == "incident":
            return incident
    return None


def build_account_indicator(
    stix_object: dict,
    incident: Optional[dict],
    feed_tags: list,
    tlp_color: Optional[str],
) -> Optional[dict]:
    """Create an Account indicator from a leaked-credential user-account object."""
    ext = get_extension_fields(stix_object)
    value = stix_object.get("account_login") or stix_object.get("display_name")
    if not value:
        demisto.debug(f"Skipping user-account {stix_object.get('id')} - no account_login.")
        return None

    tags = [LEAKED_CREDENTIAL] + list(feed_tags)
    if stix_object.get("credential"):
        tags.append(f'Credentials:{stix_object["credential"]}')
    fields = build_common_fields(stix_object, feed_tags, tlp_color, ext)
    fields.update(
        {
            "tags": tags,
            "category": LEAKED_CREDENTIAL,
            "accounttype": LEAKED_CREDENTIAL,
            "username": stix_object.get("account_login"),
            "displayname": stix_object.get("display_name"),
            "emailaddress": stix_object.get("display_name"),
            "luminarleakedcredential": stix_object.get("credential"),
            "luminarleaksource": ext.get("source"),
            "luminarleakurl": ext.get("url"),
            "luminarmonitoringplanterms": to_csv(ext.get("monitoring_plan_terms")),
            "luminarcredentialisfresh": ext.get("credential_is_fresh"),
        }
    )

    occurred = stix_object.get("created")
    if incident:
        # Follow the old integration: the related incident's data is saved on
        # the account's fields (and the incident itself is also created as a
        # 'Luminar Incident' indicator linked by a relationship edge).
        tags.append(f'Incident: {incident.get("name")}')
        ext_incident = get_extension_fields(incident)
        fields.update(
            {
                "tags": tags,
                "creationdate": incident.get("created"),
                "updateddate": incident.get("modified"),
                "luminarincidentname": incident.get("name"),
                "luminarincidentdescription": incident.get("description"),
                "luminarthreatscore": ext_incident.get("luminar_threat_score"),
                "luminarcollectiondate": ext_incident.get("collection_date"),
                "luminarcomputername": ext_incident.get("computer_name"),
            }
        )
        occurred = incident.get("created") or occurred

    raw_json = dict(stix_object)
    raw_json["value"] = value
    indicator = {
        "value": value,
        "type": FeedIndicatorType.Account,
        "rawJSON": raw_json,
        "fields": {k: v for k, v in fields.items() if v not in (None, "", [])},
    }
    if occurred:
        indicator["occurred"] = occurred
    return indicator


def iter_related_objects(stix_id: str, rel_objects: list, id_map: dict):
    """Yield (relationship_type, related_stix_object) for every object
    related to the given STIX id (both directions), deduplicated."""
    for rel_type, other_id in iter_related_ids(stix_id, rel_objects):
        candidate = id_map.get(other_id)
        if candidate:
            yield rel_type, candidate


def _describe_light(stix_id: str, light_map: dict) -> str:
    """'<object_type>: <name>' from a light-map entry."""
    entry = light_map.get(stix_id)
    if not entry:
        return f"object: {stix_id}"
    # entry: (stix_type, display_name, xsoar_value, xsoar_type); indicators
    # carry their value in the pattern, so fall back to the resolved value.
    stix_type, name = entry[0], entry[1] or entry[2]
    return f"{stix_type}: {name}" if name else stix_type


def should_include_comment_relation(source_type: Optional[str], rel_type: str, target_type: Optional[str]) -> bool:
    """Return True when a relation should be included in the indicator
    comment text.

    For IOC source type ('indicator') we keep only the curated relations in
    COMMENT_RELATION_ALLOWLIST. Other source types keep existing behavior.
    """
    if not source_type or not target_type:
        return False
    allowed = COMMENT_RELATION_ALLOWLIST.get(source_type)
    if not allowed:
        return True
    return target_type in allowed.get(rel_type, set())


def build_related_comment(stix_id: str, rel_records: list, light_map: dict) -> Optional[str]:
    """Build a single comment listing all objects related to a STIX object.

    Format: '<relationship_type> - <object_type>: <name>', e.g.
    'indicates - threat-actor: APT28'. For indicators the related object's own
    relations are nested underneath (threat-actor 'targets' location, 'uses'
    malware, ...). Leaked-record accounts stay single-level - their only
    relation is the parent incident."""
    source_entry = light_map.get(stix_id)
    source_type = source_entry[0] if source_entry else None
    lines = []
    seen_lines = set()
    for rel_type, other_id in iter_related_ids(stix_id, rel_records):
        if other_id not in light_map:
            continue
        other_type = light_map[other_id][0]
        if not should_include_comment_relation(source_type, rel_type, other_type):
            continue
        line = f"{rel_type} - {_describe_light(other_id, light_map)}"
        if line not in seen_lines:
            seen_lines.add(line)
            lines.append(line)
        if source_type == "user-account":
            continue
        if other_type not in COMMENT_RELATION_ALLOWLIST:
            continue
        for sub_rel_type, sub_id in iter_related_ids(other_id, rel_records):
            if sub_id == stix_id or sub_id not in light_map:
                continue
            sub_type = light_map[sub_id][0]
            if not should_include_comment_relation(other_type, sub_rel_type, sub_type):
                continue
            line = f"    {sub_rel_type} - {_describe_light(sub_id, light_map)}"
            if line not in seen_lines:
                seen_lines.add(line)
                lines.append(line)
    if not lines:
        return None
    return "\n".join(lines)


def build_relationship_name(stix_relationship_type: str) -> str:
    """Map a STIX relationship_type to a valid XSOAR relationship name."""
    if stix_relationship_type in STIX_RELATIONSHIP_TO_XSOAR:
        return STIX_RELATIONSHIP_TO_XSOAR[stix_relationship_type]
    if EntityRelationship.Relationships.is_valid(stix_relationship_type):
        return stix_relationship_type
    demisto.debug(f"Unknown STIX relationship type '{stix_relationship_type}', using 'related-to'.")
    return EntityRelationship.Relationships.RELATED_TO


def build_relationships_dummy_indicator(rel_records: list, light_map: dict) -> Optional[dict]:
    """
    Build a '$$DummyIndicator$$' object holding EntityRelationship entries
    resolved through the light index - relationships are created separately
    from the indicators.
    """
    xsoar_relationships = []
    for rel in rel_records:
        source = light_map.get(rel.get("source_ref"))
        target = light_map.get(rel.get("target_ref"))
        if not source or not target:
            demisto.debug(
                f"Skipping relationship - could not resolve "
                f"source_ref={rel.get('source_ref')} or target_ref={rel.get('target_ref')}."
            )
            continue

        _, _, entity_a, entity_a_type = source
        _, _, entity_b, entity_b_type = target
        if not all((entity_a, entity_a_type, entity_b, entity_b_type)):
            demisto.debug(f"Skipping relationship - unsupported entity types " f"({source[0]} -> {target[0]}).")
            continue

        xsoar_relationships.append(
            EntityRelationship(
                name=build_relationship_name(rel.get("relationship_type", "")),
                entity_a=entity_a,
                entity_a_type=entity_a_type,
                entity_b=entity_b,
                entity_b_type=entity_b_type,
                fields={
                    "firstseenbysource": rel.get("created"),
                    "lastseenbysource": rel.get("modified"),
                },
                brand="Luminar",
            ).to_indicator()
        )

    if not xsoar_relationships:
        return None
    return {"value": DUMMY_INDICATOR_VALUE, "relationships": xsoar_relationships}


def stix_objects_to_indicators(
    objects: list,
    feed_tags: list,
    tlp_color: Optional[str],
    light_map: Optional[dict] = None,
    rel_records: Optional[list] = None,
    incident_map: Optional[dict] = None,
) -> tuple[list, list]:
    """
    Transform a page of STIX objects into XSOAR indicator dicts.

    When light_map/rel_records/incident_map are not supplied they are built
    from the given objects; during fetch-indicators the batch's index
    (target + resolved context) is passed in.

    Returns:
        (indicators, rel_records)
    """
    if light_map is None or rel_records is None or incident_map is None:
        light_map, incident_map, rel_records = index_objects(objects)
    indicators: list = []

    for obj in objects:
        obj_type = obj.get("type", "")
        if obj_type in NON_INDICATOR_TYPES:
            continue

        if obj_type == "user-account":
            incident = find_related_incident(obj.get("id", ""), rel_records, incident_map)
            indicator = build_account_indicator(obj, incident, feed_tags, tlp_color)
        elif stix_is_sdo(obj_type):
            indicator = build_sdo_indicator(obj, feed_tags, tlp_color)
        else:
            # 'indicator' objects and SCOs (ipv4-addr, url, file, ...)
            indicator = build_indicator_from_stix(obj, feed_tags, tlp_color)

        if indicator:
            indicators.append(indicator)

    # Attach a single comment listing all related objects to each indicator.
    for built_indicator in indicators:
        comment = build_related_comment(built_indicator.get("rawJSON", {}).get("id", ""), rel_records, light_map)
        if comment:
            built_indicator["comments"] = [{"content": comment, "type": "IndicatorCommentRegular"}]

    return indicators, rel_records


def stix_is_sdo(stix_type: str) -> bool:
    """STIX domain objects (named entities) vs cyber-observables (valued)."""
    return stix_type in SDO_STIX_TYPES


""" INTEGRATION CONTEXT (CHECKPOINTS) """


def get_checkpoints() -> dict:
    return demisto.getIntegrationContext().get("checkpoints", {})


def save_checkpoint(collection_title: str, checkpoint: str) -> None:
    context = demisto.getIntegrationContext()
    context.setdefault("checkpoints", {})[collection_title] = checkpoint
    demisto.setIntegrationContext(context)


def normalize_taxii_timestamp(value: str) -> str:
    """Normalize a date string/datetime to TAXII format with exactly 6
    fractional digits, e.g. 2026-08-11T00:43:16.307000Z."""
    dt = arg_to_datetime(value)
    if not dt:
        raise DemistoException(f"Could not parse '{value}' as a date for the 'First Fetch Time' parameter.")
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def subtract_one_second(timestamp: str) -> str:
    """Subtract 1 second from an ISO-8601 Z timestamp, keeping the format.
    Used as an overlap buffer when rebuilding an expired pagination cursor so
    no records are missed at sub-second boundaries. On parse failure the
    original timestamp is returned."""
    dt = arg_to_datetime(timestamp)
    if not dt:
        return timestamp
    return (dt - timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


""" COMMANDS """


def create_batch(indicators: list, rel_records: list, light_map: dict) -> tuple[int, int]:
    """Persist one resolved batch to TIM: indicators (authoritative upsert -
    every managed field is populated, empty when absent, so stale values on
    existing indicators are cleared instead of merged-and-kept) on copies, and
    relationships via '$$DummyIndicator$$' payloads.
    See https://xsoar.pan.dev/docs/integrations/feeds
    Returns (indicators_created, relationships_created)."""
    to_create = []
    for indicator in indicators:
        copy = dict(indicator)
        copy["fields"] = {**LUMINAR_FIELD_DEFAULTS, **(indicator.get("fields") or {})}
        to_create.append(copy)
    for b in batch(to_create, batch_size=2000):
        demisto.createIndicators(b)
    rel_created = 0
    for rel_chunk in batch(rel_records, batch_size=2000):
        dummy = build_relationships_dummy_indicator(rel_chunk, light_map)
        if dummy:
            demisto.createIndicators([dummy])
            rel_created += len(dummy["relationships"])
    return len(indicators), rel_created


def module_test(client: Client) -> str:
    try:
        client.fetch_access_token()
        available = {c.get("title") for c in client.get_collections()}
    except LuminarAuthError:
        raise
    except Exception as e:
        raise DemistoException(f"Could not connect to the Luminar API - {e}")

    missing = [t for t in COLLECTION_TITLES if not client.resolve_collection_id(t)]
    if missing:
        raise DemistoException(
            f"The following collections were not found on the server: {missing}. " f"Available collections: {sorted(available)}"
        )
    return "ok"


def fetch_indicators_command(client: Client, first_fetch: Optional[str]) -> None:
    """fetch-indicators: pull the IOCs and Leaked Records collections and
    create indicators.

    Collections can hold millions of objects, so fetching uses a 3-batch
    sliding window (see Client.iter_resolved_batches): each batch is resolved
    (relationship endpoints found in the neighboring batches, the
    hydrated-object LRU, or via match[id]), transformed into indicators,
    created, and checkpointed before the window slides forward. At most ~3
    batches plus the LRU are ever in memory.
    """
    checkpoints = get_checkpoints()
    first_fetch_normalized = normalize_taxii_timestamp(first_fetch) if first_fetch else None

    for title in COLLECTION_TITLES:
        added_after = checkpoints.get(title) or first_fetch_normalized
        created = rel_created = 0
        try:
            collection_id = client.resolve_collection_id(title)
            if not collection_id:
                raise DemistoException(f"Collection '{title}' was not found on the Luminar server.")

            for target, context, last_added in client.iter_resolved_batches(collection_id, added_after):
                # Index target once (its rels seed both comments and the
                # dummy - each relationship is created exactly once), then
                # index context into the same structures for comment
                # resolution and incident enrichment.
                light_map, incident_map, target_rels = index_objects(target)
                comment_rels = list(target_rels)
                for obj in context:
                    index_object(obj, light_map, incident_map, comment_rels)

                indicators, _ = stix_objects_to_indicators(
                    target,
                    client.feed_tags,
                    client.tlp_color,
                    light_map=light_map,
                    rel_records=comment_rels,
                    incident_map=incident_map,
                )
                batch_created, batch_rels = create_batch(indicators, target_rels, light_map)
                created += batch_created
                rel_created += batch_rels

                if last_added:
                    save_checkpoint(title, last_added)
                demisto.info(f"Collection '{title}': batch done - {created} indicators and {rel_created} relationships so far.")
        except DemistoException as e:
            # Already-delivered batches stay saved (checkpoints advance per
            # batch); the error is re-raised so the fetch is marked as failed.
            raise DemistoException(f"Failed fetching collection '{title}': {e}") from e

        demisto.info(f"Collection '{title}': created {created} indicators and {rel_created} relationships.")


def resolve_from_date(args: dict) -> Optional[str]:
    """Normalize the 'from_date' command argument to a TAXII timestamp."""
    from_date = args.get("from_date")
    return normalize_taxii_timestamp(from_date) if from_date else None


def flatten_indicator(indicator: dict) -> dict:
    """Flatten an indicator (value/type/occurred + all fields) into a
    single dict so every mapped field is available in context output."""
    flat = {"Type": indicator.get("type"), "Value": indicator.get("value")}
    if indicator.get("occurred"):
        flat["Occurred"] = indicator["occurred"]
    flat.update(indicator.get("fields", {}))
    if indicator.get("comments"):
        flat["comment"] = " | ".join(c.get("content", "").replace("\n", "; ") for c in indicator["comments"])
    return {k: v for k, v in flat.items() if v not in (None, "", [])}


def flatten_stix_object(stix_object: dict, feed_tags: list, tlp_color: Optional[str]) -> Optional[dict]:
    """Flatten any STIX object into a field dict - reuses the indicator
    builders when possible and falls back to the raw object fields."""
    obj_type = stix_object.get("type", "")
    indicator = None
    if stix_is_sdo(obj_type):
        indicator = build_sdo_indicator(stix_object, feed_tags, tlp_color)
    elif obj_type == "user-account":
        indicator = build_account_indicator(stix_object, None, feed_tags, tlp_color)
    elif obj_type not in NON_INDICATOR_TYPES:
        indicator = build_indicator_from_stix(stix_object, feed_tags, tlp_color)
    if indicator:
        return flatten_indicator(indicator)

    flat = {
        "name": stix_object.get("name") or stix_object.get("value") or stix_object.get("account_login"),
        "description": stix_object.get("description"),
        "created": stix_object.get("created"),
        "modified": stix_object.get("modified"),
    }
    flat.update(get_extension_fields(stix_object))
    flat = {k: v for k, v in flat.items() if v not in (None, "", [])}
    return flat or None


def get_related_objects_fields(
    stix_id: str,
    rel_objects: list,
    id_map: dict,
    feed_tags: list,
    tlp_color: Optional[str],
    expand_incident: bool = False,
) -> list:
    """Resolve objects related to a STIX object via the collection's
    relationships and return each related object's flattened field set.

    With expand_incident (used for account rows), one extra hop is taken
    through a related 'incident' object so the leaked-credential row also
    shows the other objects inside the leak bundle (malware, IP, file).
    The incident's sibling accounts and nested incidents are skipped as noise."""
    related = []
    seen_relations = set()
    expanded_incidents = set()
    for rel_type, candidate in iter_related_objects(stix_id, rel_objects, id_map):
        candidate_id = candidate.get("id")
        relation_key = (rel_type, candidate_id)
        if relation_key in seen_relations:
            continue
        seen_relations.add(relation_key)
        flat = flatten_stix_object(candidate, feed_tags, tlp_color)
        if not flat:
            continue
        flat["_stixtype"] = candidate.get("type", "object")
        flat["relationship"] = rel_type
        related.append(flat)
        if expand_incident and candidate.get("type") == "incident" and candidate_id and candidate_id not in expanded_incidents:
            expanded_incidents.add(candidate_id)
            for bundle_rel_type, neighbor in iter_related_objects(candidate_id, rel_objects, id_map):
                neighbor_id = neighbor.get("id")
                relation_key = (bundle_rel_type, neighbor_id)
                if relation_key in seen_relations:
                    continue
                seen_relations.add(relation_key)
                if neighbor.get("type") in ("user-account", "incident"):
                    continue
                flat = flatten_stix_object(neighbor, feed_tags, tlp_color)
                if not flat:
                    continue
                flat["_stixtype"] = neighbor.get("type", "object")
                flat["relationship"] = bundle_rel_type
                related.append(flat)
    return related


def merge_related_fields(related: list) -> dict:
    """Merge related objects' fields into '<stix-type>-<field>' columns;
    multiple objects of the same type produce comma-separated values."""
    merged: dict[str, list] = {}
    for rel_flat in related:
        stix_type = rel_flat.get("_stixtype", "object")
        for key, value in rel_flat.items():
            if key == "_stixtype" or key in RELATED_DROP_FIELDS:
                continue
            values = value if isinstance(value, list) else [value]
            merged.setdefault(f"{stix_type}-{key}", []).extend(str(v) for v in values)
    return {column: ", ".join(dict.fromkeys(values)) for column, values in merged.items()}


def header_label(header: str) -> str:
    """Title-case label for a war-room table header.

    Own columns look up HEADER_LABELS ('luminarscore' -> 'Luminar Score').
    Related '<stix-type>-<field>' columns render as 'Threat Actor - Aliases';
    the type part is split on the last '-' so 'threat-actor-aliases' resolves
    correctly. Unknown keys fall back to a generic title-casing."""
    if "-" in header:
        stix_type, _, field = header.rpartition("-")
        if stix_type and field:
            return f"{stix_type.replace('-', ' ').title()} - {HEADER_LABELS.get(field, field.replace('_', ' ').title())}"
    return HEADER_LABELS.get(header, header.replace("_", " ").replace("-", " ").title())


def indicators_to_readable(title: str, flat_indicators: list, related_columns: list) -> str:
    """Render all indicators as one table - the indicator's own fields
    first, related '<stix-type>-<field>' columns after."""
    related_set = set(related_columns)
    own_columns: list = []
    for flat in flat_indicators:
        for key in flat:
            if key == "stixid" or key in related_set or key in own_columns:
                continue
            own_columns.append(key)
    related_columns = [c for c in related_columns if not c.endswith("-stixid")]
    return tableToMarkdown(title, flat_indicators, headers=own_columns + related_columns, headerTransform=header_label)


def stream_persist_collect(
    client: Client, collection_title: str, added_after: Optional[str], limit: int, row_filter
) -> tuple[list, list, int]:
    """Iterate resolved batches of a collection, persisting each batch's
    indicators and relationships to TIM as it arrives, and collect up to
    `limit` display rows (with related '<stix-type>-<field>' columns resolved
    within the batch window). Persisting per batch means a timeout or error
    mid-run does not lose already-created data.
    Returns (rows, related_columns, indicators_created)."""
    collection_id = client.resolve_collection_id(collection_title)
    if not collection_id:
        raise DemistoException(f"Collection '{collection_title}' was not found on the Luminar server.")

    created = 0
    rows: list = []
    related_columns: list = []
    related_columns_set = set()
    for target, context, _last_added in client.iter_resolved_batches(collection_id, added_after):
        light_map, incident_map, target_rels = index_objects(target)
        comment_rels = list(target_rels)
        for obj in context:
            index_object(obj, light_map, incident_map, comment_rels)
        indicators, _ = stix_objects_to_indicators(
            target,
            client.feed_tags,
            client.tlp_color,
            light_map=light_map,
            rel_records=comment_rels,
            incident_map=incident_map,
        )
        batch_created, _batch_rels = create_batch(indicators, target_rels, light_map)
        created += batch_created

        if len(rows) >= limit:
            continue
        id_map = {o["id"]: o for o in target + context if o.get("id")}
        for indicator in indicators:
            if len(rows) >= limit or not row_filter(indicator):
                continue
            flat = flatten_indicator(indicator)
            merged = merge_related_fields(
                get_related_objects_fields(
                    indicator.get("rawJSON", {}).get("id", ""),
                    comment_rels,
                    id_map,
                    client.feed_tags,
                    client.tlp_color,
                    expand_incident=indicator.get("type") == FeedIndicatorType.Account,
                )
            )
            flat.update(merged)
            for column in merged:
                if column not in related_columns_set:
                    related_columns_set.add(column)
                    related_columns.append(column)
            rows.append(flat)
    return rows, related_columns, created


def cognyte_luminar_get_indicators(client: Client, args: dict) -> CommandResults:
    """get-luminar-indicators - fetch the IOCs collection, persist the
    fetched objects to TIM and show up to `limit` IOC rows."""
    limit = arg_to_number(args.get("limit", 50), arg_name="limit") or 50
    # Only real IOCs as rows - SDOs appear as related '<type>-<field>' columns.
    rows, related_columns, saved = stream_persist_collect(
        client,
        IOCS_COLLECTION,
        resolve_from_date(args),
        limit,
        lambda i: i.get("type") != FeedIndicatorType.Account and not stix_is_sdo(i.get("rawJSON", {}).get("type", "")),
    )
    if not rows:
        return CommandResults(readable_output="No indicators found.")
    return CommandResults(
        outputs_prefix="LuminarV3.Indicators",
        outputs_key_field="Value",
        outputs=rows,
        readable_output=indicators_to_readable("Luminar Indicator", rows, related_columns)
        + f"\n**{saved} indicators saved to TIM.**",
    )


def cognyte_luminar_get_leaked_records(client: Client, args: dict) -> CommandResults:
    """luminar-v3-get-leaked-records - fetch the Leaked Records collection,
    persist the fetched objects to TIM and show up to `limit` account rows."""
    limit = arg_to_number(args.get("limit", 50), arg_name="limit") or 50
    rows, related_columns, saved = stream_persist_collect(
        client,
        LEAKED_RECORDS_COLLECTION,
        resolve_from_date(args),
        limit,
        lambda i: i.get("type") == FeedIndicatorType.Account,
    )
    if not rows:
        return CommandResults(readable_output="No leaked records found.")
    return CommandResults(
        outputs_prefix="LuminarV3.LeakedCredentials",
        outputs_key_field="Value",
        outputs=rows,
        readable_output=indicators_to_readable("Luminar Leaked Record", rows, related_columns)
        + f"\n**{saved} indicators saved to TIM.**",
    )


def reset_last_run() -> CommandResults:
    """Reset the fetch history (per-collection TAXII checkpoints)."""
    demisto.setIntegrationContext({})
    return CommandResults(readable_output="Fetch history deleted successfully")


def main() -> None:
    params = demisto.params()
    base_url = params.get("luminar_base_url", "").rstrip("/")
    account_id = params.get("luminar_account_id")
    client_id = params.get("luminar_client_id")
    client_secret: str = params.get("luminar_client_secret") or (params.get("luminar_credentials") or {}).get("password") or ""
    verify_certificate = not params.get("insecure", False)
    proxy = params.get("proxy", False)
    tags = argToList(params.get("feedTags"))
    tlp_color = params.get("tlp_color")
    first_fetch = params.get("first_fetch")

    client = Client(
        base_url=base_url,
        account_id=account_id,
        client_id=client_id,
        client_secret=client_secret,
        verify=verify_certificate,
        proxy=proxy,
        tags=tags,
        tlp_color=tlp_color,
    )

    command = demisto.command()
    demisto.info(f"Command being called is {command}")
    try:
        if command == "test-module":
            return_results(module_test(client))
        elif command == "fetch-indicators":
            fetch_indicators_command(client, first_fetch)
        elif command == "get-luminar-indicators":
            return_results(cognyte_luminar_get_indicators(client, demisto.args()))
        elif command == "luminar-v3-get-leaked-records":
            return_results(cognyte_luminar_get_leaked_records(client, demisto.args()))
        elif command == "luminar-v3-reset-fetch-indicators":
            return_results(reset_last_run())
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception as e:
        demisto.error(traceback.format_exc())
        message = (
            f"Authentication error in CognyteLuminarV3: {e}"
            if isinstance(e, LuminarAuthError)
            else f"Failed to execute {command} command.\nError:\n{e!s}"
        )
        return_error(message)


if __name__ in ("__builtin__", "builtins", "__main__"):
    main()
