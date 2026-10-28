"""Shared code for the CyberArk Certificate Manager SaaS and Next-Gen Trust Security integrations.

Next-Gen Trust Security (NGTS) is Certificate Manager SaaS behind the Strata Cloud Manager gateway, which
serves the same GraphQL and REST paths. So everything that does not depend on how a caller authenticates
lives here: parsing and context builders, GraphQL query builders, paging, the command functions and the
expiry fetch. Each integration supplies a client subclass (credential, base URL), a `ProductProfile` (the
wording, brand and User-Agent that differ per product), its own test-module and its dispatch.

Each integration wildcard-imports this module, and the demisto-sdk unifier inlines it at build time. Per-
product values reach this code through the client and function arguments, never through module-level
names: in the unified script an integration global would shadow one defined here, but in unit tests the
module keeps its own namespace, so the two would behave differently.
"""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa

import base64
import io
import zipfile
import requests
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from nacl.public import PublicKey, SealedBox

""" CONSTANTS """

GRAPHQL_URL_SUFFIX = "/graphql"
MACHINES_URL_SUFFIX = "/v1/machines"
CERTIFICATE_REQUESTS_URL_SUFFIX = "/outagedetection/v1/certificaterequests"
CERTIFICATE_URL_TEMPLATE = "/outagedetection/v1/certificates/{certificate_id}"
CERTIFICATE_CONTENTS_URL_TEMPLATE = "/outagedetection/v1/certificates/{certificate_id}/contents"
CERTIFICATE_KEYSTORE_URL_TEMPLATE = "/outagedetection/v1/certificates/{certificate_id}/keystore"
EDGE_ENCRYPTION_KEY_URL_TEMPLATE = "/v1/edgeencryptionkeys/{dek_hash}"

HTTP_TIMEOUT = 30  # a hang is not an exception; without this one slow endpoint stalls the command
MAX_PAGE_SIZE = 100  # hard server cap - `first: 101` returns HTTP 200 with an `errors` array
DEFAULT_LIMIT = 50
DEFAULT_MAX_PAGES = 50  # safety bound on client-side paging (50 x 100 = 5,000 certificates)
DEFAULT_EXPIRY_DAYS = 30
EXPIRED_LOOKBACK_DAYS = 365  # bounds the lower edge of the expiry window when include_expired is set

# Shared by both integrations, so playbooks, the fetch mapper and the incident type serve either one.
CONTEXT_PREFIX = "CertManagerSaaS"
NOT_FOUND_MESSAGE = "Not found (HTTP 404). This endpoint is not available on this tenant."

# The `RevocationReason` enum, verbatim from the CM SaaS GraphQL SDL. RFC 5280 reasons that are
# *not* in it - CA_COMPROMISE, CERTIFICATE_HOLD, PRIVILEGE_WITHDRAWN, AA_COMPROMISE,
# REMOVE_FROM_CRL - are rejected by the gateway, so the argument is a closed list in the YAML too.
REVOCATION_REASONS = ("UNSPECIFIED", "KEY_COMPROMISE", "AFFILIATION_CHANGED", "SUPERSEDED", "CESSATION_OF_OPERATION")
# The only revocation reason that is a vendor security assertion rather than an inventory fact.
KEY_COMPROMISE_REASON = "KEY_COMPROMISE"
# `globalRevocation.reason` has its own enum, and it spells the same reason differently.
GLOBAL_KEY_COMPROMISE_REASON = "KEY_COMPROMISED"
DEFAULT_REVOCATION_REASON = "UNSPECIFIED"
# `revocation.status` is the request: SUBMITTED means "sent to the CA" and never changes. Whether the CA
# really revoked it is `globalRevocation.status`, read from public CAs' revocation lists; private CAs usually read UNKNOWN.
REVOCATION_SUBMITTED = "SUBMITTED"
REVOCATION_FAILED = "FAILED"
REVOCATION_REJECTED = "REJECTED_APPROVAL"
REVOCATION_REPORTED_STATUSES = (REVOCATION_FAILED, "PENDING_APPROVAL", "PENDING_FINAL_APPROVAL")
GLOBAL_REVOKED = "REVOKED"
GLOBAL_NOT_REVOKED = "NOT_REVOKED"
# A renewal with a service-generated key that keeps the old certificate's subject and SANs.
RENEW_TYPE_CLONED = "CLONED_CSR_WITH_NEW_PRIVATE_KEY"
# `Certificate.status` is only ACTIVE or RETIRED.
CERTIFICATE_STATUS_ACTIVE = "ACTIVE"
# The verdict for a key compromise that is reported but not done; the default is Suspicious.
REPORTED_KEY_COMPROMISE_SCORES = {"Suspicious": Common.DBotScore.SUSPICIOUS, "Malicious": Common.DBotScore.BAD}
DEFAULT_REPORTED_KEY_COMPROMISE_SCORE = "Suspicious"
# `revokeCertificate` is documented in the SDL as "Revoke a certificate by SHA1 fingerprint".
SHA1_HEX_LENGTH = 40

CERTIFICATE_FORMATS = ("PEM", "DER")
DOWNLOAD_ACCEPT_BY_FORMAT = {"PEM": "text/plain", "DER": "application/octet-stream"}
FILE_EXTENSION_BY_FORMAT = {"PEM": "pem", "DER": "der"}

KEYSTORE_FORMATS = ("PEM", "PKCS12")
DEFAULT_KEYSTORE_FORMAT = "PEM"
# The passphrase is sealed (libsodium sealed box) to the VSatellite's key, used raw. Only ED25519 keys are
# known to work this way; VSAT_HPKE and RSA keys need another scheme.
SUPPORTED_EDGE_KEY_ALGORITHM = "ED25519"
# With `Accept: application/octet-stream`, every keystore error is an empty, generic HTTP 400.
KEYSTORE_ACCEPT = "*/*"
# "Issuer certificates not available": the issuing CA returned only the leaf, and the export needs the chain.
ISSUER_CHAIN_MISSING_CODE = 20602
# The PEM keystore is a zip holding `<cn>.key` (an encrypted PKCS#8 key) and the chain in several orders;
# `<cn>_root-last.pem` is leaf first, the order servers expect.
PEM_KEY_ENTRY_SUFFIX = ".key"
PEM_CHAIN_ENTRY_SUFFIX = "_root-last.pem"

INCIDENT_TYPE = "CertManagerSaaS Certificate Expiry"
REVOCATION_FAILED_INCIDENT_TYPE = "CertManagerSaaS Revocation Failed"
# XSIAM types a fetched issue from the instance setting, not from the incident's `type`. The Common pack's
# classifier reads this rawJSON key instead, so each issue gets its own type.
ISSUE_TYPE_RAW_KEY = "IssueType"
# last_run key: fingerprints whose failed key-compromise revocation already raised an incident.
RAISED_REVOCATION_FAILURES_KEY = "raised_revocation_failures"
# Fixed-width and UTC, so the look-back helpers can round-trip it and so lexicographic ordering of
# two timestamps is also chronological ordering.
FETCH_DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
DEFAULT_FIRST_FETCH = "30 days"
DEFAULT_MAX_FETCH = 50
# One day. The upstream expiry evaluation is daily, so a shorter window buys nothing and a longer
# one only grows the deduplication bookkeeping.
DEFAULT_LOOK_BACK_MINUTES = 1440
FETCH_MAX_PAGES = 20  # 20 x 100 = 2,000 certificates inside the expiry window per fetch
# The severity ladder, as expiry thresholds in days. Each threshold a certificate crosses is its own incident.
CRITICAL_EXPIRY_DAYS = 7
HIGH_EXPIRY_DAYS = 30
# Top-level incident field holding the deduplication key `{fingerprint}:{threshold}`.
DEDUP_ID_FIELD = "dedup_id"

# Hex digest lengths for MD5, SHA-1, SHA-256, SHA-384 and SHA-512.
FINGERPRINT_HEX_LENGTHS = (32, 40, 64, 96, 128)
# `Common.Certificate` has no SHA-384 slot, so a 96-character digest carries no hash field.
DIGEST_FIELD_BY_LENGTH = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}

# `orderBy` takes a list of field/direction pairs. A stable order is required for cursor paging to
# be meaningful.
CERTIFICATE_ORDER_BY = "[{field: LAST_MODIFIED_TIME, direction: ASC}, {field: FINGERPRINT, direction: ASC}]"

CERTIFICATE_FIELDS = """
      id
      name
      fingerprint
      serialNumber
      status
      isSelfSigned
      isCA
      isPublic
      origins
      keyUsages
      signatureAlgorithm
      signatureHashAlgorithm
      lastModifiedTime
      subject { dn commonName o ou c l st }
      issuer { dn commonName o ou c l st }
      validity { from to period }
      subjectAlternativeNames {
        __typename
        ... on DNSName { dnsName }
        ... on RFC822Name { emailAddress }
        ... on UniformResourceIdentifier { uri }
        ... on IPAddress { ip }
      }
      publicKeyInformation {
        __typename
        ... on RSAKeyInfo { strength }
        ... on ECKeyInfo { curve }
        ... on DSAKeyInfo { l n }
      }
      applications { id name }
      machineInstallations {
        totalCount
        nodes { id status machine { id name plugin { id name } } }
      }
      tlsServerEndpoints {
        totalCount
        nodes { id serverName ipAddress port deploymentStatus }
      }
      cloudInstallations {
        totalCount
        nodes { id cloudKeystoreId cloudKeystoreName cloudProviderName status metadata { __typename } }
      }
      revocation { status reason comment error { message } }
      globalRevocation { status reason revokedTime }
      workspaceId
"""

# A cloud installation names its keystore but not the keystore type; the metadata variant does, one to one.
KEYSTORE_TYPE_BY_METADATA = {
    "AWSCertificateMetadata": "AWS Certificate Manager",
    "AzureCertificateMetadata": "Azure Key Vault",
    "GCPCertificateMetadata": "Google Certificate Manager",
    "AkamaiCertificateMetadata": "Akamai CDN",
}

SEARCH_CERTIFICATES_TEMPLATE = """query SearchCertificates($first: Int!, $after: String) {{
  searchCertificates(first: $first, after: $after, orderBy: {order_by}{filter_clause}) {{
    totalCount
    pageInfo {{ hasNextPage endCursor }}
    nodes {{{fields}    }}
  }}
}}"""

# `revokeCertificate` returns a `Certificate`, so the search field selection - revocation block
# included - is reused verbatim and proves the mutation landed.
# `certificateAuthorityAccountId: UUID` is also accepted but is undocumented in the SDL, so it is
# deliberately not exposed.
REVOKE_CERTIFICATE_MUTATION = (
    "mutation RevokeCertificate($fingerprint: ID!, $revocationReason: RevocationReason!, $revocationComment: String) {\n"
    "  revokeCertificate(fingerprint: $fingerprint, revocationReason: $revocationReason, "
    "revocationComment: $revocationComment) {" + CERTIFICATE_FIELDS + "  }\n}"
)

# The thresholds the tenant actually notifies on. Tenant-global and customer-configured, so they
# can silently disagree with the severity ladder this integration computes.
ACTIVE_THRESHOLDS_QUERY = "query CertificateExpiryThresholds { getCertExpActiveThresholds { thresholds } }"

# Installations are lists of dicts, which a certificate table cell can only show as a raw Python repr.
INSTALLATION_TABLES = (
    ("Installations", "Machine installations", ["MachineName", "Host", "PluginName", "Status"]),
    ("CloudInstallations", "Cloud keystore installations", ["KeystoreName", "KeystoreType", "ProviderName", "Status"]),
)


""" EXCEPTIONS """


class GraphQLQueryError(DemistoException):
    """Raised when the GraphQL gateway answers HTTP 200 with a top-level `errors` array.

    The gateway redacts subgraph runtime errors but returns validation errors intact, so this
    covers both "the query is invalid" and "the subgraph failed". Either way the response is
    untrusted in full and must not be treated as an empty result.
    """


""" PRODUCT PROFILE """


@dataclass(frozen=True)
class ProductProfile:
    """What differs between the products in wording and identification, not in behaviour.

    Attributes:
        name: The product name used in titles and messages, and as the DBotScore vendor.
        brand: The integration brand (the YAML `name`), stamped on every certificate as `SourceBrand` so a
            playbook can route a follow-up write to the integration that found the certificate.
        user_agent: The User-Agent sent on every request, so the vendor can tell the integrations apart.
        http_error_messages: Actionable messages by HTTP status, e.g. what a 401 means for this credential.
    """

    name: str
    brand: str
    user_agent: str
    http_error_messages: dict[int, str] = field(default_factory=dict)


""" HELPER FUNCTIONS """


class GraphQLEnum(str):
    """A string written as a bare GraphQL enum value (`FAILED`), not a quoted string (`"FAILED"`).

    The gateway rejects a quoted value for an enum-typed filter such as `revocationStatus`.
    """


def to_graphql_literal(value: Any) -> str:
    """Serialize a Python value as an inline GraphQL literal.

    The CM SaaS gateway has introspection disabled, so the name of the `filterOn` input type is
    unknown and the filter cannot be passed as a typed variable. It is inlined instead. Input
    object keys are bare GraphQL names (never quoted), but string *values* share JSON's escaping
    rules, so ``json.dumps`` is reused for those to keep the escaping correct.

    Args:
        value: A JSON-like Python value.

    Returns:
        str: The value rendered as GraphQL source.
    """
    if isinstance(value, GraphQLEnum):
        return str(value)
    if isinstance(value, dict):
        return "{" + ", ".join(f"{key}: {to_graphql_literal(item)}" for key, item in value.items()) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(to_graphql_literal(item) for item in value) + "]"
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return json.dumps(value)
    return json.dumps(str(value))


def build_search_query(filter_on: dict[str, Any] | None = None) -> str:
    """Build the `searchCertificates` query, optionally with an inline `filterOn` clause.

    Args:
        filter_on: The CM SaaS filter expression, for example ``{"and": {"fingerprint": {"eq": "AB..."}}}``.

    Returns:
        str: A complete GraphQL document.
    """
    filter_clause = f", filterOn: {to_graphql_literal(filter_on)}" if filter_on else ""
    return SEARCH_CERTIFICATES_TEMPLATE.format(
        order_by=CERTIFICATE_ORDER_BY, filter_clause=filter_clause, fields=CERTIFICATE_FIELDS
    )


def normalize_fingerprint(raw: str) -> str:
    """Normalize a certificate fingerprint to bare uppercase hex.

    Args:
        raw: A fingerprint in any common presentation (colon-separated, spaced, lower case).

    Returns:
        str: The fingerprint as uppercase hex with no separators.

    Raises:
        ValueError: If the value is not a hex digest of a recognized length. Catching this up
            front is what keeps a typo distinguishable from a certificate the tenant does not
            have - the API answers both with HTTP 200 and ``totalCount: 0``.
    """
    stripped = re.sub(r"[\s:\-]", "", raw or "")
    if not stripped or not re.fullmatch(r"[0-9A-Fa-f]+", stripped):
        raise ValueError(f"{raw!r} is not a hexadecimal certificate fingerprint.")
    if len(stripped) not in FINGERPRINT_HEX_LENGTHS:
        raise ValueError(
            f"{raw!r} is {len(stripped)} hex characters long, which is not a known digest length "
            f"({', '.join(str(length) for length in FINGERPRINT_HEX_LENGTHS)})."
        )
    return stripped.upper()


def normalize_sha1_fingerprint(raw: str) -> str:
    """Normalize a fingerprint and reject anything that is not a SHA-1 digest.

    `revokeCertificate` and the `existingCertificateFingerprint` request field are both keyed on the
    SHA-1 fingerprint. A digest of another length is accepted by the transport and then matches
    nothing, which the API reports as success-with-no-result - so it is rejected here instead.

    Args:
        raw: A fingerprint in any common presentation.

    Returns:
        str: The fingerprint as uppercase hex with no separators.

    Raises:
        ValueError: If the value is not a 40-character hex digest.
    """
    fingerprint = normalize_fingerprint(raw)
    if len(fingerprint) != SHA1_HEX_LENGTH:
        raise ValueError(
            f"{raw!r} is {len(fingerprint)} hex characters long. The API keys this operation on the "
            f"SHA-1 fingerprint, which is {SHA1_HEX_LENGTH} characters."
        )
    return fingerprint


def partition_fingerprints(raw_values: Iterable[str]) -> tuple[list[str], list[dict[str, str]]]:
    """Split raw indicator values into normalized fingerprints and rejected ones.

    Args:
        raw_values: Indicator values as supplied by the caller.

    Returns:
        tuple: ``(valid_fingerprints, rejected)`` where each rejected entry carries the original
        value and the reason it was rejected.
    """
    valid: list[str] = []
    rejected: list[dict[str, str]] = []
    for raw in raw_values:
        try:
            fingerprint = normalize_fingerprint(raw)
        except ValueError as error:
            rejected.append({"Fingerprint": raw, "Reason": str(error)})
            continue
        if fingerprint not in valid:
            valid.append(fingerprint)
    return valid, rejected


def collection_nodes(container: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Return the `nodes` of a `{totalCount, nodes}` block, tolerating nulls at both levels.

    `totalCount` is server-side metadata and is not guaranteed to equal ``len(nodes)``; the
    container itself can also be null. Never iterate ``range(totalCount)``.

    Args:
        container: A GraphQL connection object, or None.

    Returns:
        list: The nodes, or an empty list.
    """
    return (container or {}).get("nodes") or []


def first_common_name(name_holder: dict[str, Any] | None) -> str | None:
    """Return the first common name of a subject or issuer.

    `commonName` is an array in the CM SaaS schema, not a string.

    Args:
        name_holder: A `subject` or `issuer` object.

    Returns:
        str | None: The first common name, or None when there is none.
    """
    names = (name_holder or {}).get("commonName")
    if isinstance(names, str):
        return names
    return names[0] if names else None


def expiry_window_filter(days: int, include_expired: bool, now: datetime | None = None) -> dict[str, Any]:
    """Build a server-side `filterOn` clause for certificates expiring within `days`.

    `validityTo` takes a `CertificateDateFilter`, whose only range operator is
    `between` over a `CertificateDateRange` of `gte` / `lte`. A 30-day window is usually a
    small fraction of the inventory (about 1% on a large one), so filtering server-side
    rather than paging the inventory is a large reduction.

    Only the current, active version counts. After a renewal the old version stays `ACTIVE`
    with its old expiry and `isCurrent: false`, and search still returns it, as it returns
    retired certificates; without these two conditions an already-renewed certificate would
    still be reported as expiring.

    Args:
        days: Size of the expiry window, in days from now.
        include_expired: Whether to extend the lower bound to include already-expired
            certificates. `EXPIRED_LOOKBACK_DAYS` bounds how far back that reaches.
        now: Reference time, defaulting to the current UTC time. Injected for testability.

    Returns:
        dict[str, Any]: A `filterOn` clause for `searchCertificates`.
    """
    reference = now or datetime.now(UTC)
    lower = reference - timedelta(days=EXPIRED_LOOKBACK_DAYS) if include_expired else reference
    upper = reference + timedelta(days=days)
    return {
        "and": [
            {"validityTo": {"between": {"gte": to_iso_z(lower), "lte": to_iso_z(upper)}}},
            {"isCurrent": {"eq": True}},
            {"status": {"eq": GraphQLEnum(CERTIFICATE_STATUS_ACTIVE)}},
        ]
    }


def to_iso_z(moment: datetime) -> str:
    """Format a datetime as the `YYYY-MM-DDTHH:MM:SSZ` form the CM SaaS API accepts.

    Args:
        moment: The timestamp to format.

    Returns:
        str: The formatted timestamp.
    """
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def days_until_expiry(validity_to: str | None, now: datetime | None = None) -> int | None:
    """Compute whole days between now and a certificate's `validity.to`.

    There is no native days-until-expiry field in the CM SaaS schema.

    Args:
        validity_to: ISO-8601 expiry timestamp.
        now: Reference time, defaulting to the current UTC time. Injected for testability.

    Returns:
        int | None: Days remaining (negative once expired), or None if the timestamp is unusable.
    """
    expiry = arg_to_datetime(validity_to, required=False)
    if not expiry:
        return None
    reference = now or datetime.now(UTC)
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=UTC)
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=UTC)
    return (expiry - reference).days


def extract_subject_alternative_names(certificate: dict[str, Any]) -> list[str]:
    """Flatten the `subjectAlternativeNames` union into plain strings.

    Args:
        certificate: A raw `searchCertificates` node.

    Returns:
        list: The SAN values, in the order returned by the API.
    """
    value_keys = ("dnsName", "emailAddress", "uri", "ip")
    names: list[str] = []
    for entry in certificate.get("subjectAlternativeNames") or []:
        for key in value_keys:
            if value := (entry or {}).get(key):
                names.append(value)
                break
    return names


def public_key_context(public_key_information: dict[str, Any] | None) -> dict[str, Any]:
    """Map `publicKeyInformation` onto an algorithm / length / curve triple.

    Args:
        public_key_information: The raw union member, or None.

    Returns:
        dict: ``{"Algorithm": ..., "Length": ..., "Curve": ...}`` with unknown parts omitted.
    """
    info = public_key_information or {}
    algorithms = {
        "RSAKeyInfo": Common.CertificatePublicKey.Algorithm.RSA,
        "ECKeyInfo": Common.CertificatePublicKey.Algorithm.EC,
        "DSAKeyInfo": Common.CertificatePublicKey.Algorithm.DSA,
    }
    algorithm = algorithms.get(info.get("__typename") or "", Common.CertificatePublicKey.Algorithm.UNKNOWN)
    return assign_params(Algorithm=algorithm, Length=info.get("strength") or info.get("l"), Curve=info.get("curve"))


def installation_context(installation: dict[str, Any]) -> dict[str, Any]:
    """Map one `machineInstallations` node onto context.

    Args:
        installation: A raw installation node.

    Returns:
        dict: The installation, flattened.
    """
    machine = installation.get("machine") or {}
    return assign_params(
        ID=installation.get("id"),
        Status=installation.get("status"),
        MachineID=machine.get("id"),
        MachineName=machine.get("name"),
        PluginName=(machine.get("plugin") or {}).get("name"),
    )


def cloud_installation_context(installation: dict[str, Any]) -> dict[str, Any]:
    """Map one `cloudInstallations` node onto context.

    Args:
        installation: A raw cloud installation node.

    Returns:
        dict: The cloud installation, flattened.
    """
    metadata_type = (installation.get("metadata") or {}).get("__typename") or ""
    return assign_params(
        ID=installation.get("id"),
        Status=installation.get("status"),
        KeystoreID=installation.get("cloudKeystoreId"),
        KeystoreName=installation.get("cloudKeystoreName"),
        KeystoreType=KEYSTORE_TYPE_BY_METADATA.get(metadata_type),
        ProviderName=installation.get("cloudProviderName"),
    )


def installation_locations(installations: list[dict[str, Any]], cloud_installations: list[dict[str, Any]]) -> list[str]:
    """Describe where a certificate is installed, one readable entry per installation.

    A machine installation reads "label (plugin)"; the plugin name carries the store type for
    machine-based cloud stores such as Azure Key Vault. A cloud installation reads "type: keystore".

    Args:
        installations: Machine installation context entries.
        cloud_installations: Cloud installation context entries.

    Returns:
        list: The locations, without duplicates, in input order.
    """
    locations = []
    for installation in installations:
        name, plugin = installation.get("MachineName"), installation.get("PluginName")
        locations.append(f"{name} ({plugin})" if name and plugin else name or plugin)
    for installation in cloud_installations:
        store_type, keystore = installation.get("KeystoreType"), installation.get("KeystoreName")
        locations.append(f"{store_type}: {keystore}" if store_type and keystore else keystore or store_type)
    return list(dict.fromkeys(location for location in locations if location))


def endpoint_context(endpoint: dict[str, Any]) -> dict[str, Any]:
    """Map one `tlsServerEndpoints` node onto context.

    Args:
        endpoint: A raw endpoint node.

    Returns:
        dict: The endpoint, flattened.
    """
    return assign_params(
        ID=endpoint.get("id"),
        ServerName=endpoint.get("serverName"),
        IPAddress=endpoint.get("ipAddress"),
        Port=endpoint.get("port"),
        DeploymentStatus=endpoint.get("deploymentStatus"),
    )


def revocation_context(revocation: dict[str, Any] | None) -> dict[str, Any]:
    """Map the `revocation` block onto context.

    Every read path asks for this block: the reputation verdict depends on it. An unrevoked
    certificate returns all-null parts, which `assign_params` drops.

    Args:
        revocation: The raw `revocation` object, or None.

    Returns:
        dict: ``{"Status": ..., "Reason": ..., "Comment": ..., "Error": ...}`` with unknown parts omitted.
    """
    raw = revocation or {}
    return assign_params(
        Status=raw.get("status"),
        Reason=raw.get("reason"),
        Comment=raw.get("comment"),
        Error=(raw.get("error") or {}).get("message"),
    )


def global_revocation_context(global_revocation: dict[str, Any] | None) -> dict[str, Any]:
    """Map the `globalRevocation` block - the CA's own revocation list, not our request - onto context.

    Args:
        global_revocation: The raw `globalRevocation` object, or None.

    Returns:
        dict: ``{"Status": ..., "Reason": ..., "RevokedTime": ...}`` with unknown parts omitted.
    """
    raw = global_revocation or {}
    return assign_params(Status=raw.get("status"), Reason=raw.get("reason"), RevokedTime=raw.get("revokedTime"))


def certificate_to_context(certificate: dict[str, Any], source_brand: str, now: datetime | None = None) -> dict[str, Any]:
    """Map a raw `searchCertificates` node onto the `CertManagerSaaS.Certificate` context shape.

    Installation and application data have no home in the documented `Certificate` context
    standard, so they live under our own prefix.

    Args:
        certificate: A raw `searchCertificates` node.
        source_brand: The brand of the integration that returned the certificate.
        now: Reference time for the expiry calculation. Injected for testability.

    Returns:
        dict: The certificate in context form.
    """
    subject = certificate.get("subject") or {}
    issuer = certificate.get("issuer") or {}
    validity = certificate.get("validity") or {}
    installations = [installation_context(node) for node in collection_nodes(certificate.get("machineInstallations"))]
    cloud_installations = [cloud_installation_context(node) for node in collection_nodes(certificate.get("cloudInstallations"))]
    return assign_params(
        ID=certificate.get("id"),
        Name=certificate.get("name"),
        Fingerprint=certificate.get("fingerprint"),
        SerialNumber=certificate.get("serialNumber"),
        Status=certificate.get("status"),
        CommonName=first_common_name(subject),
        SubjectDN=subject.get("dn"),
        IssuerCommonName=first_common_name(issuer),
        IssuerDN=issuer.get("dn"),
        ValidFrom=validity.get("from"),
        ValidTo=validity.get("to"),
        ValidityPeriodSeconds=validity.get("period"),
        DaysUntilExpiry=days_until_expiry(validity.get("to"), now=now),
        IsSelfSigned=certificate.get("isSelfSigned"),
        IsCA=certificate.get("isCA"),
        IsPublic=certificate.get("isPublic"),
        SignatureAlgorithm=certificate.get("signatureAlgorithm"),
        SignatureHashAlgorithm=certificate.get("signatureHashAlgorithm"),
        KeyUsages=certificate.get("keyUsages"),
        Origins=certificate.get("origins"),
        LastModifiedTime=certificate.get("lastModifiedTime"),
        SubjectAlternativeNames=extract_subject_alternative_names(certificate),
        PublicKey=public_key_context(certificate.get("publicKeyInformation")),
        Applications=[assign_params(ID=app.get("id"), Name=app.get("name")) for app in certificate.get("applications") or []],
        Installations=installations,
        CloudInstallations=cloud_installations,
        InstallationLocations=installation_locations(installations, cloud_installations),
        TLSEndpoints=[endpoint_context(node) for node in collection_nodes(certificate.get("tlsServerEndpoints"))],
        Revocation=revocation_context(certificate.get("revocation")),
        GlobalRevocation=global_revocation_context(certificate.get("globalRevocation")),
        # The owner NGTS reports: the TSG ID for a tenant-owned certificate, else the workspace ID. GraphQL
        # `tsgId` is deprecated for `workspaceId`; the context keeps the TSGID name. NGTS only; null on CM SaaS.
        TSGID=certificate.get("workspaceId"),
        # Both integrations share this context path, so this is what tells a playbook where to send a write.
        SourceBrand=source_brand,
        # The instance that returned the certificate, for `using=`: a brand can have several instances (one per
        # tenant), and a write must reach the tenant that holds the certificate.
        SourceInstance=demisto.integrationInstance() or None,
    )


def is_revoked(certificate: dict[str, Any]) -> bool:
    """Tell whether a certificate counts as revoked.

    Confirmed revoked on the CA's revocation list, or submitted to a CA whose list cannot be checked
    (a private CA). A submission the list still shows as not revoked does not count.

    Args:
        certificate: A raw `searchCertificates` node.

    Returns:
        bool: True when the certificate counts as revoked.
    """
    global_status = (certificate.get("globalRevocation") or {}).get("status")
    submitted = (certificate.get("revocation") or {}).get("status") == REVOCATION_SUBMITTED
    return global_status == GLOBAL_REVOKED or (submitted and global_status != GLOBAL_NOT_REVOKED)


def is_key_compromise(certificate: dict[str, Any]) -> bool:
    """Tell whether the revocation reason is key compromise, from our request or from the CA's list.

    A key-compromise request an approver rejected does not count.

    Args:
        certificate: A raw `searchCertificates` node.

    Returns:
        bool: True for a key-compromise revocation.
    """
    revocation = certificate.get("revocation") or {}
    requested = revocation.get("reason") == KEY_COMPROMISE_REASON and revocation.get("status") != REVOCATION_REJECTED
    return requested or (certificate.get("globalRevocation") or {}).get("reason") == GLOBAL_KEY_COMPROMISE_REASON


def revocation_score(certificate: dict[str, Any], reported_key_compromise_score: int) -> int:
    """Score a certificate from its revocation, the only security assertion the vendor makes.

    Expiry and self-signed are hygiene, scored by the `CertificateReputation` script. Nothing scores
    GOOD: under the highest-reliability-wins rule, GOOD could hide another source's MALICIOUS verdict.

    Args:
        certificate: A raw `searchCertificates` node.
        reported_key_compromise_score: The score for a key compromise that is reported but not done.

    Returns:
        int: A `Common.DBotScore` value.
    """
    if not is_key_compromise(certificate):
        return Common.DBotScore.SUSPICIOUS if is_revoked(certificate) else Common.DBotScore.NONE
    if is_revoked(certificate):
        return Common.DBotScore.BAD
    # Failed, waiting for approval, or submitted but still on the CA's list as not revoked.
    if (certificate.get("revocation") or {}).get("status") in (*REVOCATION_REPORTED_STATUSES, REVOCATION_SUBMITTED):
        return reported_key_compromise_score
    return Common.DBotScore.NONE


def key_compromise_description(certificate: dict[str, Any], vendor: str) -> str:
    """Explain a MALICIOUS key-compromise verdict, attributed to the vendor.

    Args:
        certificate: A raw `searchCertificates` node.
        vendor: The product name the verdict is attributed to.

    Returns:
        str: The malicious description.
    """
    revocation = certificate.get("revocation") or {}
    global_revocation = certificate.get("globalRevocation") or {}
    if global_revocation.get("status") == GLOBAL_REVOKED:
        description = (
            f"Revoked for key compromise, confirmed on the issuing CA's revocation list on "
            f"{global_revocation.get('revokedTime')} (reported by {vendor})."
        )
    elif revocation.get("status") == REVOCATION_SUBMITTED:
        description = (
            f"A KEY_COMPROMISE revocation was submitted to the CA through {vendor}. The CA's revocation list "
            "cannot be checked, so the certificate is treated as revoked."
        )
    else:
        description = f"A KEY_COMPROMISE revocation was reported in {vendor} but is {revocation.get('status')}."
    comment = revocation.get("comment")
    return f"{description} Revocation comment: {comment}" if comment else description


def revocation_verdict(
    certificate: dict[str, Any], vendor: str, reported_key_compromise_score: int = Common.DBotScore.SUSPICIOUS
) -> tuple[int, str | None]:
    """Decide the DBotScore for a certificate, and the malicious description when there is one.

    Args:
        certificate: A raw `searchCertificates` node.
        vendor: The product name the verdict is attributed to.
        reported_key_compromise_score: The score for a key compromise that is reported but not done.

    Returns:
        tuple: `(score, malicious_description)`. The description is None unless the score is BAD.
    """
    score = revocation_score(certificate, reported_key_compromise_score)
    return score, key_compromise_description(certificate, vendor) if score == Common.DBotScore.BAD else None


def certificate_to_indicator(
    certificate: dict[str, Any], reliability: str, vendor: str, reported_key_compromise_score: int = Common.DBotScore.SUSPICIOUS
) -> Common.Certificate:
    """Map a raw certificate onto the standard `Common.Certificate` indicator.

    Scoring rule: **score only revocation**, see `revocation_score`. A DBotScore of BAD is not a
    severity label - the context standard requires it to be accompanied by a `Malicious` block
    attributed to a named vendor, which only a key-compromise revocation justifies.

    Note NONE is `0`, which the context standard glosses as "the vendor returns nothing on the
    indicator". Here it means "resolved, deliberately not scored" - a different thing. An
    unresolved fingerprint gets no DBotScore at all rather than a zero.

    Args:
        certificate: A raw `searchCertificates` node.
        reliability: The configured source reliability.
        vendor: The product name, used as the DBotScore vendor.
        reported_key_compromise_score: The score for a key compromise that is reported but not done.

    Returns:
        Common.Certificate: The standard indicator.
    """
    subject = certificate.get("subject") or {}
    issuer = certificate.get("issuer") or {}
    validity = certificate.get("validity") or {}
    fingerprint = normalize_fingerprint(certificate["fingerprint"])
    digest_field = DIGEST_FIELD_BY_LENGTH.get(len(fingerprint))
    digest: dict[str, Any] = {digest_field: fingerprint.lower()} if digest_field else {}
    public_key = public_key_context(certificate.get("publicKeyInformation"))
    score, malicious_description = revocation_verdict(certificate, vendor, reported_key_compromise_score)
    # Annotated to the wider element type `Common.Certificate` expects; list is invariant.
    subject_alternative_names: list[Any] = extract_subject_alternative_names(certificate)

    return Common.Certificate(
        subject_dn=subject.get("dn") or first_common_name(subject) or fingerprint,
        name=subject.get("commonName") or None,
        issuer_dn=issuer.get("dn"),
        serial_number=certificate.get("serialNumber"),
        validity_not_before=validity.get("from"),
        validity_not_after=validity.get("to"),
        signature_algorithm=certificate.get("signatureAlgorithm"),
        subject_alternative_name=subject_alternative_names or None,
        publickey=Common.CertificatePublicKey(
            # CSP types `length` as int and `curve` as str, but None is the honest value when the key type has no
            # length (EC) or no curve (RSA/DSA); CSP writes it into context unchanged.
            algorithm=public_key["Algorithm"],
            length=public_key.get("Length"),  # type: ignore[arg-type]
            curve=public_key.get("Curve"),  # type: ignore[arg-type]
        ),
        dbot_score=Common.DBotScore(
            indicator=fingerprint,
            indicator_type=DBotScoreType.CERTIFICATE,
            integration_name=vendor,
            score=score,
            reliability=reliability,
            malicious_description=malicious_description,
        ),
        **digest,
    )


def build_key_type_parameters(args: dict[str, Any]) -> dict[str, Any]:
    """Build the `keyTypeParameters` block of a certificate request.

    `keyType` is the only required member, so the whole block is omitted unless it was supplied.

    Args:
        args: Command arguments.

    Returns:
        dict: The block, or an empty dict.
    """
    key_type = args.get("key_type")
    if not key_type:
        return {}
    return assign_params(
        keyType=key_type.upper(),
        keyLength=arg_to_number(args.get("key_length")),
        keyCurve=(args.get("key_curve") or "").upper() or None,
    )


def build_csr_attributes(args: dict[str, Any]) -> dict[str, Any]:
    """Build the `csrAttributes` block used when Certificate Manager SaaS generates the key pair.

    Args:
        args: Command arguments.

    Returns:
        dict: The block.
    """
    alternative_names = assign_params(
        dnsNames=argToList(args.get("sans")),
        ipAddresses=argToList(args.get("ip_sans")),
    )
    return assign_params(
        commonName=args.get("common_name"),
        organization=args.get("organization"),
        organizationalUnits=argToList(args.get("organizational_units")),
        locality=args.get("locality"),
        state=args.get("state"),
        country=args.get("country"),
        keyTypeParameters=build_key_type_parameters(args),
        subjectAlternativeNamesByType=alternative_names,
    )


def build_certificate_request_body(args: dict[str, Any]) -> dict[str, Any]:
    """Build the `POST /outagedetection/v1/certificaterequests` body.

    Supplying a CSR and letting the service generate the key pair are mutually exclusive modes;
    `isVaaSGenerated` is what selects between them, and it is the only required field.

    Args:
        args: Command arguments.

    Returns:
        dict: The request body.

    Raises:
        ValueError: If neither a CSR nor a common name was given, or if the certificate to renew
            was identified twice.
    """
    signing_request = args.get("certificate_signing_request")
    existing_id = args.get("existing_certificate_id")
    existing_fingerprint = args.get("existing_certificate_fingerprint")
    if existing_id and existing_fingerprint:
        raise ValueError("'existing_certificate_id' and 'existing_certificate_fingerprint' are mutually exclusive.")
    if not signing_request and not args.get("common_name"):
        raise ValueError("Either 'certificate_signing_request' or 'common_name' is required.")
    # A key-generating renewal rebuilds the subject from `csrAttributes` and silently drops every field left out.
    # With `renewType` the service copies the old certificate's subject and SANs instead, so only the key settings
    # are sent; `csrAttributes` is still required, and its common name is ignored.
    cloned_renewal = bool(existing_id or existing_fingerprint) and not signing_request
    if signing_request:
        csr_attributes = None
    elif cloned_renewal:
        csr_attributes = assign_params(commonName=args.get("common_name"), keyTypeParameters=build_key_type_parameters(args))
    else:
        csr_attributes = build_csr_attributes(args)

    body = assign_params(
        applicationId=args.get("application_id"),
        certificateIssuingTemplateId=args.get("certificate_issuing_template_id"),
        validityPeriod=args.get("validity_period"),
        existingCertificateId=existing_id,
        existingCertificateFingerprint=normalize_sha1_fingerprint(existing_fingerprint) if existing_fingerprint else None,
        tags=argToList(args.get("tags")),
        certificateSigningRequest=signing_request,
        csrAttributes=csr_attributes,
        renewType=RENEW_TYPE_CLONED if cloned_renewal else None,
    )
    body["isVaaSGenerated"] = not signing_request
    return body


def certificate_request_to_context(request: dict[str, Any]) -> dict[str, Any]:
    """Map a `CertificateRequestInformation` object onto context.

    Args:
        request: The raw certificate request.

    Returns:
        dict: The request, flattened.
    """
    error = request.get("errorInformation") or {}
    return assign_params(
        ID=request.get("id"),
        Status=request.get("status"),
        ApplicationID=request.get("applicationId"),
        CertificateIssuingTemplateID=request.get("certificateIssuingTemplateId"),
        CertificateIDs=request.get("certificateIds"),
        SubjectDN=request.get("subjectDN"),
        KeyType=request.get("keyType"),
        KeyLength=request.get("keyLength"),
        KeyCurve=request.get("keyCurve"),
        ValidityPeriod=request.get("validityPeriod"),
        CreationDate=request.get("creationDate"),
        ModificationDate=request.get("modificationDate"),
        CertificateAuthorityOrderID=request.get("caOrderId"),
        Tags=request.get("tags"),
        ErrorCode=error.get("code"),
        ErrorMessage=error.get("message"),
    )


def normalize_host(raw_host: str | None) -> str | None:
    """Reduce a `connectionDetails` host to a bare lowercase hostname or address.

    The field arrives as an FQDN, a bare IPv4, or a full URL - sometimes with a `user@` prefix,
    a path, or a `:port` suffix.

    Args:
        raw_host: The raw value, or None.

    Returns:
        str | None: The normalized host, or None when nothing usable remains.
    """
    host = (raw_host or "").strip()
    if not host:
        return None
    host = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", host)
    host = host.split("@")[-1]
    host = re.split(r"[/?#]", host)[0]
    host = re.sub(r":\d+$", "", host)
    return host.lower() or None


def connection_address(connection_details: dict[str, Any]) -> tuple[str | None, Any]:
    """Find the device address in a machine's `connectionDetails`.

    Most plugins put it at the top level; protocol-based ones such as Common KeyStore nest it
    one level down, e.g. ``{"protocol": "ssh2", "protocolSsh": {"hostnameOrAddress": ..., "port": 22}}``.

    Args:
        connection_details: The raw `connectionDetails` object.

    Returns:
        tuple: ``(raw_host, port)``, either of which can be None.
    """
    blocks = [connection_details] + [value for value in connection_details.values() if isinstance(value, dict)]
    for block in blocks:
        raw_host = block.get("host") or block.get("hostnameOrAddress")
        if raw_host:
            return raw_host, block.get("port") or block.get("TcpPort")
    return None, connection_details.get("port") or connection_details.get("TcpPort")


# `connectionDetails` is plugin-defined. Credentials come back as references today, but that is not a
# contract across every plugin, so only keys known to be non-secret reach context.
SAFE_CONNECTION_KEYS = frozenset(
    {
        "host",
        "hostnameOrAddress",
        "port",
        "TcpPort",
        "protocol",
        "keyVaultName",
        "tenantId",
        "subscriptionId",
        "resourceGroup",
        "serviceName",
        "projectId",
        "region",
        "location",
        "partition",
        "credentialType",
    }
)


def safe_connection_details(connection_details: dict[str, Any]) -> dict[str, Any]:
    """Keep only the allow-listed, non-secret keys of `connectionDetails`, one nesting level deep.

    Args:
        connection_details: The raw `connectionDetails` object.

    Returns:
        dict: The allow-listed keys; nested protocol blocks keep their allow-listed keys only.
    """
    safe: dict[str, Any] = {}
    for key, value in connection_details.items():
        if isinstance(value, dict):
            nested = {
                inner: value[inner] for inner in value if inner in SAFE_CONNECTION_KEYS and not isinstance(value[inner], dict)
            }
            if nested:
                safe[key] = nested
        elif key in SAFE_CONNECTION_KEYS:
            safe[key] = value
    return safe


def extract_list(payload: Any, *keys: str) -> list[dict[str, Any]]:
    """Pull a list out of a REST payload that may be the list itself or wrap it under a key.

    Args:
        payload: The decoded REST response.
        keys: Candidate wrapper keys, tried in order.

    Returns:
        list: The extracted list, or an empty list.
    """
    if isinstance(payload, list):
        return payload
    for key in keys:
        value = (payload or {}).get(key)
        if isinstance(value, list):
            return value
    return []


def api_errors(response: requests.Response) -> list[dict[str, Any]]:
    """Read the `errors` array of a failed REST response.

    Args:
        response: The failing response.

    Returns:
        list: The error objects, each with `code` and `message`, or an empty list when the body has none.
    """
    try:
        payload = response.json()
    except ValueError:
        return []
    errors = payload.get("errors") if isinstance(payload, dict) else None
    return [error for error in errors if isinstance(error, dict)] if isinstance(errors, list) else []


def seal_passphrase(passphrase: str, public_key: str) -> str:
    """Encrypt a passphrase for the VSatellite that holds a private key.

    The service never sees the passphrase in clear: it travels as a libsodium sealed box to the VSatellite's
    edge encryption key. The key is labelled ED25519 but is used raw, with no conversion to X25519.

    Args:
        passphrase: The passphrase that protects the exported private key.
        public_key: The base64 `key` of `GET /v1/edgeencryptionkeys/{dekHash}`.

    Returns:
        str: The sealed passphrase, base64-encoded.
    """
    sealed = SealedBox(PublicKey(base64.b64decode(public_key))).encrypt(passphrase.encode("utf-8"))
    return base64.b64encode(sealed).decode("ascii")


def build_keystore_request_body(export_format: str, sealed_passphrase: str) -> dict[str, str]:
    """Build the `POST /outagedetection/v1/certificates/{id}/keystore` body.

    Args:
        export_format: `PEM` or `PKCS12`.
        sealed_passphrase: The passphrase, sealed for the VSatellite.

    Returns:
        dict: The request body. A PKCS#12 file is also protected by the passphrase; a PEM zip is not.
    """
    return {
        "exportFormat": export_format,
        "encryptedPrivateKeyPassphrase": sealed_passphrase,
        "encryptedKeystorePassphrase": sealed_passphrase if export_format == "PKCS12" else "",
        "certificateLabel": "",
    }


def keystore_base_name(certificate: dict[str, Any], certificate_id: str) -> str:
    """Name the keystore files after the certificate's common name.

    Args:
        certificate: The REST certificate object, whose `subjectCN` is an array.
        certificate_id: The certificate identifier, used when there is no common name.

    Returns:
        str: A file-name-safe base name; a wildcard `*.example.com` becomes `_.example.com`.
    """
    common_name = first_common_name({"commonName": certificate.get("subjectCN")}) or ""
    return re.sub(r"[^A-Za-z0-9._-]", "_", common_name) or certificate_id


def unpack_pem_keystore(content: bytes) -> tuple[bytes, bytes]:
    """Take the encrypted private key and the leaf-first chain out of a PEM keystore zip.

    Args:
        content: The zip returned by the keystore export.

    Returns:
        tuple: ``(encrypted_private_key, chain)``, both PEM, exactly as returned.

    Raises:
        DemistoException: If the body is not a zip, or lacks either file.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            names = archive.namelist()
            key_name = next((name for name in names if name.endswith(PEM_KEY_ENTRY_SUFFIX)), None)
            chain_name = next((name for name in names if name.endswith(PEM_CHAIN_ENTRY_SUFFIX)), None)
            if not key_name or not chain_name:
                raise DemistoException(f"The PEM keystore has no private key or no chain file. It holds: {', '.join(names)}.")
            return archive.read(key_name), archive.read(chain_name)
    except zipfile.BadZipFile as error:
        raise DemistoException(f"The PEM keystore is not a zip archive: {error}") from error


def keystore_files(content: bytes, export_format: str, base_name: str) -> dict[str, tuple[str, bytes]]:
    """Split a keystore export into the files to return, keyed by the context field that names each one.

    Args:
        content: The body of the keystore export.
        export_format: `PEM` (a zip) or `PKCS12` (the raw .p12, not zipped).
        base_name: The base file name.

    Returns:
        dict: ``{context_field: (file_name, data)}``.
    """
    if export_format == "PKCS12":
        return {"KeystoreFileName": (f"{base_name}.p12", content)}
    private_key, chain = unpack_pem_keystore(content)
    return {"PrivateKeyFileName": (f"{base_name}.key", private_key), "ChainFileName": (f"{base_name}.pem", chain)}


""" CLIENT CLASS """


class CertificateManagerClient(BaseClient):
    """Talks to the two CM SaaS surfaces: GraphQL for certificates, REST for machines.

    Authentication is the subclass's job: a static credential goes into `headers`; a per-request one
    is attached by overriding `_http_request`.
    """

    def __init__(
        self,
        base_url: str,
        product: ProductProfile,
        verify: bool,
        proxy: bool,
        headers: dict[str, str] | None = None,
    ):
        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            timeout=HTTP_TIMEOUT,
            headers={**(headers or {}), "Accept": "application/json", "User-Agent": product.user_agent},
        )
        self.product = product

    def raise_http_error(self, response: requests.Response) -> None:
        """Translate an HTTP failure into an actionable, product-specific message.

        Args:
            response: The failing response.

        Raises:
            DemistoException: Always.
        """
        messages = {404: NOT_FOUND_MESSAGE, **self.product.http_error_messages}
        default = f"Request to {self.product.name} failed with HTTP {response.status_code}: {response.text}"
        raise DemistoException(messages.get(response.status_code, default))

    def graphql(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
        """Execute a GraphQL document and return its `data` block.

        Args:
            query: The GraphQL document.
            variables: The GraphQL variables.

        Returns:
            dict: The `data` block.

        Raises:
            GraphQLQueryError: If the response carries a top-level `errors` array. The gateway
                answers HTTP 200 in that case, so the status code alone is not a success signal.
        """
        response = self._http_request(
            "POST",
            url_suffix=GRAPHQL_URL_SUFFIX,
            json_data={"query": query, "variables": variables},
            error_handler=self.raise_http_error,
        )
        if errors := (response or {}).get("errors"):
            details = "; ".join(str((error or {}).get("message", error)) for error in errors)
            raise GraphQLQueryError(f"The {self.product.name} GraphQL gateway returned errors: {details}")
        return (response or {}).get("data") or {}

    def search_certificates(
        self, first: int, after: str | None = None, filter_on: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Run one page of `searchCertificates`.

        Args:
            first: Page size. Capped at 100 by the server.
            after: Opaque cursor from the previous page's `pageInfo.endCursor`.
            filter_on: Optional server-side filter expression.

        Returns:
            dict: The `searchCertificates` connection object.
        """
        variables = {"first": min(first, MAX_PAGE_SIZE), "after": after}
        data = self.graphql(build_search_query(filter_on), variables)
        return data.get("searchCertificates") or {}

    def revoke_certificate(self, fingerprint: str, reason: str, comment: str | None) -> dict[str, Any] | None:
        """Revoke one certificate.

        Both argument types are named in the schema, so - unlike the search filter - they are
        passed as GraphQL variables rather than inlined.

        Args:
            fingerprint: The SHA-1 fingerprint, as bare uppercase hex.
            reason: A `RevocationReason` enum value.
            comment: Free text stored on the revocation, or None.

        Returns:
            dict | None: The revoked certificate, or None when nothing matched the fingerprint.
        """
        variables = {"fingerprint": fingerprint, "revocationReason": reason, "revocationComment": comment}
        data = self.graphql(REVOKE_CERTIFICATE_MUTATION, variables)
        return data.get("revokeCertificate")

    def get_expiry_thresholds(self) -> list[int]:
        """Read the expiry thresholds the tenant notifies on. A subclass can override the source."""
        data = self.graphql(ACTIVE_THRESHOLDS_QUERY, {})
        return (data.get("getCertExpActiveThresholds") or {}).get("thresholds") or []

    def create_certificate_request(self, body: dict[str, Any]) -> Any:
        """Submit a certificate request."""
        return self._http_request(
            "POST", url_suffix=CERTIFICATE_REQUESTS_URL_SUFFIX, json_data=body, error_handler=self.raise_http_error
        )

    def get_certificate_request(self, request_id: str) -> dict[str, Any]:
        """Read one certificate request, including its status and any error information."""
        return self._http_request(
            "GET", url_suffix=f"{CERTIFICATE_REQUESTS_URL_SUFFIX}/{request_id}", error_handler=self.raise_http_error
        )

    def download_certificate(self, certificate_id: str, encoding: str, params: dict[str, Any]) -> bytes:
        """Download the contents of one certificate.

        Args:
            certificate_id: The certificate UUID. This endpoint is keyed on the id, not the
                fingerprint - `CertManagerSaaS.Certificate.ID` is where that comes from.
            encoding: `PEM` or `DER`, which also selects the `Accept` header.
            params: Additional query parameters, already filtered of empty values.

        Returns:
            bytes: The raw certificate payload.
        """
        headers = {**(self._headers or {}), "Accept": DOWNLOAD_ACCEPT_BY_FORMAT[encoding]}
        return self._http_request(
            "GET",
            url_suffix=CERTIFICATE_CONTENTS_URL_TEMPLATE.format(certificate_id=certificate_id),
            params={"format": encoding, **params},
            headers=headers,
            resp_type="content",
            error_handler=self.raise_http_error,
        )

    def raise_keystore_error(self, response: requests.Response) -> None:
        """Translate a keystore export failure, quoting the API's own error message.

        Args:
            response: The failing response.

        Raises:
            DemistoException: Always.
        """
        errors = api_errors(response)
        if any(error.get("code") == ISSUER_CHAIN_MISSING_CODE for error in errors):
            raise DemistoException(
                f"{self.product.name} can't build the keystore: the issuing CA didn't provide the issuer certificates "
                f"(the chain), and the export needs them (error {ISSUER_CHAIN_MISSING_CODE})."
            )
        messages = [str(error["message"]) for error in errors if error.get("message")]
        if messages and response.status_code not in self.product.http_error_messages:
            raise DemistoException(f"The keystore download failed (HTTP {response.status_code}): {'; '.join(messages)}")
        self.raise_http_error(response)

    def raise_edge_key_error(self, response: requests.Response) -> None:
        """Explain a missing VSatellite encryption key, then fall back to the keystore translation.

        Args:
            response: The failing response.

        Raises:
            DemistoException: Always.
        """
        if response.status_code == 404:
            raise DemistoException(
                "The VSatellite encryption key that protects this private key no longer exists (HTTP 404), for example "
                "because the VSatellite was registered again. The private key can't be exported."
            )
        self.raise_keystore_error(response)

    def get_certificate_by_id(self, certificate_id: str) -> dict[str, Any]:
        """Read one certificate over REST, including `dekHash`, which GraphQL doesn't serve."""
        return self._http_request(
            "GET",
            url_suffix=CERTIFICATE_URL_TEMPLATE.format(certificate_id=certificate_id),
            error_handler=self.raise_keystore_error,
        )

    def get_edge_encryption_key(self, dek_hash: str) -> dict[str, Any]:
        """Read the VSatellite encryption key a private key is stored under: `{key, keyAlgorithm}`."""
        return self._http_request(
            "GET",
            url_suffix=EDGE_ENCRYPTION_KEY_URL_TEMPLATE.format(dek_hash=dek_hash),
            error_handler=self.raise_edge_key_error,
        )

    def export_keystore(self, certificate_id: str, body: dict[str, str]) -> bytes:
        """Export a certificate with its private key. Success is HTTP 201 with a binary body.

        Args:
            certificate_id: The certificate UUID.
            body: The request body, with the passphrase already sealed.

        Returns:
            bytes: The keystore: a zip for PEM, the raw .p12 for PKCS12.
        """
        return self._http_request(
            "POST",
            url_suffix=CERTIFICATE_KEYSTORE_URL_TEMPLATE.format(certificate_id=certificate_id),
            json_data=body,
            headers={**(self._headers or {}), "Accept": KEYSTORE_ACCEPT},
            resp_type="content",
            error_handler=self.raise_keystore_error,
        )

    def list_machines(self) -> Any:
        """List machines. Metadata only - no connection details."""
        return self._http_request("GET", url_suffix=MACHINES_URL_SUFFIX, error_handler=self.raise_http_error)

    def get_machine(self, machine_id: str) -> dict[str, Any]:
        """Read one machine, including `connectionDetails` - the only source of a device host."""
        return self._http_request("GET", url_suffix=f"{MACHINES_URL_SUFFIX}/{machine_id}", error_handler=self.raise_http_error)


""" PAGING """


def collect_certificates(
    client: CertificateManagerClient,
    limit: int,
    filter_on: dict[str, Any] | None = None,
    predicate: Callable[[dict[str, Any]], bool] | None = None,
    max_pages: int = DEFAULT_MAX_PAGES,
) -> tuple[list[dict[str, Any]], bool]:
    """Walk `searchCertificates` pages until `limit` matches are collected.

    Args:
        client: The client.
        limit: Maximum number of certificates to return.
        filter_on: Optional server-side filter.
        predicate: Optional client-side filter, applied to each node.
        max_pages: Safety bound on the number of pages fetched.

    Returns:
        tuple: ``(certificates, more_available)``. ``more_available`` is True when the walk
        stopped at the limit or the page bound rather than at the end of the result set.
    """
    collected: list[dict[str, Any]] = []
    cursor: str | None = None
    for _ in range(max_pages):
        page = client.search_certificates(first=MAX_PAGE_SIZE, after=cursor, filter_on=filter_on)
        for node in collection_nodes(page):
            if predicate and not predicate(node):
                continue
            collected.append(node)
            if len(collected) >= limit:
                return collected, True
        page_info = page.get("pageInfo") or {}
        cursor = page_info.get("endCursor")
        if not page_info.get("hasNextPage") or not cursor:
            return collected, False
    return collected, True


""" COMMAND FUNCTIONS """


def threshold_alignment_message(client: CertificateManagerClient) -> str:
    """Describe how the tenant's expiry thresholds line up with the severity ladder.

    The thresholds are tenant-global and customer-configured, so the tenant's own expiry
    notifications can fire on days that the severity ladder does not distinguish - and neither side
    would report it. This is diagnostic only: the fetch uses its own window and works regardless.

    Args:
        client: The client.

    Returns:
        str: A human-readable summary.
    """
    try:
        thresholds = client.get_expiry_thresholds()
    except Exception as error:
        # The thresholds source may not be allow-listed or permitted for this credential. Failing the
        # connection test over a diagnostic would be wrong.
        return f"Could not read the tenant's certificate-expiry thresholds: {error}"
    if not thresholds:
        return "The tenant has no certificate-expiry thresholds configured, so it sends no expiry notifications."
    missing = [days for days in (CRITICAL_EXPIRY_DAYS, HIGH_EXPIRY_DAYS) if days not in thresholds]
    if missing:
        return (
            f"The tenant notifies on thresholds {thresholds}, which does not include "
            f"{missing} - the severity ladder of this integration will not line up with its expiry notifications."
        )
    return f"The tenant notifies on thresholds {thresholds}, which covers the severity ladder."


def certificate_command(
    client: CertificateManagerClient,
    args: dict[str, Any],
    reliability: str,
    reported_key_compromise_score: int = Common.DBotScore.SUSPICIOUS,
) -> list[CommandResults]:
    """Enrich certificate indicators from the certificate inventory.

    Args:
        client: The client.
        args: Command arguments. ``certificate`` is a comma-separated list of fingerprints.
        reliability: The configured source reliability.
        reported_key_compromise_score: The score for a key compromise that is reported but not done.

    Returns:
        list: One CommandResults per resolved certificate, plus one summarizing anything
        unresolved.
    """
    raw_values = argToList(args.get("certificate"))
    if not raw_values:
        raise ValueError("The 'certificate' argument is required and must contain at least one fingerprint.")

    fingerprints, unresolved = partition_fingerprints(raw_values)
    found: dict[str, dict[str, Any]] = {}
    for start in range(0, len(fingerprints), MAX_PAGE_SIZE):
        batch = fingerprints[start : start + MAX_PAGE_SIZE]
        page = client.search_certificates(first=len(batch), filter_on={"and": {"fingerprint": {"in": batch}}})
        for node in collection_nodes(page):
            try:
                found[normalize_fingerprint(node.get("fingerprint") or "")] = node
            except ValueError:
                # A node whose fingerprint we cannot normalize cannot be matched back to an
                # input value; dropping it is safer than guessing which request it answered.
                demisto.debug(f"Skipping a certificate with an unrecognized fingerprint shape: id={node.get('id')}")

    results = [
        build_certificate_result(node, reliability, client.product, reported_key_compromise_score)
        for node in (found[fp] for fp in fingerprints if fp in found)
    ]

    # A certificate the tenant does not return is the weakest signal this API gives: an unknown
    # fingerprint and a deleted certificate are both HTTP 200 with totalCount 0. Emitting
    # DBotScore 0 here would present "we could not look this up" as "we looked it up and found
    # nothing", so no DBotScore is produced for unresolved values at all.
    missing_reason = "No certificate with this fingerprint was returned by the tenant."
    unresolved += [{"Fingerprint": fp, "Reason": missing_reason} for fp in fingerprints if fp not in found]
    if unresolved:
        results.append(build_unresolved_result(unresolved))
    return results


def certificate_readable_row(
    certificate: dict[str, Any], context: dict[str, Any], reported_key_compromise_score: int
) -> dict[str, Any]:
    """Add the revocation and the verdict to a certificate's War Room row, so an analyst sees the score.

    Args:
        certificate: A raw `searchCertificates` node.
        context: The certificate's context entry.
        reported_key_compromise_score: The score for a key compromise that is reported but not done.

    Returns:
        dict: The context entry with flat `Revocation` and `Verdict` values.
    """
    revocation = context.get("Revocation") or {}
    reason = f"({revocation['Reason']})" if revocation.get("Reason") else None
    score = revocation_score(certificate, reported_key_compromise_score)
    labels = {value: label for label, value in REPORTED_KEY_COMPROMISE_SCORES.items()}
    return {
        **context,
        "Revocation": " ".join(filter(None, [revocation.get("Status"), reason])) or None,
        "Verdict": labels.get(score, "Unknown"),
    }


def build_certificate_result(
    certificate: dict[str, Any],
    reliability: str,
    product: ProductProfile,
    reported_key_compromise_score: int = Common.DBotScore.SUSPICIOUS,
) -> CommandResults:
    """Build the CommandResults for one resolved certificate indicator.

    Args:
        certificate: A raw `searchCertificates` node.
        reliability: The configured source reliability.
        product: The product profile: its name is the DBotScore vendor, its brand the `SourceBrand`.
        reported_key_compromise_score: The score for a key compromise that is reported but not done.

    Returns:
        CommandResults: The indicator plus our own context entry.
    """
    context = certificate_to_context(certificate, product.brand)
    return CommandResults(
        readable_output=tableToMarkdown(
            f"Certificate {context.get('Fingerprint')}",
            certificate_readable_row(certificate, context, reported_key_compromise_score),
            headers=[
                "Fingerprint",
                "CommonName",
                "IssuerCommonName",
                "Status",
                "Revocation",
                "Verdict",
                "ValidTo",
                "DaysUntilExpiry",
            ],
            removeNull=True,
        ),
        outputs_prefix=f"{CONTEXT_PREFIX}.Certificate",
        outputs_key_field="Fingerprint",
        outputs=context,
        raw_response=certificate,
        indicator=certificate_to_indicator(certificate, reliability, product.name, reported_key_compromise_score),
    )


def build_unresolved_result(unresolved: list[dict[str, str]]) -> CommandResults:
    """Build the CommandResults describing fingerprints that could not be enriched.

    Args:
        unresolved: Entries of ``{"Fingerprint": ..., "Reason": ...}``.

    Returns:
        CommandResults: A warning table, with no DBotScore attached.
    """
    return CommandResults(
        readable_output=tableToMarkdown(
            "Unresolved certificates (no reputation was produced)",
            unresolved,
            headers=["Fingerprint", "Reason"],
        )
        + "\n**Note:** the API answers an unknown *and* a malformed fingerprint identically "
        "(HTTP 200, no results), so absence here is not evidence that the certificate does not exist.",
        outputs_prefix=f"{CONTEXT_PREFIX}.UnresolvedCertificate",
        outputs_key_field="Fingerprint",
        outputs=unresolved,
    )


def certificate_search_command(client: CertificateManagerClient, args: dict[str, Any]) -> CommandResults:
    """Search the certificate inventory.

    Only `fingerprint` is filtered server-side; the other criteria weren't checked as
    server-side filters here, and `id` is not filterable at all. The remaining criteria are applied
    client-side over a bounded page walk, which is reported in the output.

    Args:
        client: The client.
        args: Command arguments.

    Returns:
        CommandResults: The matching certificates.
    """
    limit = arg_to_number(args.get("limit")) or DEFAULT_LIMIT
    max_pages = arg_to_number(args.get("max_pages")) or DEFAULT_MAX_PAGES
    fingerprint = args.get("fingerprint")
    filter_on = {"and": {"fingerprint": {"eq": normalize_fingerprint(fingerprint)}}} if fingerprint else None
    predicate = build_search_predicate(
        common_name=args.get("common_name"),
        issuer=args.get("issuer"),
        status=args.get("status"),
        expires_in_days=arg_to_number(args.get("expires_in_days")),
    )

    certificates, more_available = collect_certificates(
        client, limit=limit, filter_on=filter_on, predicate=predicate, max_pages=max_pages
    )
    title = f"{client.product.name} certificates"
    return build_certificate_list_result(certificates, title, more_available, client.product.brand)


def build_search_predicate(
    common_name: str | None = None,
    issuer: str | None = None,
    status: str | None = None,
    expires_in_days: int | None = None,
) -> Callable[[dict[str, Any]], bool] | None:
    """Build a client-side certificate predicate from the search criteria.

    Args:
        common_name: Case-insensitive substring matched against the subject CN and the SANs.
        issuer: Case-insensitive substring matched against the issuer CN and DN.
        status: Exact, case-insensitive certificate status.
        expires_in_days: Keep only certificates expiring within this many days.

    Returns:
        Callable | None: The predicate, or None when no criteria were given.
    """
    if not any([common_name, issuer, status, expires_in_days is not None]):
        return None

    def matches(certificate: dict[str, Any]) -> bool:
        if common_name:
            haystack = [first_common_name(certificate.get("subject")) or ""] + extract_subject_alternative_names(certificate)
            if not any(common_name.lower() in candidate.lower() for candidate in haystack):
                return False
        if issuer:
            issuer_data = certificate.get("issuer") or {}
            haystack = [first_common_name(issuer_data) or "", issuer_data.get("dn") or ""]
            if not any(issuer.lower() in candidate.lower() for candidate in haystack):
                return False
        if status and (certificate.get("status") or "").lower() != status.lower():
            return False
        if expires_in_days is not None:
            remaining = days_until_expiry((certificate.get("validity") or {}).get("to"))
            if remaining is None or remaining > expires_in_days:
                return False
        return True

    return matches


def certificate_readable_output(title: str, context: dict[str, Any]) -> str:
    """Render one certificate, with each kind of installation as a table of its own.

    Args:
        title: The certificate table title.
        context: The certificate context entry.

    Returns:
        str: The markdown.
    """
    nested = {key for key, _, _ in INSTALLATION_TABLES}
    readable = tableToMarkdown(title, {k: v for k, v in context.items() if k not in nested}, removeNull=True)
    for key, heading, headers in INSTALLATION_TABLES:
        if context.get(key):
            readable += "\n" + tableToMarkdown(heading, context[key], headers=headers, removeNull=True)
    return readable


def certificate_get_command(client: CertificateManagerClient, args: dict[str, Any]) -> CommandResults:
    """Retrieve one certificate by fingerprint, optionally resolving its machines' hosts.

    Args:
        client: The client.
        args: Command arguments. ``fingerprint`` is required.

    Returns:
        CommandResults: The certificate.
    """
    fingerprint = normalize_fingerprint(args["fingerprint"])
    page = client.search_certificates(first=1, filter_on={"and": {"fingerprint": {"eq": fingerprint}}})
    nodes = collection_nodes(page)
    if not nodes:
        return CommandResults(
            readable_output=f"No certificate with fingerprint {fingerprint} was returned by the tenant. "
            "Note that the API cannot distinguish an unknown fingerprint from a deleted certificate."
        )

    certificate = nodes[0]
    context = certificate_to_context(certificate, client.product.brand)
    if argToBoolean(args.get("include_machine_details") or False):
        context["Installations"] = enrich_installations_with_hosts(client, context.get("Installations") or [])

    return CommandResults(
        readable_output=certificate_readable_output(f"Certificate {fingerprint}", context),
        outputs_prefix=f"{CONTEXT_PREFIX}.Certificate",
        outputs_key_field="Fingerprint",
        outputs=context,
        raw_response=certificate,
    )


def enrich_installations_with_hosts(
    client: CertificateManagerClient, installations: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Add the device host to each installation by reading the machine detail endpoint.

    Roughly half of machines carry no host at all - cloud connectors such as Azure Key Vault
    expose a vault name instead. A missing host is a normal outcome, not an error.

    Args:
        client: The client.
        installations: Installation context entries carrying `MachineID`.

    Returns:
        list: The same entries, with `Host` added where one exists.
    """
    hosts: dict[str, str | None] = {}
    enriched = []
    for installation in installations:
        machine_id = installation.get("MachineID")
        if machine_id and machine_id not in hosts:
            connection_details = (client.get_machine(machine_id) or {}).get("connectionDetails") or {}
            raw_host, _ = connection_address(connection_details)
            hosts[machine_id] = normalize_host(raw_host)
        enriched.append(assign_params(Host=hosts.get(machine_id) if machine_id else None, **installation))
    return enriched


def certificate_list_expiring_command(client: CertificateManagerClient, args: dict[str, Any]) -> CommandResults:
    """List certificates expiring within a window, soonest first.

    Args:
        client: The client.
        args: Command arguments.

    Returns:
        CommandResults: The expiring certificates.
    """
    days = arg_to_number(args.get("days")) or DEFAULT_EXPIRY_DAYS
    limit = arg_to_number(args.get("limit")) or DEFAULT_LIMIT
    max_pages = arg_to_number(args.get("max_pages")) or DEFAULT_MAX_PAGES
    include_expired = argToBoolean(args.get("include_expired") or False)

    filter_on = expiry_window_filter(days, include_expired)
    certificates, more_available = collect_certificates(client, limit=limit, filter_on=filter_on, max_pages=max_pages)
    certificates.sort(key=lambda certificate: (certificate.get("validity") or {}).get("to") or "")
    title = f"{client.product.name} certificates expiring within {days} day(s)"
    return build_certificate_list_result(certificates, title, more_available, client.product.brand)


def build_certificate_list_result(
    certificates: list[dict[str, Any]], title: str, more_available: bool, source_brand: str
) -> CommandResults:
    """Build the CommandResults for a list of certificates.

    Args:
        certificates: Raw `searchCertificates` nodes.
        title: Human-readable table title.
        more_available: Whether the page walk stopped early.
        source_brand: The brand of the integration that returned the certificates.

    Returns:
        CommandResults: The list, with a truncation note when relevant.
    """
    context = [certificate_to_context(certificate, source_brand) for certificate in certificates]
    note = "\n**Note:** the result was truncated. Raise `limit` / `max_pages`, or narrow the search." if more_available else ""
    return CommandResults(
        readable_output=tableToMarkdown(
            title,
            context,
            headers=["Fingerprint", "CommonName", "IssuerCommonName", "Status", "ValidTo", "DaysUntilExpiry"],
            removeNull=True,
        )
        + note,
        outputs_prefix=f"{CONTEXT_PREFIX}.Certificate",
        outputs_key_field="Fingerprint",
        outputs=context or None,
        raw_response=certificates,
    )


def machine_list_command(client: CertificateManagerClient, args: dict[str, Any]) -> CommandResults:
    """List machines. Metadata only - the host lives on the machine detail endpoint.

    Args:
        client: The client.
        args: Command arguments.

    Returns:
        CommandResults: The machines.
    """
    limit = arg_to_number(args.get("limit")) or DEFAULT_LIMIT
    raw = client.list_machines()
    machines = extract_list(raw, "machines")[:limit]
    context = [machine_to_context(machine) for machine in machines]
    return CommandResults(
        readable_output=tableToMarkdown(
            f"{client.product.name} machines",
            context,
            headers=["ID", "Name", "Status", "PluginID"],
            removeNull=True,
        ),
        outputs_prefix=f"{CONTEXT_PREFIX}.Machine",
        outputs_key_field="ID",
        outputs=context or None,
        # Not the raw page: a machine's `connectionDetails` can hold secrets, so only allow-listed keys leave here.
        raw_response=context,
    )


def machine_get_command(client: CertificateManagerClient, args: dict[str, Any]) -> CommandResults:
    """Retrieve one machine, including its normalized host where one exists.

    Args:
        client: The client.
        args: Command arguments. ``machine_identifier`` is required.

    Returns:
        CommandResults: The machine.
    """
    machine = client.get_machine(args["machine_identifier"])
    context = machine_to_context(machine)
    return CommandResults(
        readable_output=tableToMarkdown(f"Machine {context.get('ID')}", context, removeNull=True),
        outputs_prefix=f"{CONTEXT_PREFIX}.Machine",
        outputs_key_field="ID",
        outputs=context,
        raw_response=context,  # not the raw machine: its `connectionDetails` can hold secrets
    )


def machine_to_context(machine: dict[str, Any]) -> dict[str, Any]:
    """Map a REST machine object onto context.

    Args:
        machine: The raw machine.

    Returns:
        dict: The machine, flattened. `Host` is absent for cloud connectors, which carry a vault
        name rather than an address.
    """
    connection_details = machine.get("connectionDetails") or {}
    raw_host, port = connection_address(connection_details)
    return assign_params(
        ID=machine.get("id"),
        Name=machine.get("machineName") or machine.get("name"),
        Status=machine.get("status"),
        PluginID=machine.get("pluginId"),
        EdgeInstanceID=machine.get("edgeInstanceId"),
        CreationDate=machine.get("creationDate"),
        ModificationDate=machine.get("modificationDate"),
        Host=normalize_host(raw_host),
        Port=port,
        ConnectionDetails=safe_connection_details(connection_details) or None,
    )


def certificate_revoke_command(client: CertificateManagerClient, args: dict[str, Any]) -> CommandResults:
    """Revoke one certificate. This is the destructive command of the integration.

    Args:
        client: The client.
        args: Command arguments. ``fingerprint`` is required.

    Returns:
        CommandResults: The revoked certificate, including its revocation status.

    Raises:
        ValueError: If the revocation reason is not one the API accepts.
        DemistoException: If no certificate matched the fingerprint, or the CA refused the revocation.
    """
    fingerprint = normalize_sha1_fingerprint(args["fingerprint"])
    reason = (args.get("reason") or DEFAULT_REVOCATION_REASON).strip().upper()
    if reason not in REVOCATION_REASONS:
        raise ValueError(f"'{reason}' is not a revocation reason. Valid values: {', '.join(REVOCATION_REASONS)}.")

    certificate = client.revoke_certificate(fingerprint, reason, args.get("comment"))
    if not certificate:
        raise DemistoException(
            f"No certificate with fingerprint {fingerprint} was returned by the tenant, so nothing was revoked. "
            "Note that the API cannot distinguish an unknown fingerprint from a deleted certificate."
        )
    # A CA refusal comes back as a normal response with status FAILED, not as an error. Raising makes
    # a playbook take its failure path instead of recording a revocation that did not happen.
    revocation = certificate.get("revocation") or {}
    if revocation.get("status") == REVOCATION_FAILED:
        ca_error = (revocation.get("error") or {}).get("message") or "the CA gave no reason"
        raise DemistoException(f"The CA did not revoke certificate {fingerprint}: {ca_error}")

    context = certificate_to_context(certificate, client.product.brand)
    return CommandResults(
        readable_output=tableToMarkdown(
            f"Revoked certificate {fingerprint}",
            context,
            headers=["Fingerprint", "CommonName", "Status", "ValidTo", "Revocation"],
            removeNull=True,
        ),
        outputs_prefix=f"{CONTEXT_PREFIX}.Certificate",
        outputs_key_field="Fingerprint",
        outputs=context,
        raw_response=certificate,
    )


def certificate_request_command(client: CertificateManagerClient, args: dict[str, Any]) -> CommandResults:
    """Request a new certificate.

    Args:
        client: The client.
        args: Command arguments.

    Returns:
        CommandResults: The created certificate requests.

    Raises:
        DemistoException: If the API accepted the call but created nothing.
    """
    raw = client.create_certificate_request(build_certificate_request_body(args))
    requests_created = extract_list(raw, "certificateRequests")
    if not requests_created:
        raise DemistoException(f"{client.product.name} accepted the request but returned no certificate request: {raw}")

    context = [certificate_request_to_context(entry) for entry in requests_created]
    return CommandResults(
        readable_output=tableToMarkdown(
            "Certificate request submitted",
            context,
            headers=["ID", "Status", "ApplicationID", "SubjectDN", "CreationDate"],
            removeNull=True,
        ),
        outputs_prefix=f"{CONTEXT_PREFIX}.CertificateRequest",
        outputs_key_field="ID",
        outputs=context,
        raw_response=raw,
    )


def certificate_request_status_command(client: CertificateManagerClient, args: dict[str, Any]) -> CommandResults:
    """Read the status of a certificate request.

    Args:
        client: The client.
        args: Command arguments. ``request_id`` is required.

    Returns:
        CommandResults: The certificate request.
    """
    raw = client.get_certificate_request(args["request_id"])
    context = certificate_request_to_context(raw)
    return CommandResults(
        readable_output=tableToMarkdown(f"Certificate request {context.get('ID')}", context, removeNull=True),
        outputs_prefix=f"{CONTEXT_PREFIX}.CertificateRequest",
        outputs_key_field="ID",
        outputs=context,
        raw_response=raw,
    )


def certificate_download_command(client: CertificateManagerClient, args: dict[str, Any]) -> list[Any]:
    """Download the contents of a certificate as a war-room file.

    Args:
        client: The client.
        args: Command arguments. ``certificate_id`` is required.

    Returns:
        list: The file entry, plus a context entry when the payload is text (PEM).

    Raises:
        ValueError: If the requested encoding is not one the API offers.
    """
    certificate_id = args["certificate_id"]
    encoding = (args.get("format") or "PEM").strip().upper()
    if encoding not in CERTIFICATE_FORMATS:
        raise ValueError(f"'{encoding}' is not a certificate format. Valid values: {', '.join(CERTIFICATE_FORMATS)}.")

    params = assign_params(chainOrder=args.get("chain_order"), containerFormat=args.get("container_format"))
    contents = client.download_certificate(certificate_id, encoding, params)
    file_name = f"{certificate_id}.{FILE_EXTENSION_BY_FORMAT[encoding]}"
    results: list[Any] = [fileResult(file_name, contents)]
    if encoding == "PEM":
        results.append(build_certificate_contents_result(certificate_id, file_name, contents))
    return results


def build_certificate_contents_result(certificate_id: str, file_name: str, contents: bytes) -> CommandResults:
    """Put a PEM payload into context so a playbook can hand it straight to an installation step.

    DER is binary and is deliberately left as a file entry only.

    Args:
        certificate_id: The certificate UUID.
        file_name: The name of the war-room file entry.
        contents: The raw payload.

    Returns:
        CommandResults: The context entry.
    """
    context = {
        "ID": certificate_id,
        "Format": "PEM",
        "FileName": file_name,
        "Contents": contents.decode("utf-8", errors="replace"),
    }
    return CommandResults(
        readable_output=f"Downloaded certificate {certificate_id} as {file_name}.",
        outputs_prefix=f"{CONTEXT_PREFIX}.CertificateContents",
        outputs_key_field="ID",
        outputs=context,
    )


def edge_public_key(client: CertificateManagerClient, certificate_id: str, dek_hash: str | None) -> str:
    """Find the VSatellite key to seal the passphrase for, and check that the export can work.

    Args:
        client: The client.
        certificate_id: The certificate UUID, for the messages.
        dek_hash: The certificate's `dekHash`: set only when a VSatellite generated and stores the private key.

    Returns:
        str: The base64 public key.

    Raises:
        DemistoException: If the key wasn't generated by a VSatellite, or the VSatellite's key type is not supported.
    """
    if not dek_hash:
        raise DemistoException(
            f"{client.product.name} doesn't hold the private key of certificate {certificate_id}. Only private keys that "
            "a VSatellite generated (a certificate requested without a CSR) can be downloaded."
        )
    edge_key = client.get_edge_encryption_key(dek_hash)
    algorithm = edge_key.get("keyAlgorithm")
    if algorithm != SUPPORTED_EDGE_KEY_ALGORITHM:
        raise DemistoException(
            f"The private key of certificate {certificate_id} is protected by a VSatellite key of type {algorithm}. "
            f"Downloading it is not supported yet; only {SUPPORTED_EDGE_KEY_ALGORITHM} keys are."
        )
    return edge_key["key"]


def build_keystore_results(
    certificate_id: str, export_format: str, files: dict[str, tuple[str, bytes]], from_setting: bool = False
) -> list[Any]:
    """Return the keystore as war-room files, and only the file names as context.

    The private key never enters the context: the context is copied into playbook inputs, task outputs and
    exports, while a file entry stays in the war room.

    Args:
        certificate_id: The certificate UUID.
        export_format: `PEM` or `PKCS12`.
        files: ``{context_field: (file_name, data)}``.
        from_setting: Whether the passphrase came from the instance setting rather than the argument.

    Returns:
        list: One file entry per file, then the context entry.
    """
    context = {"CertificateID": certificate_id, "Format": export_format}
    context.update({context_field: file_name for context_field, (file_name, _) in files.items()})
    results: list[Any] = [fileResult(file_name, data) for file_name, data in files.values()]
    readable = tableToMarkdown(f"Keystore of certificate {certificate_id}", context, headers=list(context))
    source = "the instance's Keystore passphrase setting" if from_setting else "the passphrase you supplied"
    note = f"\nThe private key is encrypted with {source}."
    results.append(
        CommandResults(
            readable_output=readable + note,
            outputs_prefix=f"{CONTEXT_PREFIX}.Keystore",
            outputs_key_field="CertificateID",
            outputs=context,
        )
    )
    return results


def keystore_passphrase(params: dict[str, Any]) -> str:
    """Read the "Keystore passphrase" setting.

    A playbook can't read the Cortex credentials store, but an instance setting of type 9 can, so this setting is
    how a keystore passphrase stays out of playbooks.

    Args:
        params: `demisto.params()`.

    Returns:
        str: The passphrase, or an empty string when the setting is empty.
    """
    return (params.get("keystore_passphrase") or {}).get("password") or ""


def certificate_keystore_download_command(
    client: CertificateManagerClient, args: dict[str, Any], default_passphrase: str = ""
) -> list[Any]:
    """Download a certificate with its private key, encrypted with a passphrase.

    Works only for a private key that a VSatellite generated: the service stores it encrypted to the VSatellite,
    so the passphrase is sealed to the VSatellite's key and the VSatellite builds the keystore.

    Args:
        client: The client.
        args: Command arguments. ``certificate_id`` is required; ``passphrase`` overrides ``default_passphrase``.
        default_passphrase: The instance's "Keystore passphrase" setting.

    Returns:
        list: The keystore files, then a context entry naming them.

    Raises:
        ValueError: If the format is not one the API offers, or there is no passphrase.
    """
    certificate_id = args["certificate_id"]
    export_format = (args.get("format") or DEFAULT_KEYSTORE_FORMAT).strip().upper()
    if export_format not in KEYSTORE_FORMATS:
        raise ValueError(f"'{export_format}' is not a keystore format. Valid values: {', '.join(KEYSTORE_FORMATS)}.")
    passphrase = args.get("passphrase") or default_passphrase
    if not passphrase:
        raise ValueError(
            "No passphrase to encrypt the private key: pass the 'passphrase' argument or set the instance's Keystore passphrase."
        )

    certificate = client.get_certificate_by_id(certificate_id)
    public_key = edge_public_key(client, certificate_id, certificate.get("dekHash"))
    body = build_keystore_request_body(export_format, seal_passphrase(passphrase, public_key))
    content = client.export_keystore(certificate_id, body)
    files = keystore_files(content, export_format, keystore_base_name(certificate, certificate_id))
    return build_keystore_results(certificate_id, export_format, files, from_setting=not args.get("passphrase"))


""" FETCH """


def expiry_thresholds(window_days: int) -> list[int]:
    """Return the thresholds to raise incidents on, most severe (smallest) first.

    A threshold beyond the expiry window is clamped to the window: the certificate only starts
    matching the fetch filter there, so that is the earliest moment the crossing can be seen. A
    window wider than the ladder adds its own rung at the window edge.

    Args:
        window_days: The expiry window being fetched, in days.

    Returns:
        list: Distinct thresholds in days, ascending.
    """
    return sorted({min(days, window_days) for days in (window_days, HIGH_EXPIRY_DAYS, CRITICAL_EXPIRY_DAYS)})


def threshold_severity(threshold_days: int) -> float:
    """Map an expiry threshold onto an `IncidentSeverity` value.

    Taken from the threshold, not from the days remaining at fetch time, so a crossing detected a
    few hours late cannot land on the neighbouring rung. The ladder never drops below Medium: Low
    produces neither a case nor a grouping, so an expiring certificate that landed there would be
    invisible in practice.

    Args:
        threshold_days: The threshold that was crossed, in days before expiry.

    Returns:
        float: An `IncidentSeverity` value.
    """
    if threshold_days <= CRITICAL_EXPIRY_DAYS:
        return IncidentSeverity.CRITICAL
    if threshold_days <= HIGH_EXPIRY_DAYS:
        return IncidentSeverity.HIGH
    return IncidentSeverity.MEDIUM


def expiry_description(context: dict[str, Any], threshold_days: int) -> str:
    """Summarise an expiry crossing in one readable sentence for the incident description.

    Args:
        context: The certificate in context form.
        threshold_days: The threshold crossed, in days before expiry.

    Returns:
        str: The description.
    """
    subject = context.get("CommonName") or context.get("Fingerprint")
    issuer = context.get("IssuerCommonName") or context.get("IssuerDN") or "an unknown issuer"
    return (
        f"Certificate {subject} (fingerprint {context.get('Fingerprint')}), issued by {issuer}, expires on "
        f"{context.get('ValidTo')} - {context.get('DaysUntilExpiry')} day(s) left. "
        f"It crossed the {threshold_days}-day expiry threshold."
    )


def build_expiry_incident(
    certificate: dict[str, Any], threshold_days: int, incident_type: str, source_brand: str, now: datetime | None = None
) -> dict[str, Any] | None:
    """Build the incident for one certificate crossing one expiry threshold.

    `occurred` is the moment the certificate *crossed* the threshold, not the moment we noticed.
    That is the timestamp the look-back mechanism needs: a crossing can happen well before the
    fetch that first sees it. It can also lie in the future, for a threshold not yet reached.

    Args:
        certificate: A raw `searchCertificates` node.
        threshold_days: The threshold, in days before expiry.
        incident_type: The incident type to create.
        source_brand: The brand of the integration that returned the certificate.
        now: Reference time for the expiry calculation. Injected for testability.

    Returns:
        dict | None: The incident, or None when the certificate carries no usable expiry date.
    """
    expiry = arg_to_datetime((certificate.get("validity") or {}).get("to"), required=False)
    fingerprint = certificate.get("fingerprint")
    if not expiry or not fingerprint:
        return None

    context = certificate_to_context(certificate, source_brand, now=now)
    context["CrossedThresholdDays"] = threshold_days
    context[ISSUE_TYPE_RAW_KEY] = incident_type
    common_name = context.get("CommonName") or fingerprint
    return {
        "name": f"Certificate expiring in {context.get('DaysUntilExpiry')} day(s): {common_name}",
        # XSIAM shows `details` as the issue description; without it the issue reads "EMPTY".
        "details": expiry_description(context, threshold_days),
        "occurred": to_iso_z(expiry - timedelta(days=threshold_days)),
        "type": incident_type,
        "severity": threshold_severity(threshold_days),
        "rawJSON": json.dumps(context),
        # The deduplication key. `dbotMirrorId` is mirroring, not deduplication - the mechanism
        # here is `last_run["found_incident_ids"]`, which is keyed on this field.
        DEDUP_ID_FIELD: f"{fingerprint}:{threshold_days}",
    }


def most_severe_crossing(
    certificate: dict[str, Any], thresholds: list[int], incident_type: str, source_brand: str, fetch_range: tuple[str, str]
) -> dict[str, Any] | None:
    """Return the incident for the most severe threshold the certificate crossed within the fetch range.

    Only one per certificate: when several crossings fall in one range - the first-fetch backlog -
    the less severe ones are already stale. A later range either repeats the same choice or starts
    after them, so they are never raised.

    Args:
        certificate: A raw `searchCertificates` node.
        thresholds: Thresholds in days, most severe first.
        incident_type: The incident type to create.
        source_brand: The brand of the integration that returned the certificate.
        fetch_range: ``(start_time, end_time)`` of the fetch range, both in `FETCH_DATE_FORMAT`.

    Returns:
        dict | None: The incident, or None when no threshold was crossed within the range.
    """
    start_time, end_time = fetch_range
    crossings = (build_expiry_incident(certificate, days, incident_type, source_brand) for days in thresholds)
    # Both timestamps come from the same fixed-width UTC format, so a string comparison is a
    # chronological comparison.
    return next((incident for incident in crossings if incident and start_time <= incident["occurred"] <= end_time), None)


def expiry_incidents(
    certificates: list[dict[str, Any]], window_days: int, incident_type: str, source_brand: str, fetch_range: tuple[str, str]
) -> list[dict[str, Any]]:
    """Turn certificates into incidents, one per threshold crossed within the fetch range.

    Sorted oldest-first, because the caller keeps the first `fetch_limit` of them and records the
    latest `occurred` as the next run's starting point.

    Args:
        certificates: Raw `searchCertificates` nodes.
        window_days: The expiry window being fetched, in days.
        incident_type: The incident type to create.
        source_brand: The brand of the integration that returned the certificates.
        fetch_range: ``(start_time, end_time)`` of the fetch range, both in `FETCH_DATE_FORMAT`.

    Returns:
        list: The incidents.
    """
    thresholds = expiry_thresholds(window_days)
    incidents = [
        most_severe_crossing(certificate, thresholds, incident_type, source_brand, fetch_range) for certificate in certificates
    ]
    return sorted((incident for incident in incidents if incident), key=lambda incident: incident["occurred"])


def build_revocation_failed_incident(
    certificate: dict[str, Any], source_brand: str, now: datetime | None = None
) -> dict[str, Any]:
    """Build the incident for a key-compromise revocation that failed, at severity High.

    The API keeps no timestamp for the failure, so `occurred` is the moment the fetch noticed it.

    Args:
        certificate: A raw `searchCertificates` node with a failed `KEY_COMPROMISE` revocation.
        source_brand: The brand of the integration that returned the certificate.
        now: Reference time. Injected for testability.

    Returns:
        dict: The incident.
    """
    context = certificate_to_context(certificate, source_brand, now=now)
    context[ISSUE_TYPE_RAW_KEY] = REVOCATION_FAILED_INCIDENT_TYPE
    fingerprint = certificate["fingerprint"]
    subject = context.get("CommonName") or fingerprint
    error = (context.get("Revocation") or {}).get("Error") or "the CA gave no reason"
    return {
        "name": f"Key-compromise revocation failed: {subject}",
        "details": (
            f"The KEY_COMPROMISE revocation of certificate {subject} (fingerprint {fingerprint}) failed: {error}. "
            "The key is reported compromised, but clients still trust the certificate. Retry the revocation, "
            "or replace the certificate."
        ),
        "occurred": to_iso_z(now or datetime.now(UTC)),
        "type": REVOCATION_FAILED_INCIDENT_TYPE,
        "severity": IncidentSeverity.HIGH,
        "rawJSON": json.dumps(context),
        DEDUP_ID_FIELD: f"{fingerprint}:revocation-failed",
    }


def revocation_failed_incidents(
    client: CertificateManagerClient, raised_before: list[str]
) -> tuple[list[dict[str, Any]], list[str]]:
    """Raise one incident per certificate whose key-compromise revocation is FAILED.

    A failure stays FAILED until someone acts, so deduplication is by state, not by time: a
    fingerprint is raised again only after it left the failed state and failed anew.

    Args:
        client: The client.
        raised_before: Fingerprints already raised, from the previous run.

    Returns:
        tuple: ``(incidents, fingerprints_now_failed)``.
    """
    # The API filters on revocation status but not on reason, so the reason is checked here. The
    # status is checked again too: a filter the server ignored must not raise every certificate.
    certificates, _ = collect_certificates(
        client,
        limit=FETCH_MAX_PAGES * MAX_PAGE_SIZE,
        filter_on={"and": {"revocationStatus": {"eq": GraphQLEnum(REVOCATION_FAILED)}}},
        max_pages=FETCH_MAX_PAGES,
    )
    failed_key_compromise = {"status": REVOCATION_FAILED, "reason": KEY_COMPROMISE_REASON}
    failed = [
        cert
        for cert in certificates
        if cert.get("fingerprint")
        and {key: (cert.get("revocation") or {}).get(key) for key in failed_key_compromise} == failed_key_compromise
    ]
    incidents = [
        build_revocation_failed_incident(cert, client.product.brand)
        for cert in failed
        if cert["fingerprint"] not in raised_before
    ]
    return incidents, sorted(cert["fingerprint"] for cert in failed)


def fetch_incidents(
    client: CertificateManagerClient, params: dict[str, Any], last_run: dict[str, Any]
) -> tuple[list[dict[str, Any]], dict]:
    """Fetch expiring certificates, and failed key-compromise revocations, as incidents.

    Args:
        client: The client.
        params: `demisto.params()`.
        last_run: `demisto.getLastRun()`.

    Returns:
        tuple: ``(incidents, last_run)``.
    """
    # Read before the look-back helpers touch last_run, which they rebuild.
    raised_before = list(last_run.get(RAISED_REVOCATION_FAILURES_KEY) or [])
    look_back = arg_to_number(params.get("look_back"))
    look_back = DEFAULT_LOOK_BACK_MINUTES if look_back is None else look_back
    fetch_limit = arg_to_number(last_run.get("limit")) or arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_FETCH
    window_days = arg_to_number(params.get("fetch_expiry_days")) or DEFAULT_EXPIRY_DAYS
    incident_type = params.get("incidentType") or INCIDENT_TYPE

    start_time, end_time = get_fetch_run_time_range(
        last_run=last_run,
        first_fetch=params.get("first_fetch") or DEFAULT_FIRST_FETCH,
        look_back=look_back,
        date_format=FETCH_DATE_FORMAT,
    )
    # Server-side. A 30-day window is a small fraction of the inventory, so paging
    # the inventory and filtering locally is never the right shape here.
    certificates, _ = collect_certificates(
        client,
        limit=FETCH_MAX_PAGES * MAX_PAGE_SIZE,
        filter_on=expiry_window_filter(window_days, include_expired=False),
        max_pages=FETCH_MAX_PAGES,
    )
    candidates = expiry_incidents(certificates, window_days, incident_type, client.product.brand, (start_time, end_time))

    incidents = filter_incidents_by_duplicates_and_limit(
        incidents_res=candidates, last_run=last_run, fetch_limit=fetch_limit, id_field=DEDUP_ID_FIELD
    )
    updated_last_run = update_last_run_object(
        last_run=last_run,
        incidents=incidents,
        fetch_limit=fetch_limit,
        start_fetch_time=start_time,
        end_fetch_time=end_time,
        look_back=look_back,
        created_time_field="occurred",
        id_field=DEDUP_ID_FIELD,
        date_format=FETCH_DATE_FORMAT,
    )
    failure_incidents, now_failed = revocation_failed_incidents(client, raised_before)
    updated_last_run[RAISED_REVOCATION_FAILURES_KEY] = now_failed
    return incidents + failure_incidents, updated_last_run


""" PARAMETERS """


def resolve_reliability(params: dict[str, Any]) -> str:
    """Read and validate the configured source reliability.

    Args:
        params: `demisto.params()`.

    Returns:
        str: A valid `DBotScoreReliability` value.
    """
    reliability = params.get("integrationReliability") or DBotScoreReliability.C
    if not DBotScoreReliability.is_valid_type(reliability):
        raise DemistoException(f"'{reliability}' is not a valid Source Reliability value.")
    return reliability


def resolve_reported_key_compromise_score(params: dict[str, Any]) -> int:
    """Read the "Score reported key compromise as" setting.

    Args:
        params: `demisto.params()`.

    Returns:
        int: `Common.DBotScore.SUSPICIOUS` or `Common.DBotScore.BAD`.
    """
    choice = params.get("reported_key_compromise_score") or DEFAULT_REPORTED_KEY_COMPROMISE_SCORE
    if choice not in REPORTED_KEY_COMPROMISE_SCORES:
        raise DemistoException(
            f"'{choice}' is not a valid value for 'Score reported key compromise as'. Use Suspicious or Malicious."
        )
    return REPORTED_KEY_COMPROMISE_SCORES[choice]
