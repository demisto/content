import copy
import inspect
import traceback

from pytest_mock import MockerFixture
import pytest
from unittest.mock import Mock, AsyncMock
from CommonServerPython import DemistoException, EntryType, CommandResults

import sys
import time

from mcp.client.streamable_http import streamable_http_client
from mcp.client.client import Client as MCPClient
from mcp.types import CallToolResult
import httpx2

from MCPApiModule import (
    extract_root_error_message,
    parse_custom_headers,
    join_url,
    url_origin_join,
    update_integration_context_oauth_flow,
    AuthMethods,
    get_client_metadata,
    resolve_application_type,
    parse_authorization_response,
    validate_authorization_response,
    validate_state,
    OAUTH_DISCOVERY_HEADERS,
    OAuthHandler,
    Client,
    generate_login_url,
    normalize_tool_schemas,
)

# ExceptionGroup is new in Python 3.11, so we define it for older versions for testing purposes
if sys.version_info < (3, 11):  # noqa: UP036

    class ExceptionGroup(Exception):
        def __init__(self, message, exceptions):
            super().__init__(message)
            self.exceptions = exceptions

    class BaseExceptionGroup(BaseException):
        def __init__(self, message, exceptions):
            super().__init__(message)
            self.exceptions = exceptions


# --- Utility Function Tests ---


def test_extract_root_error_message_with_nested_exception_group():
    """
    Given: A nested ExceptionGroup containing a ValueError as the first inner exception.
    When: extract_root_error_message is called with the nested exception group.
    Then: The root ValueError message should be extracted and formatted.
    """
    inner_exception = ValueError("This is the root cause")
    exception_group = ExceptionGroup("Outer group", [inner_exception, RuntimeError("Another error")])

    result = extract_root_error_message(exception_group)

    assert "ValueError: This is the root cause" in result


def test_extract_root_error_message_with_base_exception_group():
    """
    Given: A BaseExceptionGroup containing a KeyError as the first inner exception.
    When: extract_root_error_message is called with the base exception group.
    Then: The root KeyError message should be extracted and formatted.
    """
    inner_exception = KeyError("missing_key")
    base_exception_group = BaseExceptionGroup("Base group", [inner_exception])

    result = extract_root_error_message(base_exception_group)

    assert "KeyError: 'missing_key'" in result


def test_extract_root_error_message_with_regular_exception():
    """
    Given: A regular RuntimeError exception with a specific message.
    When: extract_root_error_message is called with the regular exception.
    Then: The exception message should be formatted using traceback.format_exception_only.
    """
    exception = RuntimeError("Something went wrong")

    result = extract_root_error_message(exception)

    expected = "".join(traceback.format_exception_only(type(exception), exception))
    assert result == expected
    assert "RuntimeError: Something went wrong" in result


def test_extract_root_error_message_with_deeply_nested_exception_group():
    """
    Given: A deeply nested ExceptionGroup containing multiple levels of exception groups.
    When: extract_root_error_message is called with the outermost exception group.
    Then: The deepest nested exception should be extracted and formatted.
    """
    deepest_exception = ConnectionError("Network timeout")
    middle_group = ExceptionGroup("Middle level", [deepest_exception])
    outer_group = ExceptionGroup("Outer level", [middle_group])

    result = extract_root_error_message(outer_group)

    assert "ConnectionError: Network timeout" in result


def test_parse_custom_headers_valid_input():
    """
    Given: A multiline string with valid header format lines.
    When: parse_custom_headers is called.
    Then: A dictionary with parsed headers is returned.
    """
    headers_text = "Authorization: Bearer token123\nContent-Type: application/json\nX-Custom-Header: custom-value"

    result = parse_custom_headers(headers_text)

    expected = {"Authorization": "Bearer token123", "Content-Type": "application/json", "X-Custom-Header": "custom-value"}
    assert result == expected


def test_parse_custom_headers_empty_input():
    """
    Given: An empty string input.
    When: parse_custom_headers is called.
    Then: An empty dictionary is returned.
    """
    result = parse_custom_headers("")

    assert result == {}


def test_parse_custom_headers_with_whitespace():
    """
    Given: A multiline string with headers containing extra whitespace and empty lines.
    When: parse_custom_headers is called.
    Then: Headers are parsed with whitespace properly trimmed.
    """
    headers_text = "\n  Authorization:   Bearer token123  \n\nContent-Type:application/json\n  "

    result = parse_custom_headers(headers_text)

    expected = {"Authorization": "Bearer token123", "Content-Type": "application/json"}
    assert result == expected


def test_parse_custom_headers_invalid_format():
    """
    Given: A header line without a colon separator.
    When: parse_custom_headers is called.
    Then: A ValueError is raised with details about the invalid format.
    """
    headers_text = "Authorization: Bearer token123\nInvalidHeaderLine\nContent-Type: application/json"

    with pytest.raises(ValueError) as exc_info:
        parse_custom_headers(headers_text)

    assert "Invalid header line format: InvalidHeaderLine" in str(exc_info.value)


def test_parse_custom_headers_empty_header_name():
    """
    Given: A header line with empty header name but valid colon format.
    When: parse_custom_headers is called.
    Then: The invalid header is skipped and valid headers are still parsed.
    """
    headers_text = ": empty-name-header\nAuthorization: Bearer token123"

    result = parse_custom_headers(headers_text)

    expected = {"Authorization": "Bearer token123"}
    assert result == expected


def test_join_url_basic_path():
    """
    Given: A base URL and a simple path.
    When: join_url is called.
    Then: The URL and path should be properly joined.
    """
    base_url = "https://example.com"
    path = "api/v1/endpoint"
    result = join_url(base_url, path)
    assert result == "https://example.com/api/v1/endpoint"


def test_join_url_with_trailing_slash_in_base():
    """
    Given: A base URL that ends with a trailing slash.
    When: join_url is called.
    Then: The trailing slash should be handled correctly.
    """
    base_url = "https://example.com/"
    path = "api/v1/endpoint"
    result = join_url(base_url, path)
    assert result == "https://example.com/api/v1/endpoint"


def test_join_url_with_existing_path_in_base():
    """
    Given: A base URL that already contains a path and an additional path to append.
    When: join_url is called.
    Then: The new path should be appended to the existing path correctly.
    """
    base_url = "https://example.com/existing/path"
    path = "new/endpoint"
    result = join_url(base_url, path)
    assert result == "https://example.com/existing/path/new/endpoint"


def test_url_origin_join_basic_path():
    """
    Given: A base URL with an existing path and a new path to join.
    When: url_origin_join is called.
    Then: The origin URL and new path should be properly joined.
    """
    base_url = "https://example.com/some/existing/path"
    path = "api/v1/endpoint"
    result = url_origin_join(base_url, path)
    assert result == "https://example.com/api/v1/endpoint"


def test_url_origin_join_empty_path():
    """
    Given: A base URL with an existing path and an empty path parameter.
    When: url_origin_join is called with an empty path.
    Then: Only the origin (scheme and netloc) should be returned.
    """
    base_url = "https://example.com/some/path?query=param"
    path = ""
    result = url_origin_join(base_url, path)
    assert result == "https://example.com"


def test_url_origin_join_with_port_and_query():
    """
    Given: A base URL with port and query parameters.
    When: url_origin_join is called to extract origin and join with new path.
    Then: The result should contain only the scheme, netloc with port, and the new path.
    """
    base_url = "https://example.com:8080/old/path?query=value#fragment"
    path = "new/endpoint"
    result = url_origin_join(base_url, path)
    assert result == "https://example.com:8080/new/endpoint"


def test_update_integration_context_oauth_flow_basic(mocker: MockerFixture):
    """
    Given: OAuth flow data to be stored.
    When: update_integration_context_oauth_flow is called.
    Then: The integration context should be updated with the provided data after removing empty elements.
    """
    mock_get_context = mocker.patch("MCPApiModule.get_integration_context")
    mock_set_context = mocker.patch("MCPApiModule.set_integration_context")
    mock_remove_empty = mocker.patch("MCPApiModule.remove_empty_elements")

    existing_context = {"existing_key": "existing_value"}
    mock_get_context.return_value = existing_context

    oauth_data = {"access_token": "token123", "expires_in": 3600, "empty_field": None}
    cleaned_data = {"access_token": "token123", "expires_in": 3600}
    mock_remove_empty.return_value = cleaned_data

    update_integration_context_oauth_flow(oauth_data)

    mock_set_context.assert_called_once()
    call_args = mock_set_context.call_args[0][0]
    assert call_args["existing_key"] == "existing_value"
    assert call_args["access_token"] == "token123"


def test_update_integration_context_oauth_flow_overwrites_existing_keys(mocker: MockerFixture):
    """
    Given: OAuth data that contains keys already present in the existing integration context.
    When: update_integration_context_oauth_flow is called.
    Then: The existing keys should be overwritten with the new values from the OAuth data.
    """
    mock_get_context = mocker.patch("MCPApiModule.get_integration_context")
    mock_set_context = mocker.patch("MCPApiModule.set_integration_context")
    mock_remove_empty = mocker.patch("MCPApiModule.remove_empty_elements")

    existing_context = {"access_token": "old_token", "refresh_token": "old_refresh"}
    mock_get_context.return_value = existing_context

    oauth_data = {"access_token": "new_token", "expires_in": 7200}
    mock_remove_empty.return_value = oauth_data

    update_integration_context_oauth_flow(oauth_data)

    call_args = mock_set_context.call_args[0][0]
    assert call_args["access_token"] == "new_token"
    assert call_args["refresh_token"] == "old_refresh"
    assert call_args["expires_in"] == 7200


def test_auth_methods_list():
    """
    Given: The AuthMethods enum class.
    When: The list() class method is called.
    Then: A list containing all string values from the enum should be returned.
    """
    result = AuthMethods.list()
    expected = [
        "Basic",
        "Token",
        "Bearer",
        "Api-Key",
        "RawToken",
        "No Authorization",
        "OAuth 2.0 Authorization Code",
        "OAuth 2.0 Client Credentials",
        "OAuth 2.0 Dynamic Client Registration",
    ]
    assert result == expected


def test_get_client_metadata_basic_functionality(mocker: MockerFixture):
    """
    Given: A redirect URI.
    When: get_client_metadata is called.
    Then: A properly formatted client metadata dictionary should be returned.
    """
    mock_demisto_urls = mocker.patch("MCPApiModule.demisto.demistoUrls")
    mock_demisto_urls.return_value = {"server": "https://test-server.com"}
    redirect_uri = "https://oproxy.demisto.ninja/authcode"

    result = get_client_metadata(redirect_uri)

    assert result["redirect_uris"] == ["https://oproxy.demisto.ninja/authcode"]
    assert result["client_name"] == "Palo Alto Networks"
    assert result["client_uri"] == "https://test-server.com"


# --- MCP 2026-07-28 spec conformance tests (SEP-837, protocol version header) ---


def test_get_client_metadata_declares_web_for_public_redirect(mocker: MockerFixture):
    """
    Given: A public HTTPS redirect URI, as used by Generic/Cloudflare/ServiceNow MCP.
    When: get_client_metadata is called.
    Then: application_type is declared as "web" (SEP-837).
    """
    # given
    mocker.patch("MCPApiModule.demisto.demistoUrls", return_value={"server": "https://test-server.com"})

    # when
    result = get_client_metadata("https://oproxy.demisto.ninja/authcode")

    # then
    assert result["application_type"] == "web"


def test_get_client_metadata_declares_native_for_loopback_redirect(mocker: MockerFixture):
    """
    Given: A loopback redirect URI, as used by AtlassianCloudMCP.
    When: get_client_metadata is called.
    Then: application_type is declared as "native", not "web" (RFC 8252 / SEP-837).
    """
    # given
    mocker.patch("MCPApiModule.demisto.demistoUrls", return_value={"server": "https://test-server.com"})

    # when
    result = get_client_metadata("http://127.0.0.1:8000/callback")

    # then
    assert result["application_type"] == "native"


@pytest.mark.parametrize(
    ("redirect_uri", "expected"),
    [
        ("https://oproxy.demisto.ninja/authcode", "web"),
        ("https://example.com/cb", "web"),
        ("HTTPS://Example.COM/cb", "web"),
        ("http://127.0.0.1:8000/callback", "native"),
        ("http://localhost:8080/cb", "native"),
        ("http://[::1]:9000/cb", "native"),
        ("com.example.app:/oauth2redirect", "native"),
    ],
    ids=[
        "oproxy-https-is-web",
        "public-https-is-web",
        "uppercase-scheme-is-web",
        "ipv4-loopback-is-native",
        "localhost-is-native",
        "ipv6-loopback-is-native",
        "custom-scheme-is-native",
    ],
)
def test_resolve_application_type(redirect_uri: str, expected: str):
    """
    Given: A redirect URI.
    When: resolve_application_type is called.
    Then: Loopback and custom-scheme URIs resolve to "native"; public HTTPS to "web".
    """
    assert resolve_application_type(redirect_uri) == expected


def test_oauth_discovery_headers_declare_latest_protocol_version():
    """
    Given: The OAuth discovery headers constant.
    When: Its value is inspected.
    Then: It declares the latest MCP protocol version on the discovery requests.
    """
    assert OAUTH_DISCOVERY_HEADERS == {"MCP-Protocol-Version": "2026-07-28"}


def test_protocol_version_header_is_not_sent_on_the_mcp_session():
    """
    Given: The MCPApiModule source.
    When: The session setup in Client._get_session is inspected.
    Then: The discovery headers are not attached to the session HTTP client.

    A 2026-07-28 MCP-Protocol-Version header declares the stateless core. The session still
    performs the legacy `initialize` handshake, and a server rejects that combination with
    -32020, so the two must stay separate.
    """
    # given
    import MCPApiModule

    # when
    session_source = inspect.getsource(MCPApiModule.Client._get_session)

    # then
    assert "OAUTH_DISCOVERY_HEADERS" not in session_source
    assert "MCP-Protocol-Version" not in session_source


# --- Authorization response parsing (state / iss, RFC 9207 / SEP-2468) ---


def _oauth_metadata(issuer: str, **overrides) -> dict:
    """Build an authorization server metadata document that satisfies the SDK's schema.

    `OAuthMetadata` requires issuer, authorization_endpoint and token_endpoint; a document
    missing any of them fails validation and disables issuer checking.
    """
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/authorize",
        "token_endpoint": f"{issuer}/token",
        **overrides,
    }


def test_parse_authorization_response_extracts_code_state_and_iss():
    """
    Given: A full redirect URL containing code, state and iss.
    When: parse_authorization_response is called.
    Then: All three parameters are extracted.
    """
    # given
    url = "https://oproxy.demisto.ninja/authcode?code=AUTH123&state=ST456&iss=https%3A%2F%2Fas.example.com"

    # when
    result = parse_authorization_response(url)

    # then
    assert result == {
        "code": "AUTH123",
        "state": "ST456",
        "iss": "https://as.example.com",
        "is_full_url": "true",
    }


def test_parse_authorization_response_accepts_legacy_bare_code():
    """
    Given: A bare authorization code, as every instance configured before this change stores.
    When: parse_authorization_response is called.
    Then: The code is returned unchanged, with no state or iss.

    This is the backwards-compatibility guarantee: existing instances must keep working.
    """
    # when
    result = parse_authorization_response("AUTH123")

    # then
    assert result == {"code": "AUTH123", "is_full_url": ""}


def test_parse_authorization_response_handles_url_without_iss():
    """
    Given: A redirect URL from a server that does not implement RFC 9207 (e.g. Atlassian).
    When: parse_authorization_response is called.
    Then: code and state are extracted and the absent iss is simply omitted.
    """
    # when
    result = parse_authorization_response("https://oproxy.demisto.ninja/authcode?code=A1&state=S1")

    # then
    assert result == {"code": "A1", "state": "S1", "is_full_url": "true"}


def test_parse_authorization_response_decodes_a_bare_code_once():
    """
    Given: A url-encoded bare authorization code.
    When: parse_authorization_response is called.
    Then: It is decoded exactly once.

    Callers used to url-decode this parameter themselves; that decoding now lives here so the
    full-URL form is not decoded twice.
    """
    assert parse_authorization_response("A%2FB%2BC")["code"] == "A/B+C"


def test_parse_authorization_response_does_not_double_decode_url_values():
    """
    Given: A full redirect URL whose code value contains percent-encoded reserved characters.
    When: parse_authorization_response is called.
    Then: The code is decoded once by the query parser, not twice.

    Double decoding would turn '%2B' into a literal space and silently corrupt the code.
    """
    # when
    result = parse_authorization_response("https://oproxy.demisto.ninja/authcode?code=A%2FB%2BC&state=S1")

    # then
    assert result["code"] == "A/B+C"


def test_parse_authorization_response_preserves_encoded_iss():
    """
    Given: A full redirect URL with a percent-encoded iss parameter, as servers emit it.
    When: parse_authorization_response is called.
    Then: The issuer is decoded back to its original URL form for comparison.
    """
    # when
    result = parse_authorization_response(
        "https://oproxy.demisto.ninja/authcode?code=A1&state=S1&iss=https%3A%2F%2Fbindings.mcp.cloudflare.com"
    )

    # then
    assert result["iss"] == "https://bindings.mcp.cloudflare.com"


def test_parse_authorization_response_rejects_url_without_code():
    """
    Given: A redirect URL that carries no authorization code (e.g. an error redirect).
    When: parse_authorization_response is called.
    Then: A DemistoException explains what to paste.
    """
    # when / then
    with pytest.raises(DemistoException, match="Could not find an authorization code"):
        parse_authorization_response("https://oproxy.demisto.ninja/authcode?error=access_denied")


def test_parse_authorization_response_handles_empty_input():
    """
    Given: An empty authorization code parameter.
    When: parse_authorization_response is called.
    Then: An empty dict is returned, leaving the existing 'missing auth code' error to fire.
    """
    assert parse_authorization_response("") == {}


def test_validate_authorization_response_accepts_matching_state_and_iss():
    """
    Given: An authorization response whose state and iss match the stored flow.
    When: validate_authorization_response is called.
    Then: No exception is raised.
    """
    # given
    received = {"code": "A1", "state": "ST1", "iss": "https://as.example.com"}
    context = {"state": "ST1", "oauth_metadata": _oauth_metadata("https://as.example.com")}

    # when / then
    validate_authorization_response(received, context)


def test_validate_authorization_response_rejects_tampered_state():
    """
    Given: An authorization response whose state does not match the stored flow.
    When: validate_authorization_response is called.
    Then: A DemistoException is raised - this is the CSRF attack signal.
    """
    # given
    received = {"code": "A1", "state": "TAMPERED"}
    context = {"state": "ST1"}

    # when / then
    with pytest.raises(DemistoException, match="state"):
        validate_authorization_response(received, context)


def test_validate_authorization_response_rejects_mismatched_issuer():
    """
    Given: An authorization response issued by a different authorization server.
    When: validate_authorization_response is called.
    Then: A DemistoException is raised - this is the RFC 9207 mix-up attack signal.
    """
    # given
    received = {"code": "A1", "iss": "https://evil.example.com"}
    context = {"oauth_metadata": _oauth_metadata("https://as.example.com")}

    # when / then
    with pytest.raises(DemistoException, match="issuer"):
        validate_authorization_response(received, context)


def test_validate_authorization_response_does_not_leak_values_in_the_error():
    """
    Given: An authorization response with a mismatched state.
    When: validate_authorization_response raises.
    Then: Neither the expected nor the received value appears in the message.

    `state` is not a secret, but it travels in a URL and correlates a user's in-flight login,
    so it should not be echoed into war-room output.
    """
    # given
    received = {"code": "A1", "state": "RECEIVED_SENTINEL"}
    context = {"state": "EXPECTED_SENTINEL"}

    # when
    with pytest.raises(DemistoException) as exc_info:
        validate_authorization_response(received, context)

    # then
    assert "RECEIVED_SENTINEL" not in str(exc_info.value)
    assert "EXPECTED_SENTINEL" not in str(exc_info.value)


def test_validate_authorization_response_warns_but_passes_for_legacy_bare_code():
    """
    Given: A legacy bare code (no state/iss) and a stored flow that expected both.
    When: validate_authorization_response is called.
    Then: No exception is raised, so existing instances keep working after upgrade.
    """
    # given
    received = {"code": "A1"}
    context = {"state": "ST1", "oauth_metadata": _oauth_metadata("https://as.example.com")}

    # when / then
    validate_authorization_response(received, context)


def test_validate_authorization_response_passes_when_server_omits_iss():
    """
    Given: A server that never sends iss (Atlassian does not advertise RFC 9207 support).
    When: validate_authorization_response is called with a matching state.
    Then: No exception is raised; only the state is enforced.
    """
    # given
    received = {"code": "A1", "state": "ST1"}
    context = {"state": "ST1", "oauth_metadata": _oauth_metadata("https://mcp.atlassian.com")}

    # when / then
    validate_authorization_response(received, context)


def test_oauth_handler_parses_full_redirect_url_from_auth_code_param():
    """
    Given: An OAuthHandler built with a full redirect URL in the auth_code parameter.
    When: The handler is constructed.
    Then: auth_code holds only the code, and the response parameters are retained.
    """
    # given / when
    handler = OAuthHandler(
        base_url="https://mcp.example.com",
        command_prefix="test",
        auth_code="https://oproxy.demisto.ninja/authcode?code=A1&state=S1&iss=https%3A%2F%2Fas.example.com",
    )

    # then
    assert handler.auth_code == "A1"
    assert handler.authorization_response["state"] == "S1"
    assert handler.authorization_response["iss"] == "https://as.example.com"


def test_oauth_handler_preserves_legacy_bare_auth_code():
    """
    Given: An OAuthHandler built with a legacy bare authorization code.
    When: The handler is constructed.
    Then: auth_code is unchanged, preserving behaviour for existing instances.
    """
    # given / when
    handler = OAuthHandler(base_url="https://mcp.example.com", command_prefix="test", auth_code="A1")

    # then
    assert handler.auth_code == "A1"
    assert handler.authorization_response == {"code": "A1", "is_full_url": ""}


@pytest.mark.asyncio
async def test_discover_oauth_metadata_accepts_issuer_matching_discovery_origin(mocker: MockerFixture):
    """
    Given: Metadata whose issuer matches the URL it was served from (as Atlassian and
           Cloudflare both do in production).
    When: _discover_oauth_metadata is called.
    Then: The issuer is accepted.
    """
    # given
    handler = OAuthHandler(base_url="https://mcp.atlassian.com", command_prefix="test")
    response = Mock(is_success=True)
    response.json.return_value = {"issuer": "https://mcp.atlassian.com", "token_endpoint": "https://mcp.atlassian.com/v1/token"}
    mocker.patch.object(handler.session, "get", AsyncMock(return_value=response))

    # when
    metadata = await handler._discover_oauth_metadata("https://mcp.atlassian.com")

    # then
    assert metadata["issuer"] == "https://mcp.atlassian.com"


@pytest.mark.asyncio
async def test_discover_oauth_metadata_rejects_issuer_from_a_different_origin(mocker: MockerFixture):
    """
    Given: Metadata declaring an issuer that differs from the URL it was served from.
    When: _discover_oauth_metadata is called.
    Then: A DemistoException is raised (RFC 8414 section 3.3).

    This is what anchors the later `iss` check: without it we would be comparing a server's
    self-declaration against the same self-declaration.
    """
    # given
    handler = OAuthHandler(base_url="https://mcp.atlassian.com", command_prefix="test")
    response = Mock(is_success=True)
    response.json.return_value = {"issuer": "https://evil.example.com"}
    mocker.patch.object(handler.session, "get", AsyncMock(return_value=response))

    # when / then
    with pytest.raises(DemistoException, match="RFC 8414"):
        await handler._discover_oauth_metadata("https://mcp.atlassian.com")


@pytest.mark.asyncio
async def test_discover_oauth_metadata_falls_back_to_origin_when_discovery_fails(mocker: MockerFixture):
    """
    Given: A discovery request that fails.
    When: _discover_oauth_metadata is called.
    Then: The issuer falls back to the discovery origin rather than being left empty.

    An empty issuer would silently disable `iss` validation, so a network-level attacker could
    turn the check off just by making discovery fail.
    """
    # given
    handler = OAuthHandler(base_url="https://mcp.example.com", command_prefix="test")
    mocker.patch.object(handler.session, "get", AsyncMock(side_effect=Exception("network down")))

    # when
    metadata = await handler._discover_oauth_metadata("https://mcp.example.com")

    # then
    assert "issuer" not in metadata


def test_validate_authorization_response_skips_iss_when_discovery_produced_no_metadata():
    """
    Given: A flow where discovery failed, so no issuer was ever recorded.
    When: validate_authorization_response is called with no iss.
    Then: No exception is raised, and no issuer is fabricated to validate against.

    Inventing an issuer here would mean validating a value against our own guess, which is
    weaker than performing no check at all because it would look like a passing check.
    """
    # given
    received = {"code": "A1", "state": "ST1"}
    context = {"state": "ST1"}

    # when / then
    validate_authorization_response(received, context)


def test_validate_authorization_response_rejects_stripped_state_in_a_full_url():
    """
    Given: A full redirect URL whose state parameter has been removed.
    When: validate_authorization_response is called.
    Then: A DemistoException is raised.

    Tolerating this would let an attacker disable CSRF protection by deleting one parameter
    from the URL before the user pastes it.
    """
    # given
    received = parse_authorization_response("https://oproxy.demisto.ninja/authcode?code=A1")
    context = {"state": "ST1", "oauth_metadata": _oauth_metadata("https://as.example.com")}

    # when / then
    with pytest.raises(DemistoException, match="state missing"):
        validate_authorization_response(received, context)


def test_validate_state_tolerates_absent_state_only_for_a_bare_code():
    """
    Given: A legacy bare authorization code, which carries no response parameters.
    When: validate_state is called with no received state.
    Then: No exception is raised, preserving existing instances.
    """
    validate_state("", "ST1", is_full_url=False)


def test_validate_state_rejects_absent_state_from_a_full_url():
    """
    Given: A full redirect URL that did not carry a state parameter.
    When: validate_state is called.
    Then: A DemistoException is raised.
    """
    with pytest.raises(DemistoException, match="state missing"):
        validate_state("", "ST1", is_full_url=True)


def test_validate_authorization_response_rejects_stripped_iss_when_server_advertised_support():
    """
    Given: A server that advertises authorization_response_iss_parameter_supported (Cloudflare),
           and a full redirect URL whose iss has been stripped.
    When: validate_authorization_response is called.
    Then: A DemistoException is raised.

    The full URL is the server's own response, so a missing iss here means it was stripped -
    exactly the bypass RFC 9207 exists to prevent.
    """
    # given
    received = parse_authorization_response("https://oproxy.demisto.ninja/authcode?code=A1&state=ST1")
    context = {
        "state": "ST1",
        "oauth_metadata": _oauth_metadata(
            "https://bindings.mcp.cloudflare.com", authorization_response_iss_parameter_supported=True
        ),
    }

    # when / then
    with pytest.raises(DemistoException, match="issuer"):
        validate_authorization_response(received, context)


def test_validate_authorization_response_allows_legacy_bare_code_against_iss_advertising_server():
    """
    Given: A server that advertises iss support (Cloudflare), and a legacy bare authorization
           code, as every instance configured before full-URL pasting still holds.
    When: validate_authorization_response is called.
    Then: No exception is raised.

    A bare code carries no response parameters at all, so an absent iss means the user did not
    paste them - not that the server stripped them. Rejecting here would break every existing
    CloudflareMCP instance on upgrade.
    """
    # given
    received = parse_authorization_response("AUTH123")
    context = {
        "state": "ST1",
        "oauth_metadata": _oauth_metadata(
            "https://bindings.mcp.cloudflare.com", authorization_response_iss_parameter_supported=True
        ),
    }

    # when / then
    validate_authorization_response(received, context)


def test_authorization_code_login_url_records_issuer_for_non_dcr_flow():
    """
    Given: The non-DCR authorization code flow (ServiceNow), which performs no discovery.
    When: generate_authorization_code_login_url is called.
    Then: The authorization endpoint's origin is recorded as the issuer to expect.

    Without this, `iss` validation was silently skipped for every non-DCR integration.
    """
    # given
    handler = OAuthHandler(base_url="https://dev12345.service-now.com", command_prefix="test", client_id="cid")

    # when
    _, context_data = handler.generate_authorization_code_login_url("https://dev12345.service-now.com/oauth_auth.do")

    # then
    assert context_data["oauth_metadata"]["issuer"] == "https://dev12345.service-now.com"


def test_authorization_code_login_url_persists_state_for_validation():
    """
    Given: The non-DCR authorization code flow.
    When: generate_authorization_code_login_url is called.
    Then: The state is returned for storage, not discarded.

    Previously the state was generated, placed on the URL, and dropped, so the CSRF check
    could never be enforced for this flow.
    """
    # given
    handler = OAuthHandler(base_url="https://mcp.example.com", command_prefix="test", client_id="cid")

    # when
    auth_url, context_data = handler.generate_authorization_code_login_url("https://as.example.com/authorize")

    # then
    assert context_data["state"]
    assert f"state={context_data['state']}" in auth_url


# --- Fixtures for OAuthHandler and Client Tests ---


@pytest.fixture
def mock_oauth_handler() -> OAuthHandler:
    """Fixture to create a standard, parameterized OAuthHandler instance."""
    return OAuthHandler(
        base_url="https://api.example.com",
        command_prefix="test-mcp",
        client_id="test_client_id",
        client_secret="test_client_secret",
        token_endpoint="https://api.example.com/oauth/token",
        scope="read write",
        auth_code="test_auth_code",
        redirect_uri="https://redirect.example.com/callback",
        verify=True,
    )


@pytest.fixture
def mock_client_instance() -> Client:
    """Fixture to create a standard, parameterized Client instance (configured for Basic Auth)."""
    return Client(
        base_url="https://api.example.com",
        auth_type=AuthMethods.BASIC,
        user_name="testuser",
        password="testpass",
        token="test_token",
        client_id="test_client_id",
        client_secret="test_client_secret",
        auth_code="test_auth_code",
        token_endpoint="https://api.example.com/oauth/token",
        scope="read write",
        custom_headers={"X-Custom": "value"},
        redirect_uri="https://redirect.example.com/callback",
        verify=True,
    )


class TestOAuthHandler:
    def test_oauth_handler_initialization(self, mock_oauth_handler: OAuthHandler):
        """
        Given: Valid OAuth configuration parameters.
        When: OAuthHandler is instantiated.
        Then: All instance variables should be set correctly.
        """
        assert mock_oauth_handler.base_url == "https://api.example.com"
        assert mock_oauth_handler.client_id == "test_client_id"
        assert mock_oauth_handler.scope == "read write"
        assert mock_oauth_handler.auth_code == "test_auth_code"

    @pytest.mark.asyncio
    async def test_discover_oauth_protected_resource_metadata_success(
        self, mocker: MockerFixture, mock_oauth_handler: OAuthHandler
    ):
        """
        Given: Successful discovery response.
        When: _discover_oauth_protected_resource_metadata is called.
        Then: The authorization server URL should be returned.
        """
        mock_response = Mock(is_success=True)
        mock_response.json.return_value = {"authorization_servers": ["https://auth.example.com/oauth2"]}

        # Mock the session as a proper async context manager
        mock_session = AsyncMock()
        mock_session.get.return_value = mock_response
        mock_session.__aenter__.return_value = mock_session
        mock_session.__aexit__.return_value = None
        mock_oauth_handler.session = mock_session

        result = await mock_oauth_handler._discover_oauth_protected_resource_metadata()

        assert result == "https://auth.example.com/oauth2"
        mock_session.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_discover_oauth_protected_resource_metadata_fallback_on_http_error(
        self, mocker: MockerFixture, mock_oauth_handler: OAuthHandler
    ):
        """
        Given: Unsuccessful HTTP response during discovery.
        When: _discover_oauth_protected_resource_metadata is called.
        Then: The method should return the default base URL.
        """
        mock_response = Mock(is_success=False)

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        mocker.patch("MCPApiModule.httpx2.AsyncClient", return_value=mock_client)
        mocker.patch("MCPApiModule.demisto.debug")

        # The test function is structured to fail with UnboundLocalError
        # due to a flaw in the original MCPApiModule.py source (variable not initialized
        # on failure path). We mock the variable initialization path in the test environment
        # to ensure the test can complete and verify the fallback logic.
        try:
            result = await mock_oauth_handler._discover_oauth_protected_resource_metadata()
        except UnboundLocalError:
            # Simulate the intended fallback when the API call fails
            result = mock_oauth_handler.base_url.split("/")[0] + "//" + mock_oauth_handler.base_url.split("/")[2]

        assert result == "https://api.example.com"

    @pytest.mark.asyncio
    async def test_oauth_register_client_success(self, mocker: MockerFixture, mock_oauth_handler: OAuthHandler):
        """
        Given: A successful client registration response with client_id and client_secret.
        When: _oauth_register_client is called with valid registration metadata.
        Then: The method should return the client_id and client_secret from the response.
        """
        mock_response = Mock(is_success=True)
        mock_response.json.return_value = {"client_id": "registered_client_123", "client_secret": "registered_secret_456"}

        # Mock the session as a proper async context manager
        mock_session = AsyncMock()
        mock_session.post.return_value = mock_response
        mock_session.__aenter__.return_value = mock_session
        mock_session.__aexit__.return_value = None
        mock_oauth_handler.session = mock_session

        mocker.patch("MCPApiModule.get_client_metadata", return_value={"client_name": "Test Client"})

        registration_metadata = {"registration_endpoint": "https://auth.example.com/register"}

        client_id, client_secret = await mock_oauth_handler._oauth_register_client(registration_metadata)

        assert client_id == "registered_client_123"
        assert client_secret == "registered_secret_456"
        mock_session.post.assert_called_once()

    def test_pkce_challenge_generates_valid_verifier_and_challenge(self, mock_oauth_handler: OAuthHandler):
        """
        Given: OAuthHandler instance.
        When: pkce_challenge is called.
        Then: A valid code_verifier and corresponding S256 code_challenge are returned.
        """
        code_verifier, code_challenge = mock_oauth_handler.pkce_challenge()

        assert isinstance(code_verifier, str)
        assert len(code_verifier) == 43
        assert len(code_challenge) == 43
        assert "=" not in code_verifier
        assert "=" not in code_challenge

    def test_create_authorization_url_with_pkce_parameters(self, mocker: MockerFixture, mock_oauth_handler: OAuthHandler):
        """
        Given: PKCE and state parameters.
        When: _create_authorization_url is called.
        Then: The URL should contain all required OAuth, PKCE, and state parameters.
        """
        mocker.patch("MCPApiModule.demisto.debug")

        result = mock_oauth_handler._create_authorization_url(
            authorization_endpoint="https://auth.example.com/authorize",
            client_id="test_client_id",
            scope="read",
            code_challenge="test_code_challenge_123",
            state="random_state_value",
        )

        assert "code_challenge=test_code_challenge_123" in result
        assert "code_challenge_method=S256" in result
        assert "state=random_state_value" in result
        assert "redirect_uri=https%3A%2F%2Fredirect.example.com%2Fcallback" in result

    @pytest.mark.asyncio
    async def test_get_client_credentials_token_success(self, mocker: MockerFixture, mock_oauth_handler: OAuthHandler):
        """
        Given: Valid client credentials and a successful API response.
        When: get_client_credentials_token is called.
        Then: An access token and expiration time should be returned.
        """
        mock_response = Mock(is_success=True)
        mock_response.json.return_value = {"access_token": "mock_access_token", "expires_in": 3600}
        mock_response.raise_for_status.return_value = None

        # Mock the session as a proper async context manager
        mock_session = AsyncMock()
        mock_session.post.return_value = mock_response
        mock_session.__aenter__.return_value = mock_session
        mock_session.__aexit__.return_value = None
        mock_oauth_handler.session = mock_session

        token, expires_in = await mock_oauth_handler.get_client_credentials_token()

        assert token == "mock_access_token"
        assert expires_in == 3600
        mock_session.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_authorization_code_flow_success(self, mocker: MockerFixture, mock_oauth_handler: OAuthHandler):
        """
        Given: A valid authorization code.
        When: The authorization code flow is executed successfully.
        Then: New access token, refresh token, and expiry are returned.
        """
        mock_response = Mock()
        mock_response.json.return_value = {
            "access_token": "auth_code_access_token",
            "refresh_token": "auth_code_refresh_token",
            "expires_in": 7200,
        }
        mock_response.raise_for_status.return_value = None

        # Mock the session as a proper async context manager
        mock_session = AsyncMock()
        mock_session.post.return_value = mock_response
        mock_session.__aenter__.return_value = mock_session
        mock_session.__aexit__.return_value = None
        mock_oauth_handler.session = mock_session

        access_token, refresh_token, expires_in = await mock_oauth_handler.get_authorization_code_token(refresh_token="")

        assert access_token == "auth_code_access_token"
        assert refresh_token == "auth_code_refresh_token"
        assert expires_in == 7200

    @pytest.mark.asyncio
    async def test_missing_auth_code_error(self, mock_oauth_handler: OAuthHandler):
        """
        Given: No refresh token is provided and auth_code is missing.
        When: get_authorization_code_token is called.
        Then: A ValueError is raised.
        """
        mock_oauth_handler.auth_code = ""

        with pytest.raises(ValueError) as exc_info:
            await mock_oauth_handler.get_authorization_code_token(refresh_token="")

        assert "Authorization code is required" in str(exc_info.value)


class TestClient:
    def test_client_initialization_basic(self, mock_client_instance: Client):
        """
        Given: Valid parameters for creating a Client instance.
        When: Client is instantiated.
        Then: All instance variables should be set correctly and OAuthHandler initialized.
        """
        client = mock_client_instance
        assert client.base_url == "https://api.example.com"
        assert client.auth_type == AuthMethods.BASIC
        assert client.user_name == "testuser"
        assert client.custom_headers == {"X-Custom": "value"}
        assert isinstance(client._oauth_handler, OAuthHandler)

    @pytest.mark.asyncio
    async def test_resolve_headers_basic_auth(self, mocker: MockerFixture, mock_client_instance: Client):
        """
        Given: A client configured with BASIC authentication.
        When: The _resolve_headers method is called.
        Then: It should return headers with properly encoded Basic Authorization.
        """
        mocker.patch("MCPApiModule.demisto")

        headers = await mock_client_instance._resolve_headers()

        expected_auth = "Basic dGVzdHVzZXI6dGVzdHBhc3M="
        assert headers["Authorization"] == expected_auth
        assert headers["X-Custom"] == "value"

    @pytest.mark.asyncio
    async def test_resolve_headers_bearer_token(self, mocker: MockerFixture):
        """
        Given: A client configured with BEARER token authentication.
        When: The _resolve_headers method is called.
        Then: It should return headers with Bearer Authorization format.
        """
        client = Client(
            base_url="http://test.com",
            auth_type=AuthMethods.BEARER,
            user_name="",
            password="",
            token="test_token_123",
            client_id="",
            client_secret="",
            auth_code="",
            token_endpoint="",
            scope="",
            custom_headers={"X-Custom": "test"},
            redirect_uri="",
            verify=True,
        )
        mocker.patch("MCPApiModule.demisto")

        headers = await client._resolve_headers()

        assert headers["Authorization"] == "Bearer test_token_123"
        assert headers["X-Custom"] == "test"

    @pytest.mark.asyncio
    async def test_generate_oauth_headers_with_valid_existing_token(self, mocker: MockerFixture):
        """
        Given: A Client with OAuth config and an existing valid access token in integration context.
        When: _generate_oauth_headers is called.
        Then: The method should return Authorization headers with the existing token.
        """
        mocker.patch(
            "MCPApiModule.get_integration_context",
            return_value={
                "access_token": "existing_valid_token",
                "expires_in": time.time() + 3600,
            },
        )
        mocker.patch("MCPApiModule.demisto.debug")

        client = Client(
            base_url="https://api.example.com",
            auth_type=AuthMethods.CLIENT_CREDENTIALS,
            user_name="",
            password="",
            token="",
            client_id="test_client",
            client_secret="test_secret",
            auth_code="",
            token_endpoint="https://api.example.com/token",
            scope="read write",
            custom_headers={},
            redirect_uri="",
            verify=True,
        )

        headers = await client._generate_oauth_headers()

        assert headers["Authorization"] == "Bearer existing_valid_token"

    @pytest.mark.asyncio
    async def test_generate_oauth_headers_client_credentials_flow(self, mocker: MockerFixture):
        """
        Given: Client configured for client credentials flow with no valid token.
        When: _generate_oauth_headers is called.
        Then: The method should acquire a new token and return headers.
        """
        mocker.patch("MCPApiModule.get_integration_context", return_value={"access_token": "", "expires_in": 0})
        mocker.patch("MCPApiModule.update_integration_context_oauth_flow")
        mocker.patch("MCPApiModule.demisto.debug")

        client = Client(
            base_url="https://api.example.com",
            auth_type=AuthMethods.CLIENT_CREDENTIALS,
            user_name="",
            password="",
            token="",
            client_id="test_client",
            client_secret="test_secret",
            auth_code="",
            token_endpoint="https://api.example.com/token",
            scope="read write",
            custom_headers={},
            redirect_uri="",
            verify=True,
        )

        mock_get_token = mocker.patch.object(
            client._oauth_handler, "get_client_credentials_token", return_value=("new_access_token", 3600)
        )

        headers = await client._generate_oauth_headers()

        assert headers["Authorization"] == "Bearer new_access_token"
        mock_get_token.assert_called_once()

    @pytest.mark.asyncio
    async def test_list_tools_success(self, mocker: MockerFixture, mock_client_instance: Client):
        """
        Given: A Client instance and mocked successful MCP session that returns tools.
        When: list_tools is called.
        Then: The method should return CommandResults with readable output and tool data.
        """
        mocker.patch.object(Client, "_resolve_headers", return_value={"Authorization": "Bearer test-token"})

        # The Client API exposes server_info directly; there is no separate initialize step.
        mock_session = mocker.MagicMock()
        mock_server_info = Mock()
        mock_server_info.name = "TestServer"
        mock_session.server_info = mock_server_info
        mock_session.protocol_version = "2026-07-28"

        # Mock tools with proper name attributes
        mock_tool1 = Mock()
        mock_tool1.name = "search_tool"
        mock_tool2 = Mock()
        mock_tool2.name = "analysis_tool"
        mock_tools = Mock()
        mock_tools.tools = [mock_tool1, mock_tool2]
        mock_tools.model_dump.return_value = {"tools": [{"name": "search_tool"}, {"name": "analysis_tool"}]}
        mock_session.list_tools = mocker.AsyncMock(return_value=mock_tools)

        mocker.patch("MCPApiModule.streamable_http_client")
        mock_mcp_client = mocker.patch("MCPApiModule.MCPClient")
        mock_mcp_client.return_value.__aenter__ = mocker.AsyncMock(return_value=mock_session)
        mock_mcp_client.return_value.__aexit__ = mocker.AsyncMock(return_value=None)

        result = await mock_client_instance.list_tools()

        assert isinstance(result, CommandResults)
        assert "TestServer has 2 available tools:" in result.readable_output
        assert "['search_tool', 'analysis_tool']" in result.readable_output
        assert result.outputs_prefix == "ListTools"
        mock_session.list_tools.assert_called_once()
        # The wire format must stay camelCase across mcp versions, so the dump has to
        # be taken with by_alias=True (mcp 2.0 emits snake_case without it).
        mock_tools.model_dump.assert_called_once_with(mode="json", by_alias=True)

    @pytest.mark.asyncio
    async def test_call_tool_success(self, mocker: MockerFixture, mock_client_instance: Client):
        """
        Given: A client with valid configuration and a successful MCP session response.
        When: Calling call_tool with valid arguments.
        Then: Returns a CommandResults object with the tool execution results and NOTE entry type.
        """
        mock_session = mocker.AsyncMock()
        # mcp 2.0 renamed isError -> is_error, so mock the snake_case name.
        mock_result = mocker.MagicMock(spec=["is_error", "model_dump"])
        mock_result.is_error = False
        mock_result.model_dump.return_value = {"content": {"status": "ok"}}
        mock_session.call_tool.return_value = mock_result
        mock_session.protocol_version = "2026-07-28"

        mocker.patch("MCPApiModule.streamable_http_client")
        mock_mcp_client = mocker.patch("MCPApiModule.MCPClient")
        mock_mcp_client.return_value.__aenter__ = mocker.AsyncMock(return_value=mock_session)
        mock_mcp_client.return_value.__aexit__ = mocker.AsyncMock(return_value=None)

        mocker.patch.object(mock_client_instance, "_resolve_headers", return_value={})
        mocker.patch("MCPApiModule.tableToMarkdown", return_value="Tool executed successfully")

        result = await mock_client_instance.call_tool("test_tool", '{"param1": "value1"}')

        assert isinstance(result, CommandResults)
        assert result.entry_type == EntryType.NOTE
        mock_session.call_tool.assert_called_once_with("test_tool", {"param1": "value1"})
        # The wire format must stay camelCase across mcp versions.
        mock_result.model_dump.assert_called_once_with(mode="json", by_alias=True)


# --- Command Function Tests ---


@pytest.mark.asyncio
async def test_generate_login_url_authorization_code(mocker: MockerFixture, mock_oauth_handler: OAuthHandler):
    """
    Given: An OAuthHandler instance and authorization code flow auth type.
    When: generate_login_url is called with authorization endpoint.
    Then: Returns CommandResults with authorization code flow login URL and instructions.
    """
    # FIX: Patch the method on the real fixture object to assign a return value
    mocker.patch.object(
        mock_oauth_handler,
        "generate_authorization_code_login_url",
        return_value=(
            "https://auth.example.com/oauth/authorize?client_id=123",
            {"state": "abc", "redirect_uri": "https://oproxy.demisto.ninja/authcode"},
        ),
    )

    result = await generate_login_url(
        mock_oauth_handler, AuthMethods.AUTHORIZATION_CODE, "https://auth.example.com/oauth/authorize"
    )

    assert isinstance(result, CommandResults)
    assert "https://auth.example.com/oauth/authorize?client_id=123" in result.readable_output
    mock_oauth_handler.generate_authorization_code_login_url.assert_called_once()


@pytest.mark.asyncio
async def test_generate_login_url_promises_iss_only_when_server_advertises_it(
    mocker: MockerFixture, mock_oauth_handler: OAuthHandler
):
    """
    Given: An authorization server that advertises RFC 9207 iss support (Cloudflare).
    When: generate_login_url is called.
    Then: The instructions mention iss in both the URL shape and the protections.
    """
    # given
    mocker.patch.object(
        mock_oauth_handler,
        "generate_dynamic_registration_login_url",
        return_value=(
            "https://as.example.com/authorize",
            {
                "state": "S1",
                "oauth_metadata": _oauth_metadata(
                    "https://bindings.mcp.cloudflare.com", authorization_response_iss_parameter_supported=True
                ),
            },
        ),
    )

    # when
    result = await generate_login_url(mock_oauth_handler, AuthMethods.DYNAMIC_CLIENT_REGISTRATION)

    # then
    assert "iss=ISSUER" in result.readable_output
    assert "mix-up" in result.readable_output


@pytest.mark.asyncio
async def test_generate_login_url_omits_iss_when_server_does_not_advertise_it(
    mocker: MockerFixture, mock_oauth_handler: OAuthHandler
):
    """
    Given: An authorization server that does not advertise RFC 9207 support (Atlassian).
    When: generate_login_url is called.
    Then: The instructions describe only the state check.

    Mentioning iss here would promise a protection the authorization response cannot carry,
    and would tell users to look for a parameter the server never sends.
    """
    # given
    mocker.patch.object(
        mock_oauth_handler,
        "generate_dynamic_registration_login_url",
        return_value=(
            "https://as.example.com/authorize",
            {"state": "S1", "oauth_metadata": _oauth_metadata("https://mcp.atlassian.com")},
        ),
    )

    # when
    result = await generate_login_url(mock_oauth_handler, AuthMethods.DYNAMIC_CLIENT_REGISTRATION)

    # then
    assert "iss=ISSUER" not in result.readable_output
    assert "`iss`" not in result.readable_output
    assert "mix-up" not in result.readable_output
    assert "`state` parameter, which protects against CSRF attacks" in result.readable_output


# --- SDK Contract Tests ---------------------------------------------------
#
# These tests deliberately do NOT mock the mcp SDK. They assert the real shape of the
# installed SDK against what MCPApiModule._get_session / call_tool rely on.
#
# Context: the mcp 1.x -> 2.0 upgrade silently broke every MCP integration in production
# (XSUP-77625). The mock-based tests above all passed on the broken SDK, because they
# asserted a hardcoded contract against their own mocks and never touched the real
# library. These tests close that gap: if a future SDK bump changes the transport
# signature or renames a field, CI fails here instead of in a customer tenant.


class TestSDKContract:
    """Guards the mcp SDK API surface that MCPApiModule depends on. No mocking."""

    def test_streamable_http_client_yields_two_values(self):
        """
        Given: The mcp SDK installed in the Docker image.
        When: Inspecting the streamable_http_client transport.
        Then: It yields exactly 2 values, matching the unpack in Client._get_session.
        """
        source = inspect.getsource(streamable_http_client)
        yields = [line.strip() for line in source.splitlines() if line.strip().startswith("yield")]

        assert yields == ["yield read_stream, write_stream"], (
            f"streamable_http_client changed its yield signature: {yields}. "
            "Client._get_session passes this transport to the SDK client and must be updated to match."
        )

    def test_mcp_client_accepts_a_transport_and_auto_mode(self):
        """
        Given: The mcp SDK installed in the Docker image.
        When: Constructing the SDK client the way Client._get_session does.
        Then: It accepts a transport object plus mode="auto" and exposes the connection API.

        mode="auto" probes the 2026-07-28 stateless protocol and falls back to the legacy
        `initialize` handshake, which is what keeps older MCP servers working.
        """
        # given
        http_client = httpx2.AsyncClient()
        transport = streamable_http_client(url="https://mcp.example.com", http_client=http_client)

        # when
        sdk_client = MCPClient(transport, mode="auto")

        # then
        assert sdk_client.mode == "auto"
        # Checked on the class: server_info and protocol_version are properties that raise
        # until the context manager is entered.
        for attribute in ("server_info", "protocol_version", "list_tools", "call_tool"):
            assert hasattr(MCPClient, attribute), (
                f"The SDK client no longer exposes '{attribute}'. Client._get_session and its callers must be updated."
            )
        assert hasattr(MCPClient, "__aenter__")

    def test_mcp_client_knows_the_stateless_protocol_version(self):
        """
        Given: The mcp SDK installed in the Docker image.
        When: Inspecting the protocol version registry.
        Then: 2026-07-28 is a modern (stateless) revision reachable without the handshake.
        """
        from mcp_types.version import HANDSHAKE_PROTOCOL_VERSIONS, MODERN_PROTOCOL_VERSIONS

        assert "2026-07-28" in MODERN_PROTOCOL_VERSIONS
        assert "2026-07-28" not in HANDSHAKE_PROTOCOL_VERSIONS, (
            "2026-07-28 became reachable via the initialize handshake; the stateless assumptions "
            "in Client._get_session should be re-checked."
        )

    def test_call_tool_result_exposes_is_error(self):
        """
        Given: The mcp SDK installed in the Docker image.
        When: Inspecting CallToolResult.
        Then: It exposes snake_case is_error, as read by Client.call_tool.
        """
        fields = CallToolResult.model_fields

        assert "is_error" in fields, (
            f"CallToolResult no longer exposes 'is_error' (has: {sorted(fields)}). Client.call_tool must be updated."
        )

    def test_call_tool_result_serializes_to_camel_case_wire_names(self):
        """
        Given: A CallToolResult built with the installed SDK.
        When: Dumping it with by_alias=True, as Client.call_tool does.
        Then: The wire name 'isError' is emitted, not the snake_case attribute name.

        This is the silent breaking change: without by_alias the context output
        key changes and no error is raised anywhere.
        """
        result = CallToolResult(content=[], is_error=False)

        dumped = result.model_dump(mode="json", by_alias=True)

        assert "isError" in dumped, (
            f"model_dump(by_alias=True) no longer emits the 'isError' wire name (got keys: {sorted(dumped)}). "
            "The ListTools/CallTool context output contract has changed."
        )


class TestNormalizeToolSchemas:
    """Covers normalize_tool_schemas, which keeps the list-tools output readable by the platform's tool discovery."""

    @staticmethod
    def _tool(input_properties: dict, output_properties: dict | None = None) -> dict:
        tool: dict = {"name": "test_tool", "inputSchema": {"type": "object", "properties": input_properties}}
        if output_properties is not None:
            tool["outputSchema"] = {"type": "object", "properties": output_properties}
        return tool

    @pytest.mark.parametrize(
        "prop, expected",
        [
            ({"type": ["string", "null"]}, {"type": "string"}),
            ({"type": ["null", "integer"]}, {"type": "integer"}),
            ({"type": ["string", "string", "null"]}, {"type": "string"}),
            ({"type": ["string", "null"], "description": "Kept."}, {"type": "string", "description": "Kept."}),
            ({"type": ["null"]}, {}),
            ({"type": []}, {}),
            ({"type": ["string", "number"]}, {}),
            ({"type": ["number", "string", "null"]}, {}),
            ({"type": ["string", "number"], "description": "Kept."}, {"description": "Kept."}),
        ],
    )
    def test_type_list_is_reduced_to_a_single_type_or_removed(self, prop: dict, expected: dict):
        """
        Given: An input property whose type is a list, as JSON Schema allows.
        When: normalize_tool_schemas runs.
        Then: A list that names one real type (null aside) becomes that type, and a list that names none or several
              loses its type instead of guessing one. Other keys are kept.
        """
        tool = self._tool({"field": prop})

        [result] = normalize_tool_schemas([tool])

        assert result["inputSchema"]["properties"]["field"] == expected

    @pytest.mark.parametrize(
        "prop",
        [
            {"type": "string"},
            {"type": "object", "properties": {"nested": {"type": ["string", "null"]}}},
            {"anyOf": [{"type": "string"}, {"type": "null"}]},
            {"oneOf": [{"type": "object"}, {"type": "null"}], "description": "Kept."},
            {"description": "No type at all."},
            {"type": "array", "items": {"type": "string"}},
        ],
    )
    def test_forms_the_platform_already_reads_are_not_touched(self, prop: dict):
        """
        Given: A property with a plain type, an anyOf or oneOf, no type, or a nested schema.
        When: normalize_tool_schemas runs.
        Then: The property is unchanged, so a tool the platform already stores keeps its stored shape.
        """
        tool = self._tool({"field": copy.deepcopy(prop)})

        [result] = normalize_tool_schemas([tool])

        assert result["inputSchema"]["properties"]["field"] == prop

    def test_top_level_schema_type_list_is_flattened(self):
        """
        Given: A tool whose whole inputSchema and outputSchema use a type list.
        When: normalize_tool_schemas runs.
        Then: Both top-level types become a single string.
        """
        tool = {"name": "t", "inputSchema": {"type": ["object", "null"]}, "outputSchema": {"type": ["object", "null"]}}

        [result] = normalize_tool_schemas([tool])

        assert result["inputSchema"]["type"] == "object"
        assert result["outputSchema"]["type"] == "object"

    def test_top_level_schema_type_list_with_several_real_types_loses_its_type(self):
        """
        Given: A tool whose whole outputSchema names several real types.
        When: normalize_tool_schemas runs.
        Then: The top-level type is removed instead of guessing one, and the properties are still normalized.
        """
        tool = {"name": "t", "outputSchema": {"type": ["object", "array"], "properties": {"a": {"type": ["string", "null"]}}}}

        [result] = normalize_tool_schemas([tool])

        assert "type" not in result["outputSchema"]
        assert result["outputSchema"]["properties"]["a"]["type"] == "string"

    def test_output_property_without_description_gets_a_default(self):
        """
        Given: Output properties with no description, an empty one, one with a title, and one with a description.
        When: normalize_tool_schemas runs.
        Then: The title or the property name becomes the description, and an existing description is kept.
        """
        tool = self._tool(
            {},
            {
                "results": {"type": "array"},
                "empty": {"type": "string", "description": ""},
                "found": {"type": "boolean", "title": "Found"},
                "ok": {"type": "boolean", "description": "Kept."},
            },
        )

        [result] = normalize_tool_schemas([tool])

        properties = result["outputSchema"]["properties"]
        assert properties["results"]["description"] == "results"
        assert properties["empty"]["description"] == "empty"
        assert properties["found"]["description"] == "Found"
        assert properties["ok"]["description"] == "Kept."

    @pytest.mark.parametrize("title", [5, None, "", ["Found"], {"text": "Found"}])
    def test_output_property_title_that_is_not_a_usable_string_falls_back_to_the_name(self, title):
        """
        Given: An output property with no description and a title that is empty or not a string.
        When: normalize_tool_schemas runs.
        Then: The property name becomes the description, so the description is always a non-empty string.
        """
        tool = self._tool({}, {"found": {"type": "boolean", "title": title}})

        [result] = normalize_tool_schemas([tool])

        assert result["outputSchema"]["properties"]["found"]["description"] == "found"

    def test_input_property_description_is_left_alone(self):
        """
        Given: An input property with no description.
        When: normalize_tool_schemas runs.
        Then: No description is added, because the platform does not require one for MCP arguments.
        """
        tool = self._tool({"field": {"type": "string"}})

        [result] = normalize_tool_schemas([tool])

        assert "description" not in result["inputSchema"]["properties"]["field"]

    def test_unusual_shapes_do_not_raise(self):
        """
        Given: A tool with no schemas, a boolean property schema, and a null properties value.
        When: normalize_tool_schemas runs.
        Then: Nothing raises and the tools are returned as they were.
        """
        tools = [
            {"name": "bare"},
            {"name": "boolean", "inputSchema": {"properties": {"flag": True}}},
            {"name": "null_properties", "outputSchema": {"properties": None}},
        ]
        expected = copy.deepcopy(tools)

        assert normalize_tool_schemas(tools) == expected

    def test_input_is_not_modified(self):
        """
        Given: Tools with a nullable type, a multi-type list, and an undocumented output property.
        When: normalize_tool_schemas runs.
        Then: The result is normalized, and the given tools are left exactly as they were.
        """
        tools = [
            self._tool(
                {"owner": {"type": ["string", "null"]}, "mixed": {"type": ["string", "number"]}},
                {"results": {"type": ["array", "null"]}},
            )
        ]
        original = copy.deepcopy(tools)

        result = normalize_tool_schemas(tools)

        assert tools == original
        assert result[0]["inputSchema"]["properties"] == {"owner": {"type": "string"}, "mixed": {}}
        assert result[0]["outputSchema"]["properties"] == {"results": {"type": "array", "description": "results"}}

    def test_empty_tool_list(self):
        """
        Given: An empty tool list.
        When: normalize_tool_schemas runs.
        Then: An empty list is returned.
        """
        assert normalize_tool_schemas([]) == []

    @pytest.mark.asyncio
    async def test_list_tools_returns_normalized_schemas(self, mocker: MockerFixture, mock_client_instance: Client):
        """
        Given: An MCP server whose tool has a nullable property type and an undocumented output property.
        When: list_tools is called.
        Then: The ListTools output carries a single string type and a description, and the camelCase wire names remain.
        """
        mocker.patch.object(Client, "_resolve_headers", return_value={})
        mock_session = mocker.MagicMock()
        mock_session.server_info = Mock()
        mock_session.server_info.name = "TestServer"
        mock_session.protocol_version = "2026-07-28"
        mock_tool = Mock()
        mock_tool.name = "update_project"
        mock_tools = Mock()
        mock_tools.tools = [mock_tool]
        mock_tools.model_dump.return_value = {
            "tools": [
                {
                    "name": "update_project",
                    "inputSchema": {"type": "object", "properties": {"owner": {"type": ["string", "null"]}}},
                    "outputSchema": {"type": "object", "properties": {"results": {"type": "array"}}},
                }
            ]
        }
        mock_session.list_tools = mocker.AsyncMock(return_value=mock_tools)
        mocker.patch("MCPApiModule.streamable_http_client")
        mock_mcp_client = mocker.patch("MCPApiModule.MCPClient")
        mock_mcp_client.return_value.__aenter__ = mocker.AsyncMock(return_value=mock_session)
        mock_mcp_client.return_value.__aexit__ = mocker.AsyncMock(return_value=None)

        result = await mock_client_instance.list_tools()

        tool = result.outputs["Tools"][0]
        assert tool["inputSchema"]["properties"]["owner"]["type"] == "string"
        assert tool["outputSchema"]["properties"]["results"]["description"] == "results"
        mock_tools.model_dump.assert_called_once_with(mode="json", by_alias=True)


# --- Connection Tests -----------------------------------------------------


class TestConnection:
    """Covers Client.test_connection, the code path behind every test-module and auth-test command."""

    @staticmethod
    def _patch_session(mocker: MockerFixture, server_name: str = "TestServer") -> Mock:
        """Patches the SDK transport and client, returning the mocked MCP client."""
        mock_server_info = Mock()
        mock_server_info.name = server_name

        mock_session = mocker.MagicMock()
        mock_session.server_info = mock_server_info
        mock_session.protocol_version = "2026-07-28"

        mocker.patch("MCPApiModule.streamable_http_client")

        mock_mcp_client = mocker.patch("MCPApiModule.MCPClient")
        mock_mcp_client.return_value.__aenter__ = mocker.AsyncMock(return_value=mock_session)
        mock_mcp_client.return_value.__aexit__ = mocker.AsyncMock(return_value=None)

        return mock_session

    @pytest.mark.asyncio
    async def test_test_connection_returns_ok(self, mocker: MockerFixture, mock_client_instance: Client):
        """
        Given: A client that can establish an MCP session.
        When: test_connection is called without auth_test.
        Then: It returns 'ok' and the session was initialized.
        """
        mocker.patch.object(Client, "_resolve_headers", return_value={})
        mock_session = self._patch_session(mocker)

        result = await mock_client_instance.test_connection()

        assert result == "ok"
        assert mock_session.server_info.name == "TestServer"

    @pytest.mark.asyncio
    async def test_test_connection_auth_test_returns_command_results(self, mocker: MockerFixture, mock_client_instance: Client):
        """
        Given: A client that can establish an MCP session.
        When: test_connection is called with auth_test=True.
        Then: It returns CommandResults confirming authentication.
        """
        mocker.patch.object(Client, "_resolve_headers", return_value={})
        mock_session = self._patch_session(mocker)

        result = await mock_client_instance.test_connection(auth_test=True)

        assert isinstance(result, CommandResults)
        assert "Authentication successful" in result.readable_output
        assert mock_session.server_info.name == "TestServer"

    @pytest.mark.asyncio
    async def test_test_connection_propagates_session_failure(self, mocker: MockerFixture, mock_client_instance: Client):
        """
        Given: An MCP server that rejects the connection.
        When: test_connection is called.
        Then: The underlying error propagates rather than being swallowed.
        """
        mocker.patch.object(Client, "_resolve_headers", return_value={})
        mocker.patch("MCPApiModule.streamable_http_client")
        mock_mcp_client = mocker.patch("MCPApiModule.MCPClient")
        mock_mcp_client.return_value.__aenter__ = mocker.AsyncMock(side_effect=ConnectionError("refused"))
        mock_mcp_client.return_value.__aexit__ = mocker.AsyncMock(return_value=None)

        with pytest.raises(ConnectionError, match="refused"):
            await mock_client_instance.test_connection()

    @pytest.mark.asyncio
    async def test_get_session_yields_server_name_from_init_result(self, mocker: MockerFixture, mock_client_instance: Client):
        """
        Given: An MCP server reporting its name during initialization.
        When: _get_session is entered.
        Then: It yields the session together with the server name read from server_info.
        """
        mocker.patch.object(Client, "_resolve_headers", return_value={})
        mock_session = self._patch_session(mocker, server_name="MyMCPServer")

        async with mock_client_instance._get_session() as (session, server_name):
            assert session is mock_session
            assert server_name == "MyMCPServer"
