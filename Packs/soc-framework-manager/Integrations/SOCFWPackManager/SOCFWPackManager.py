"""SOC Framework Pack Manager integration.

Internal HTTP layer for the SOCFWPackManager script. Downloads a SOC Framework
content pack ZIP from a URL and uploads it to the tenant as system content.

End users do not call this integration directly. The SOCFWPackManager script
invokes ``socfw-install-pack`` on this integration.
"""

import os
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Any

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401,F403


INTEGRATION_NAME = "SOCFWPackManager"

# Hard cap on the size of a pack ZIP we will download or extract.
# SOC Framework packs are small (a few MB); 500 MB leaves plenty of headroom
# while bounding memory / disk usage for a wrong or malicious URL.
MAX_DOWNLOAD_BYTES = 500 * 1024 * 1024  # 500 MB
DOWNLOAD_CHUNK_BYTES = 1024 * 1024  # 1 MB streaming chunks
DEFAULT_DOWNLOAD_TIMEOUT = 300  # seconds
DEFAULT_TEST_TIMEOUT = 15  # seconds


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class ContentClient(BaseClient):
    """HTTP client for SOC Framework pack downloads and tenant connectivity.

    All HTTP traffic for this integration flows through this class so that
    timeout, TLS verification, and proxy settings are configured in exactly
    one place. The ``insecure`` and ``proxy`` integration parameters are
    threaded into ``BaseClient`` here and used uniformly for every request.
    """

    def __init__(
        self,
        base_url: str,
        api_id: str,
        api_key: str,
        verify: bool,
        proxy: bool,
    ):
        # public_api endpoints are served from api-<tenant>.xdr...
        api_base = (base_url or "").rstrip("/")
        if "://api-" not in api_base:
            api_base = api_base.replace("://", "://api-", 1)

        super().__init__(
            base_url=api_base,
            verify=verify,
            proxy=proxy,
            headers={
                "x-xdr-auth-id": str(api_id),
                "Authorization": api_key,
            },
        )
        self._verify = verify
        self._api_id = str(api_id)
        self._api_key = api_key
        self._raw_base_url = base_url.rstrip("/")
        self._api_base_url = api_base

    # -- connectivity -------------------------------------------------------

    def test_connectivity(self) -> None:
        """Probe a low-cost public_api endpoint to confirm credentials work."""
        self._http_request(
            method="POST",
            url_suffix="/public_api/v1/xql/get_datasets",
            json_data={"request_data": {}},
            timeout=DEFAULT_TEST_TIMEOUT,
            ok_codes=(200, 207),
            resp_type="response",
        )

    # -- pack download / upload --------------------------------------------

    def stream_download_zip(self, url: str, dest_path: str) -> int:
        """Download a pack ZIP to ``dest_path`` with an enforced size cap.

        Reads ``Content-Length`` up front when present, then bounds the actual
        bytes written so a server that lies about (or omits) length cannot
        blow past the cap. Uses BaseClient TLS verify / proxy settings.

        Returns the number of bytes written.
        """
        resp = self._http_request(
            method="GET",
            full_url=url,
            timeout=DEFAULT_DOWNLOAD_TIMEOUT,
            resp_type="response",
            stream=True,
        )

        advertised = resp.headers.get("Content-Length")
        if advertised is not None:
            try:
                if int(advertised) > MAX_DOWNLOAD_BYTES:
                    raise DemistoException(
                        f"Pack ZIP exceeds size limit "
                        f"({int(advertised)} bytes > {MAX_DOWNLOAD_BYTES})"
                    )
            except ValueError:
                # Non-integer Content-Length — fall through to streaming guard.
                pass

        written = 0
        with open(dest_path, "wb") as fh:
            for chunk in resp.iter_content(chunk_size=DOWNLOAD_CHUNK_BYTES):
                if not chunk:
                    continue
                written += len(chunk)
                if written > MAX_DOWNLOAD_BYTES:
                    fh.close()
                    if os.path.exists(dest_path):
                        os.unlink(dest_path)
                    raise DemistoException(
                        f"Pack ZIP exceeds size limit during download "
                        f"(> {MAX_DOWNLOAD_BYTES} bytes)"
                    )
                fh.write(chunk)
        return written

    def upload_pack_as_system_content(self, pack_path: str) -> dict:
        """Upload a pack directory as system content via demisto-sdk.

        ``upload_content_entity(xsiam=True, zip=True)`` is the documented path
        for installing a pack as system content. Credentials and TLS verify
        flow in via process env so the SDK call sees the same configuration
        as ContentClient itself.
        """
        self._set_sdk_env()

        # Imported lazily because demisto-sdk is heavy and only needed here.
        from demisto_sdk.commands.common.logger import logging_setup
        from demisto_sdk.commands.upload.upload import upload_content_entity

        logging_setup(
            INTEGRATION_NAME, console_threshold="CRITICAL", propagate=True
        )

        try:
            upload_content_entity(
                input=pack_path,
                zip=True,
                xsiam=True,
                insecure=(not self._verify),
            )
            return {"success": True, "message": f"Uploaded {pack_path}"}
        except BaseException as exc:
            # demisto-sdk raises SystemExit (or its own Exit class) on
            # completion. Exit code 0 / None is success.
            code = getattr(exc, "code", getattr(exc, "exit_code", None))
            if code is None:
                raise
            if str(code) not in ("0", "None"):
                raise DemistoException(
                    f"demisto-sdk upload failed with exit code {code}: {exc}"
                ) from exc
            return {"success": True, "message": f"Uploaded {pack_path}"}

    # -- internals ----------------------------------------------------------

    def _set_sdk_env(self) -> None:
        """Set env vars required by ``demisto-sdk upload_content_entity``."""
        os.environ["DEMISTO_API_KEY"] = self._api_key
        os.environ["XSIAM_AUTH_ID"] = self._api_id
        os.environ["DEMISTO_BASE_URL"] = self._api_base_url
        os.environ["DEMISTO_SDK_IGNORE_CONTENT_WARNING"] = "1"
        os.environ["DEMISTO_SDK_SKIP_LOGGER_SETUP"] = "yes"
        os.environ["DEMISTO_SDK_OFFLINE_ENV"] = "False"
        os.environ["ARTIFACTS_FOLDER"] = "/tmp/artifacts"
        os.environ["DEMISTO_SDK_LOG_NO_COLORS"] = "true"


# ---------------------------------------------------------------------------
# Safe ZIP extraction (ZipSlip / path-traversal hardened)
# ---------------------------------------------------------------------------


def _safe_extract_zip(zip_path: str, target_dir: str) -> None:
    """Extract ``zip_path`` into ``target_dir`` rejecting any member that
    would escape the destination directory via ``..`` or absolute paths.

    Mitigates ZipSlip (CWE-22) and bounds total uncompressed size to the
    same cap used for the download.
    """
    target_root = os.path.realpath(target_dir)

    with zipfile.ZipFile(zip_path, "r") as zf:
        # Pre-flight: validate every member path and size.
        total_uncompressed = 0
        for info in zf.infolist():
            member_name = info.filename
            if not member_name or member_name.endswith("/"):
                continue  # directories handled by extractall

            # Reject absolute paths and Windows drive paths.
            if os.path.isabs(member_name) or (
                len(member_name) > 1 and member_name[1] == ":"
            ):
                raise DemistoException(
                    f"Refusing to extract absolute path from ZIP: {member_name}"
                )

            dest_path = os.path.realpath(
                os.path.join(target_root, member_name)
            )
            if (
                dest_path != target_root
                and not dest_path.startswith(target_root + os.sep)
            ):
                raise DemistoException(
                    f"Refusing to extract member outside destination "
                    f"(ZipSlip): {member_name}"
                )

            total_uncompressed += info.file_size
            if total_uncompressed > MAX_DOWNLOAD_BYTES:
                raise DemistoException(
                    "Pack ZIP uncompressed size exceeds limit "
                    f"(> {MAX_DOWNLOAD_BYTES} bytes)"
                )

        # Validation passed — safe to extract.
        zf.extractall(target_root)


def _safe_flatten_one_level(pack_path: str) -> None:
    """Flatten ``pack_path/<single_root>/*`` up into ``pack_path/*``.

    Many pack ZIPs ship as ``<packname>/<files>``; this strips the leading
    directory. Every move target is validated to stay inside ``pack_path``.
    """
    pack_root = os.path.realpath(pack_path)
    entries = os.listdir(pack_root)
    if len(entries) != 1:
        return

    inner = os.path.join(pack_root, entries[0])
    if not os.path.isdir(inner):
        return

    inner_real = os.path.realpath(inner)
    if not inner_real.startswith(pack_root + os.sep):
        # Shouldn't happen post-extract, but verify anyway.
        return

    for item in os.listdir(inner_real):
        src = os.path.join(inner_real, item)
        dst = os.path.realpath(os.path.join(pack_root, item))
        if (
            dst != pack_root
            and not dst.startswith(pack_root + os.sep)
        ):
            raise DemistoException(
                f"Refusing to flatten file outside pack root: {item}"
            )
        shutil.move(src, dst)
    Path(inner_real).rmdir()


def _prepare_pack_dir(zip_path: str, filename: str) -> str:
    """Extract ``zip_path`` into ``Packs/<packname>/`` and flatten one level.

    Mirrors the layout demisto-sdk's ``upload_content_entity`` expects.
    Creates ``Tests/Marketplace/landingPage_sections.json`` to suppress SDK
    warnings during upload.
    """
    pack_name = filename[:-4] if filename.endswith(".zip") else filename
    packs_path = os.path.join(os.getcwd(), "Packs")
    pack_path = os.path.join(packs_path, pack_name)
    os.makedirs(pack_path, exist_ok=True)

    if not zipfile.is_zipfile(zip_path):
        raise DemistoException("Downloaded file is not a valid zip.")

    test_path = os.path.join(os.getcwd(), "Tests", "Marketplace")
    os.makedirs(test_path, exist_ok=True)
    landing_page = os.path.join(test_path, "landingPage_sections.json")
    if not os.path.exists(landing_page):
        with open(landing_page, "w") as fh:
            fh.write('{"sections": []}')

    # ZipSlip-hardened extract.
    _safe_extract_zip(zip_path, pack_path)

    # Confirm the pack actually has metadata before we hand it to the SDK.
    if not _has_pack_metadata(pack_path):
        raise DemistoException(
            "Zip missing pack_metadata.json — not a valid pack."
        )

    _safe_flatten_one_level(pack_path)
    return pack_path


def _has_pack_metadata(pack_path: str) -> bool:
    """True if pack_metadata.json is at pack root or one level deep."""
    if os.path.isfile(os.path.join(pack_path, "pack_metadata.json")):
        return True
    for entry in os.listdir(pack_path):
        sub = os.path.join(pack_path, entry)
        if os.path.isdir(sub) and os.path.isfile(
            os.path.join(sub, "pack_metadata.json")
        ):
            return True
    return False


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def test_module(client: ContentClient) -> str:
    """Connectivity test for the integration instance."""
    client.test_connectivity()
    return "ok"


def install_pack_command(
    client: ContentClient, args: dict[str, Any]
) -> CommandResults:
    """Download a pack ZIP from ``url`` and install it as system content.

    The ``url`` argument is declared ``required: true`` in the YAML, so the
    XSOAR engine rejects missing values before this function runs.
    """
    url = (args.get("url") or "").strip()
    filename = (args.get("filename") or "").strip()

    if not filename:
        filename = url.rstrip("/").split("/")[-1]
    # Strip any path components from the filename to prevent the pack name
    # (derived from filename) from escaping Packs/ via "../" segments.
    filename = os.path.basename(filename)
    if not filename or filename in (".", ".."):
        raise DemistoException(
            "filename argument resolves to an empty or unsafe value"
        )
    if not filename.endswith(".zip"):
        filename += ".zip"

    tmp_dir = tempfile.mkdtemp()
    zip_path = os.path.join(tmp_dir, filename)
    try:
        client.stream_download_zip(url, zip_path)
        pack_path = _prepare_pack_dir(zip_path, filename)
        result = client.upload_pack_as_system_content(pack_path)

        return CommandResults(
            outputs_prefix="SOCFramework.PackInstall",
            outputs_key_field="filename",
            outputs={
                "filename": filename,
                "url": url,
                "status": "success",
                "response": result,
            },
            readable_output=f"Pack **{filename}** installed successfully.",
        )
    finally:
        try:
            if os.path.exists(zip_path):
                os.unlink(zip_path)
            if os.path.isdir(tmp_dir):
                shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:  # pragma: no cover - cleanup is best-effort
            pass


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    base_url = (params.get("url") or "").rstrip("/")
    creds = params.get("credentials") or {}
    api_id = str(creds.get("identifier") or "")
    api_key = creds.get("password") or ""
    insecure = argToBoolean(params.get("insecure", False))
    proxy = argToBoolean(params.get("proxy", False))

    client = ContentClient(
        base_url=base_url,
        api_id=api_id,
        api_key=api_key,
        verify=(not insecure),
        proxy=proxy,
    )

    try:
        if command == "test-module":
            return_results(test_module(client))
        elif command == "socfw-install-pack":
            return_results(install_pack_command(client, args))
        else:
            raise NotImplementedError(f"Command not implemented: {command}")
    except Exception as exc:
        return_error(f"{INTEGRATION_NAME}: {exc}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
