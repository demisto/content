
import json
import os
import shutil
import tempfile
import zipfile


INTEGRATION_NAME = "SOCFWPackManager"


def _set_sdk_env(base_url: str, api_key: str, api_id: str):
    """Set env vars required by demisto-sdk upload_content_entity."""
    api_base = base_url.rstrip('/')
    if '://api-' not in api_base:
        api_base = api_base.replace('://', '://api-', 1)
    os.environ["DEMISTO_API_KEY"]  = api_key
    os.environ["XSIAM_AUTH_ID"]    = str(api_id)
    os.environ["DEMISTO_BASE_URL"] = api_base
    os.environ["DEMISTO_SDK_IGNORE_CONTENT_WARNING"] = "1"
    os.environ["DEMISTO_SDK_SKIP_LOGGER_SETUP"] = "yes"
    os.environ["DEMISTO_SDK_OFFLINE_ENV"] = "False"
    os.environ["ARTIFACTS_FOLDER"] = "/tmp/artifacts"
    os.environ["DEMISTO_SDK_LOG_NO_COLORS"] = "true"


def unzip_and_flatten(zip_path: str, filename: str) -> str:
    """
    Extract zip to Packs/<packname>/ and flatten one level of nesting.
    Mirrors unzip_files_to_verify_compression() from POV_XSIAM_Content_Management.
    Creates Tests/Marketplace/landingPage_sections.json to suppress SDK logs.
    """
    pack_name = filename.replace(".zip", "")
    packs_path = os.path.join(os.getcwd(), "Packs")
    pack_path  = os.path.join(packs_path, pack_name)
    os.makedirs(packs_path, exist_ok=True)

    if not zipfile.is_zipfile(zip_path):
        raise Exception("Downloaded file is not a valid zip.")

    test_path = os.path.join(os.getcwd(), "Tests", "Marketplace")
    os.makedirs(test_path, exist_ok=True)
    with open(os.path.join(test_path, "landingPage_sections.json"), "w") as f:
        json.dump({"sections": []}, f)

    with zipfile.ZipFile(zip_path, "r") as zf:
        names = [x.filename for x in zf.infolist()]

    meta_files = [n for n in names if "pack_metadata.json" in n]
    if not meta_files:
        raise Exception("Zip missing pack_metadata.json — not a valid pack.")

    parts = meta_files[0].split("/")
    if len(parts) > 2:
        raise Exception(f"Zip packed too deep: {parts}")

    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(pack_path)

    if len(parts) == 2:
        root_dir = os.path.join(pack_path, parts[0])
        for item in os.listdir(root_dir):
            shutil.move(os.path.join(root_dir, item), os.path.join(pack_path, item))
        os.rmdir(root_dir)

    return pack_path


def post_system_content_bundle(base_url: str, api_key: str, api_id: str,
                                pack_path: str) -> dict:
    """
    Upload pack directory via demisto-sdk upload_content_entity(xsiam=True).
    Mirrors Client.post_system_content_bundle() from POV_XSIAM_Content_Management.
    Requires docker image demisto/xsoar-tools (has demisto-sdk pre-installed).
    """
    _set_sdk_env(base_url, api_key, api_id)

    from demisto_sdk.commands.common.logger import logging_setup
    logging_setup("SOCFWPackManager", console_threshold="CRITICAL", propagate=True)
    from demisto_sdk.commands.upload.upload import upload_content_entity

    try:
        upload_content_entity(input=pack_path, zip=True, xsiam=True, insecure=True)
        return {"success": True, "message": f"Uploaded {pack_path}"}
    except BaseException as e:
        # demisto-sdk raises either SystemExit or its own Exit class on completion.
        # Exit code 0 = success. Anything else is a real failure.
        code = getattr(e, "code", getattr(e, "exit_code", None))
        if code is None:
            raise
        if str(code) not in ("0", "None"):
            raise Exception(f"demisto-sdk upload failed with exit code {code}: {e}")
        return {"success": True, "message": f"Uploaded {pack_path}"}


def command_install_pack(params: dict, args: dict) -> None:
    """
    socfw-install-pack: download zip, extract, upload via demisto-sdk system path.
    Mirrors the XSIAM Starter save_as_system=yes path exactly.
    Credentials come from integration instance params — never exposed.
    """
    base_url = (params.get("url") or "").rstrip("/")
    creds    = params.get("credentials") or {}
    api_id   = str(creds.get("identifier") or "")
    api_key  = creds.get("password") or ""

    url      = (args.get("url") or "").strip()
    filename = (args.get("filename") or "").strip()

    if not url:
        raise ValueError("url argument is required")
    if not filename:
        filename = url.rstrip("/").split("/")[-1]
    if not filename.endswith(".zip"):
        filename += ".zip"

    dl = requests.get(url, timeout=300, verify=False)
    if dl.status_code != 200:
        raise Exception(f"Download failed HTTP {dl.status_code}: {url}")

    tmp_dir  = tempfile.mkdtemp()
    zip_path = os.path.join(tmp_dir, filename)
    try:
        with open(zip_path, "wb") as fh:
            fh.write(dl.content)

        pack_path = unzip_and_flatten(zip_path, filename)

        result = post_system_content_bundle(
            base_url=base_url,
            api_key=api_key,
            api_id=api_id,
            pack_path=pack_path,
        )

        return_results(CommandResults(
            outputs_prefix="SOCFramework.PackInstall",
            outputs={"filename": filename, "url": url, "status": "success", "response": result},
            readable_output=f"Pack **{filename}** installed successfully.",
        ))
    finally:
        if os.path.exists(zip_path):
            os.unlink(zip_path)


def command_test_module(params: dict) -> None:
    base_url = (params.get("url") or "").rstrip("/")
    creds    = params.get("credentials") or {}
    api_id   = str(creds.get("identifier") or "")
    api_key  = creds.get("password") or ""
    verify   = not params.get("insecure", False)

    if not base_url:
        raise Exception("Server URL is required.")
    if not api_key or not api_id:
        raise Exception("API Key and API Key ID are required.")

    # Light check — hit the tenant API keys endpoint
    # public_api endpoints need the api- prefix URL
    api_base = base_url.rstrip('/')
    if '://api-' not in api_base:
        api_base = api_base.replace('://', '://api-', 1)
    url = f"{api_base}/public_api/v1/xql/get_datasets"
    headers = {"x-xdr-auth-id": api_id, "Authorization": api_key}
    resp = requests.post(url, headers=headers, json={"request_data": {}},
                         verify=verify, timeout=15)
    if resp.status_code not in (200, 207):
        raise Exception(f"Connection test failed HTTP {resp.status_code}")
    return_results("ok")


def main():
    params  = demisto.params()
    args    = demisto.args()
    command = demisto.command()

    try:
        if command == "test-module":
            command_test_module(params)
        elif command == "socfw-install-pack":
            command_install_pack(params, args)
        else:
            raise NotImplementedError(f"Command not implemented: {command}")
    except Exception as e:
        return_error(f"{INTEGRATION_NAME}: {e}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
