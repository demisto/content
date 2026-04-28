"""Browser Use Local — runs the open-source `browser-use` agent inside the
Cortex XSOAR / XSIAM integration container.

Unlike the cloud companion integration, **everything runs in-container**:
- Chromium is launched by Playwright on the integration host.
- The LLM is called with the user's own provider API key (Anthropic, Google,
  OpenAI, or Browser Use Cloud's hosted model).
- Cookies/profiles are not persisted across executions unless the user opts in
  (`use_integration_context=true`), since each XSOAR command runs in a fresh
  container.

The integration is intentionally minimal — three commands plus a `test-module`
— because each invocation is heavy (it spawns Chromium and burns LLM tokens).
For high-throughput automation use the **Browser Use** (cloud) integration in
the same pack.

Required Docker image: `demisto/browser-use:1.0.0.x` (see the local Dockerfile
in this directory). The image must include Chromium + Playwright +
`browser-use` + the LLM client SDKs.
"""

from __future__ import annotations

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401  # pylint: disable=W0614

import asyncio
import json
import os
import tempfile
from typing import Any

import urllib3

urllib3.disable_warnings()

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

INTEGRATION_NAME = "Browser Use Local"
INTEGRATION_CONTEXT = "BrowserUseLocal"

# Mapping from instance-param `llm_provider` to a (factory, default model name).
# We import lazily inside the factory so the integration loads even if a given
# SDK is missing from the docker image — only the factory the user picked needs
# to import successfully.
_PROVIDER_DEFAULTS = {
    "browser-use": "browser-use/bu-30b-a3b-preview",
    "anthropic": "claude-sonnet-4-6",
    "google": "gemini-3-flash-preview",
    "openai": "gpt-4o",
}


# --------------------------------------------------------------------------- #
# LLM factory
# --------------------------------------------------------------------------- #


def _build_llm(provider: str, model: str | None, api_key: str):
    """Construct a `browser-use` chat LLM for the chosen provider.

    Imports are deferred so a missing optional SDK doesn't break the integration
    at module load time — it only fails when the user actually tries to use
    that provider.
    """
    provider = (provider or "browser-use").lower()
    chosen_model = model or _PROVIDER_DEFAULTS.get(provider)
    if not chosen_model:
        raise DemistoException(f"Unsupported llm_provider `{provider}`. Choose one of: "
                               f"{', '.join(_PROVIDER_DEFAULTS)}.")

    if provider == "browser-use":
        from browser_use import ChatBrowserUse  # type: ignore[import-not-found]

        # ChatBrowserUse picks up BROWSER_USE_API_KEY from the env or accepts api_key kw.
        return ChatBrowserUse(model=chosen_model, api_key=api_key) if api_key else ChatBrowserUse(model=chosen_model)

    if provider == "anthropic":
        from browser_use import ChatAnthropic  # type: ignore[import-not-found]
        if api_key:
            os.environ["ANTHROPIC_API_KEY"] = api_key
        return ChatAnthropic(model=chosen_model)

    if provider == "google":
        from browser_use import ChatGoogle  # type: ignore[import-not-found]
        if api_key:
            os.environ["GOOGLE_API_KEY"] = api_key
        return ChatGoogle(model=chosen_model)

    if provider == "openai":
        from browser_use import ChatOpenAI  # type: ignore[import-not-found]
        if api_key:
            os.environ["OPENAI_API_KEY"] = api_key
        return ChatOpenAI(model=chosen_model)

    raise DemistoException(f"Unsupported llm_provider `{provider}`.")


def _build_browser(headless: bool, use_cloud: bool, cloud_api_key: str | None):
    """Construct a `browser_use.Browser`. `use_cloud=True` swaps the local
    Chromium for a Browser Use Cloud stealth browser (still authenticated with a
    `bu_` API key)."""
    from browser_use import Browser  # type: ignore[import-not-found]

    if use_cloud:
        if not cloud_api_key:
            raise DemistoException(
                "use_cloud_browser=true but no Browser Use Cloud API key was provided. "
                "Set the optional 'Browser Use Cloud API Key' instance parameter."
            )
        return Browser(use_cloud=True, api_key=cloud_api_key)

    return Browser(headless=headless)


# --------------------------------------------------------------------------- #
# Async runner
# --------------------------------------------------------------------------- #


async def _run_agent_async(
    *,
    task: str,
    llm: Any,
    browser: Any,
    max_steps: int | None,
    output_schema: dict | None,
) -> dict:
    """Run a single browser-use Agent task and return a structured result dict."""
    from browser_use import Agent  # type: ignore[import-not-found]

    agent_kwargs: dict[str, Any] = {"task": task, "llm": llm, "browser": browser}
    if output_schema:
        # browser-use accepts a Pydantic model OR JSON-Schema dict for structured output
        agent_kwargs["output_model"] = output_schema

    agent = Agent(**agent_kwargs)
    run_kwargs: dict[str, Any] = {}
    if max_steps:
        run_kwargs["max_steps"] = max_steps

    history = await agent.run(**run_kwargs)

    # `history` is a browser-use AgentHistoryList. Normalise into plain dicts
    # because the rest of the integration is sync + JSON-serialised.
    final_output = None
    is_done = False
    success: bool | None = None
    visited_urls: list[str] = []

    if history is not None:
        try:
            final_output = history.final_result()
        except Exception:  # noqa: BLE001
            final_output = None
        try:
            is_done = bool(history.is_done())
        except Exception:  # noqa: BLE001
            is_done = False
        try:
            success = history.is_successful()  # may return None
        except Exception:  # noqa: BLE001
            success = None
        try:
            visited_urls = list(history.urls() or [])
        except Exception:  # noqa: BLE001
            visited_urls = []

    return {
        "FinalOutput": final_output,
        "IsDone": is_done,
        "IsSuccessful": success,
        "VisitedUrls": visited_urls,
    }


def _run_async(coro):
    """Run an async coroutine from a synchronous XSOAR command handler."""
    try:
        return asyncio.run(coro)
    except RuntimeError:
        # Edge case: an event loop may already exist in some XSOAR runtimes.
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()


# --------------------------------------------------------------------------- #
# Command handlers
# --------------------------------------------------------------------------- #


def test_module(params: dict) -> str:
    """Validate the configuration: import browser_use and instantiate the chosen LLM."""
    try:
        import browser_use  # noqa: F401  # type: ignore[import-not-found]
    except ImportError as exc:
        return (
            f"`browser_use` package is not installed in the integration Docker image. "
            f"Use `demisto/browser-use:*` (see the integration Dockerfile). Original error: {exc}"
        )

    provider = (params.get("llm_provider") or "browser-use").lower()
    api_key = (params.get("llm_credentials") or {}).get("password") or params.get("llm_api_key")
    if provider != "browser-use" and not api_key:
        return f"LLM API Key is required when llm_provider is `{provider}`."

    try:
        _build_llm(provider, params.get("default_model"), api_key)
    except Exception as exc:  # noqa: BLE001
        return f"Failed to construct LLM client for provider `{provider}`: {exc}"

    return "ok"


def agent_run_command(params: dict, args: dict) -> CommandResults:
    """Run an open-source browser-use agent task locally."""
    task = args.get("task")
    if not task:
        raise DemistoException("`task` is required.")

    provider = (args.get("llm_provider") or params.get("llm_provider") or "browser-use").lower()
    model = args.get("model") or params.get("default_model")
    api_key = (params.get("llm_credentials") or {}).get("password") or params.get("llm_api_key")

    headless = argToBoolean(args.get("headless") or params.get("default_headless") or "true")
    use_cloud_browser = argToBoolean(
        args.get("use_cloud_browser") or params.get("default_use_cloud_browser") or "false"
    )
    cloud_api_key = (params.get("cloud_credentials") or {}).get("password") or params.get("cloud_api_key")

    max_steps = arg_to_number(args.get("max_steps") or params.get("default_max_steps"))

    output_schema_raw = args.get("output_schema")
    output_schema: dict | None = None
    if output_schema_raw:
        try:
            output_schema = json.loads(output_schema_raw)
        except json.JSONDecodeError as exc:
            raise DemistoException(f"`output_schema` must be valid JSON: {exc}") from exc

    llm = _build_llm(provider, model, api_key)
    browser = _build_browser(headless=headless, use_cloud=use_cloud_browser, cloud_api_key=cloud_api_key)

    result = _run_async(
        _run_agent_async(task=task, llm=llm, browser=browser, max_steps=max_steps, output_schema=output_schema)
    )

    ctx = {
        "Task": task,
        "Provider": provider,
        "Model": model or _PROVIDER_DEFAULTS.get(provider),
        "FinalOutput": result.get("FinalOutput"),
        "IsDone": result.get("IsDone"),
        "IsSuccessful": result.get("IsSuccessful"),
        "VisitedUrls": result.get("VisitedUrls"),
    }
    headers = ["Provider", "Model", "IsDone", "IsSuccessful"]
    md = tableToMarkdown(f"{INTEGRATION_NAME} - Agent run", ctx, headers=headers, removeNull=True)
    if final := ctx.get("FinalOutput"):
        md += f"\n### Final Output\n\n```\n{str(final)[:4000]}\n```"
    if visited := ctx.get("VisitedUrls"):
        md += "\n\n### Visited URLs\n\n" + "\n".join(f"- {u}" for u in visited[:50])

    return CommandResults(
        outputs_prefix=f"{INTEGRATION_CONTEXT}.AgentRun",
        outputs=ctx,
        readable_output=md,
        raw_response=ctx,
    )


def screenshot_command(params: dict, args: dict) -> dict:
    """Take a single screenshot of a URL using a local headless Chromium.

    Returns a War Room file entry with the PNG, so it can be attached to incidents.
    Bypasses the LLM entirely — useful for quick safe URL captures.
    """
    url = args.get("url")
    if not url:
        raise DemistoException("`url` is required.")
    wait_seconds = arg_to_number(args.get("wait_seconds") or 0) or 0
    full_page = argToBoolean(args.get("full_page") or "true")
    headless = argToBoolean(args.get("headless") or params.get("default_headless") or "true")

    return _run_async(_screenshot_async(url=url, wait_seconds=wait_seconds, full_page=full_page, headless=headless))


async def _screenshot_async(*, url: str, wait_seconds: int, full_page: bool, headless: bool) -> dict:
    from playwright.async_api import async_playwright  # type: ignore[import-not-found]

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=headless)
        try:
            page = await browser.new_page()
            await page.goto(url, wait_until="load", timeout=60_000)
            if wait_seconds:
                await asyncio.sleep(wait_seconds)
            with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as fh:
                screenshot_path = fh.name
            await page.screenshot(path=screenshot_path, full_page=full_page)
        finally:
            await browser.close()

    with open(screenshot_path, "rb") as fh:
        data = fh.read()
    return fileResult(filename="browser_use_screenshot.png", data=data, file_type=EntryType.IMAGE)


def version_command() -> CommandResults:
    """Report the installed browser-use library version (useful for support tickets)."""
    try:
        import browser_use  # type: ignore[import-not-found]

        version = getattr(browser_use, "__version__", "unknown")
    except ImportError as exc:
        return CommandResults(readable_output=f"browser-use is not installed: {exc}")

    ctx = {"BrowserUseVersion": version}
    return CommandResults(
        outputs_prefix=f"{INTEGRATION_CONTEXT}.Version",
        outputs=ctx,
        readable_output=f"`browser-use` version: **{version}**",
    )


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    demisto.debug(f"{INTEGRATION_NAME} - Command being called is `{command}`")

    try:
        if command == "test-module":
            return_results(test_module(params))
        elif command == "browser-use-local-agent-run":
            return_results(agent_run_command(params, args))
        elif command == "browser-use-local-screenshot":
            return_results(screenshot_command(params, args))
        elif command == "browser-use-local-version":
            return_results(version_command())
        else:
            raise NotImplementedError(f"Command `{command}` is not implemented in {INTEGRATION_NAME}.")
    except Exception as exc:  # noqa: BLE001
        demisto.error(f"{INTEGRATION_NAME} - failed to execute `{command}`: {exc}")
        return_error(f"Failed to execute {command} command. Error: {exc}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
