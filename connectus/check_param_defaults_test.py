"""Tests for ``check_param_defaults`` — the ConnectUs param-default-removal analyzer.

Under ConnectUs, integration parameters no longer arrive with type-based
defaults injected by the framework (an unchecked checkbox used to arrive as
``False``, an empty numeric field as ``0``; now they arrive absent / ``None``
/ ``""``). Code that converts a *defaultless* param read with
``argToBoolean`` / ``arg_to_number`` / ``int`` / ``float`` / ``bool`` will
therefore raise at runtime.

The analyzer classifies every param read into three buckets:

* **UNSAFE** — a provable break (defaultless converter on a literal param).
* **UNCERTAIN** — a static-analysis blind spot ("params still to be checked
  by AI"): cross-function value flow, dynamic/non-literal access, custom
  wrappers, silent ``0``/``False`` reliance, YML ambiguity.
* **SAFE** — provably fine (``params.get("x", False)`` / ``... or <default>``).

These tests drive the implementation (TDD): they assert the public API
(:func:`analyze_source`, :func:`analyze_integration`), the three-bucket
classification, the JSON-verdict shape, the exit-code contract, the ignore
mechanism, and the non-Python short-circuit.
"""
from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

import check_param_defaults as cpd

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _src(code: str) -> str:
    """Dedent a triple-quoted snippet so AST line numbers stay sane."""
    return textwrap.dedent(code).lstrip("\n")


def _params(verdict: dict, bucket: str) -> set[str]:
    """Collect the ``param`` names recorded in a verdict bucket."""
    return {entry["param"] for entry in verdict[bucket]}


def _write_integration(
    tmp_path: Path,
    name: str,
    *,
    py: str | None = None,
    js: str | None = None,
    ps1: str | None = None,
    yml: str | None = None,
) -> Path:
    """Materialize a fake integration dir and return its path."""
    d = tmp_path / name
    d.mkdir()
    if py is not None:
        (d / f"{name}.py").write_text(_src(py))
    if js is not None:
        (d / f"{name}.js").write_text(_src(js))
    if ps1 is not None:
        (d / f"{name}.ps1").write_text(_src(ps1))
    if yml is not None:
        (d / f"{name}.yml").write_text(_src(yml))
    return d


# --------------------------------------------------------------------------
# Verdict shape / contract
# --------------------------------------------------------------------------


class TestVerdictShape:
    def test_envelope_keys(self):
        verdict = cpd.analyze_source("x = 1\n", filename="X.py")
        assert set(verdict) >= {
            "integration",
            "pass",
            "unsafe",
            "uncertain",
            "safe_count",
        }
        assert isinstance(verdict["unsafe"], list)
        assert isinstance(verdict["uncertain"], list)
        assert isinstance(verdict["safe_count"], int)

    def test_clean_source_passes(self):
        verdict = cpd.analyze_source("x = 1 + 2\n", filename="X.py")
        assert verdict["pass"] is True
        assert verdict["unsafe"] == []
        assert verdict["uncertain"] == []

    def test_pass_is_false_when_unsafe(self):
        code = """
        params = demisto.params()
        flag = argToBoolean(params.get("trust_any_certificate"))
        """
        verdict = cpd.analyze_source(_src(code), filename="X.py")
        assert verdict["pass"] is False

    def test_pass_is_false_when_uncertain(self):
        # Non-literal access -> cannot bind a name -> uncertain.
        code = """
        params = demisto.params()
        for key in keys:
            value = argToBoolean(params.get(key))
        """
        verdict = cpd.analyze_source(_src(code), filename="X.py")
        assert verdict["pass"] is False
        assert verdict["uncertain"]

    def test_unsafe_entry_fields(self):
        code = """
        params = demisto.params()
        flag = argToBoolean(params.get("verify"))
        """
        verdict = cpd.analyze_source(_src(code), filename="X.py")
        entry = verdict["unsafe"][0]
        assert set(entry) >= {"param", "site", "reason"}
        assert entry["param"] == "verify"
        # site is "file:line"
        assert ":" in entry["site"]
        assert entry["site"].startswith("X.py:")


# --------------------------------------------------------------------------
# UNSAFE — Tier 1: inline defaultless converters (the loud class)
# --------------------------------------------------------------------------


class TestUnsafeInline:
    @pytest.mark.parametrize("converter", ["argToBoolean", "arg_to_bool_or_none"])
    def test_bool_converter_on_defaultless_get(self, converter):
        code = f"""
        params = demisto.params()
        v = {converter}(params.get("insecure"))
        """
        verdict = cpd.analyze_source(_src(code), filename="X.py")
        assert "insecure" in _params(verdict, "unsafe")

    @pytest.mark.parametrize("converter", ["arg_to_number", "int", "float"])
    def test_number_converter_on_defaultless_get(self, converter):
        code = f"""
        params = demisto.params()
        n = {converter}(params.get("max_fetch"))
        """
        verdict = cpd.analyze_source(_src(code), filename="X.py")
        assert "max_fetch" in _params(verdict, "unsafe")

    def test_converter_on_subscript_access(self):
        code = """
        params = demisto.params()
        n = int(params["limit"])
        """
        verdict = cpd.analyze_source(_src(code), filename="X.py")
        assert "limit" in _params(verdict, "unsafe")

    def test_converter_on_demisto_params_inline(self):
        code = """
        flag = argToBoolean(demisto.params().get("proxy"))
        """
        verdict = cpd.analyze_source(_src(code), filename="X.py")
        assert "proxy" in _params(verdict, "unsafe")


# --------------------------------------------------------------------------
# SAFE — the dominant real-world pattern must NOT be flagged
# --------------------------------------------------------------------------


class TestSafePatterns:
    def test_get_with_default_is_safe(self):
        code = """
        params = demisto.params()
        flag = argToBoolean(params.get("insecure", False))
        """
        verdict = cpd.analyze_source(_src(code), filename="X.py")
        assert "insecure" not in _params(verdict, "unsafe")
        assert "insecure" not in _params(verdict, "uncertain")
        assert verdict["safe_count"] >= 1

    def test_get_or_default_is_safe(self):
        code = """
        params = demisto.params()
        n = int(params.get("limit") or 50)
        """
        verdict = cpd.analyze_source(_src(code), filename="X.py")
        assert "limit" not in _params(verdict, "unsafe")
        assert verdict["safe_count"] >= 1

    def test_plain_get_without_converter_is_safe(self):
        # A bare read with no converter and no risky use is not a loud break.
        code = """
        params = demisto.params()
        url = params.get("url")
        """
        verdict = cpd.analyze_source(_src(code), filename="X.py")
        assert "url" not in _params(verdict, "unsafe")

    def test_subscript_with_default_via_or_is_safe(self):
        code = """
        params = demisto.params()
        n = int(params.get("limit", 0) or 0)
        """
        verdict = cpd.analyze_source(_src(code), filename="X.py")
        assert "limit" not in _params(verdict, "unsafe")


# --------------------------------------------------------------------------
# Def-use — value stored in a local var first (single-function pass)
# --------------------------------------------------------------------------


class TestDefUse:
    def test_local_var_then_convert_is_unsafe(self):
        code = """
        def main():
            params = demisto.params()
            raw = params.get("max_fetch")
            n = int(raw)
        """
        verdict = cpd.analyze_source(_src(code), filename="X.py")
        assert "max_fetch" in _params(verdict, "unsafe")

    def test_local_var_with_default_then_convert_is_safe(self):
        code = """
        def main():
            params = demisto.params()
            raw = params.get("max_fetch", 10)
            n = int(raw)
        """
        verdict = cpd.analyze_source(_src(code), filename="X.py")
        assert "max_fetch" not in _params(verdict, "unsafe")

    def test_value_crossing_function_is_uncertain(self):
        # The converted value flows out of the reading function into a
        # helper -> interprocedural -> the analyzer must surface it as
        # uncertain rather than silently pass.
        code = """
        def main():
            params = demisto.params()
            flag = params.get("verify")
            client = build_client(flag)

        def build_client(flag):
            return argToBoolean(flag)
        """
        verdict = cpd.analyze_source(_src(code), filename="X.py")
        # 'verify' is read defaultless and handed across a call boundary.
        assert "verify" in (
            _params(verdict, "uncertain") | _params(verdict, "unsafe")
        )


# --------------------------------------------------------------------------
# UNCERTAIN — blind spots surfaced by name (not silently passed)
# --------------------------------------------------------------------------


class TestUncertain:
    def test_dynamic_key_access_is_uncertain(self):
        code = """
        params = demisto.params()
        for key in ("a", "b"):
            v = argToBoolean(params.get(key))
        """
        verdict = cpd.analyze_source(_src(code), filename="X.py")
        assert verdict["uncertain"]
        # The reason should name it as a dynamic/non-literal access blind spot.
        reasons = " ".join(e["reason"].lower() for e in verdict["uncertain"])
        assert "dynamic" in reasons or "non-literal" in reasons

    def test_params_splat_is_uncertain(self):
        code = """
        params = demisto.params()
        client = Client(**params)
        """
        verdict = cpd.analyze_source(_src(code), filename="X.py")
        reasons = " ".join(e["reason"].lower() for e in verdict["uncertain"])
        assert "splat" in reasons or "**params" in reasons or "spread" in reasons

    def test_command_args_get_is_not_flagged(self):
        # ``args.get("x")`` / ``demisto.args().get("x")`` are COMMAND
        # arguments, not configuration params. They are always supplied at
        # call time and are out of scope for the param-default-removal change.
        code = """
        args = demisto.args()
        flag = argToBoolean(args.get("use_domain_admin_access"))
        n = int(demisto.args().get("limit"))
        """
        verdict = cpd.analyze_source(_src(code), filename="X.py")
        assert verdict["unsafe"] == []
        assert verdict["uncertain"] == []

    def test_custom_wrapper_read_is_uncertain(self):
        # A read through a custom wrapper hides the call shape -> uncertain.
        code = """
        n = arg_to_number(get_param("limit"))
        """
        verdict = cpd.analyze_source(_src(code), filename="X.py")
        # Either flagged unsafe (wrapper returns the raw param) is too strong;
        # the honest answer is uncertain because get_param's body is unknown.
        assert "limit" in _params(verdict, "uncertain") or verdict["uncertain"]


# --------------------------------------------------------------------------
# Ignore mechanism
# --------------------------------------------------------------------------


class TestIgnore:
    def test_inline_noqa_suppresses_unsafe(self):
        code = """
        params = demisto.params()
        flag = argToBoolean(params.get("insecure"))  # noqa: ucp-param-default
        """
        verdict = cpd.analyze_source(_src(code), filename="X.py")
        assert "insecure" not in _params(verdict, "unsafe")

    def test_ignored_param_list_suppresses_unsafe(self):
        code = """
        params = demisto.params()
        flag = argToBoolean(params.get("insecure"))
        """
        verdict = cpd.analyze_source(
            _src(code), filename="X.py", ignore_params={"insecure"}
        )
        assert "insecure" not in _params(verdict, "unsafe")
        assert "insecure" not in _params(verdict, "uncertain")

    def test_noqa_on_unrelated_line_does_not_suppress(self):
        code = """
        params = demisto.params()
        flag = argToBoolean(params.get("insecure"))
        other = 1  # noqa: ucp-param-default
        """
        verdict = cpd.analyze_source(_src(code), filename="X.py")
        assert "insecure" in _params(verdict, "unsafe")


# --------------------------------------------------------------------------
# Tier 2 — YML-aware enrichment
# --------------------------------------------------------------------------


class TestYmlAware:
    def test_checkbox_read_in_truthy_context_is_safe(self, tmp_path):
        # A checkbox param read bare and consumed only in a TRUTHY context
        # (an `if` test) behaves identically whether the value is the old
        # injected ``False`` or the new absent ``None`` — both are falsey.
        # This must NOT be flagged (user decision 2026-06-07).
        d = _write_integration(
            tmp_path,
            "MyInt",
            py="""
            def main():
                params = demisto.params()
                if params.get("fetch_incidents"):
                    do_fetch()
            """,
            yml="""
            name: MyInt
            configuration:
            - name: fetch_incidents
              type: 8
              defaultvalue: "false"
            script:
              type: python
            """,
        )
        verdict = cpd.analyze_integration(d)
        assert "fetch_incidents" not in _params(verdict, "uncertain")
        assert "fetch_incidents" not in _params(verdict, "unsafe")

    def test_checkbox_read_compared_to_false_is_uncertain(self, tmp_path):
        # When the old ``False`` mattered semantically — e.g. an explicit
        # ``== False`` / ``is False`` comparison — switching to ``None``
        # changes behavior. Surface it for AI review.
        d = _write_integration(
            tmp_path,
            "MyInt",
            py="""
            def main():
                params = demisto.params()
                if params.get("fetch_incidents") == False:
                    skip()
            """,
            yml="""
            name: MyInt
            configuration:
            - name: fetch_incidents
              type: 8
              defaultvalue: "false"
            script:
              type: python
            """,
        )
        verdict = cpd.analyze_integration(d)
        assert "fetch_incidents" in _params(verdict, "uncertain")

    def test_checkbox_read_escaping_to_assignment_is_uncertain(self, tmp_path):
        # A checkbox read stored/returned (escaping any boolean context) may
        # be consumed somewhere the None-vs-False distinction matters.
        d = _write_integration(
            tmp_path,
            "MyInt",
            py="""
            def main():
                params = demisto.params()
                flag = params.get("fetch_incidents")
                return build(flag)
            """,
            yml="""
            name: MyInt
            configuration:
            - name: fetch_incidents
              type: 8
              defaultvalue: "false"
            script:
              type: python
            """,
        )
        verdict = cpd.analyze_integration(d)
        assert "fetch_incidents" in _params(verdict, "uncertain")

    def test_yml_param_with_string_type_bare_read_is_safe(self, tmp_path):
        d = _write_integration(
            tmp_path,
            "MyInt",
            py="""
            def main():
                params = demisto.params()
                url = params.get("server_url")
            """,
            yml="""
            name: MyInt
            configuration:
            - name: server_url
              type: 0
            script:
              type: python
            """,
        )
        verdict = cpd.analyze_integration(d)
        assert "server_url" not in _params(verdict, "uncertain")
        assert "server_url" not in _params(verdict, "unsafe")


# --------------------------------------------------------------------------
# analyze_integration — directory-level + non-Python short-circuit
# --------------------------------------------------------------------------


class TestAnalyzeIntegration:
    def test_python_integration_flags_unsafe(self, tmp_path):
        d = _write_integration(
            tmp_path,
            "MyInt",
            py="""
            def main():
                params = demisto.params()
                n = int(params.get("limit"))
            """,
            yml="""
            name: MyInt
            configuration:
            - name: limit
              type: 0
            script:
              type: python
            """,
        )
        verdict = cpd.analyze_integration(d)
        assert "limit" in _params(verdict, "unsafe")
        assert verdict["integration"] == "MyInt"

    def test_javascript_short_circuits(self, tmp_path):
        d = _write_integration(
            tmp_path,
            "JsInt",
            js="""
            var insecure = params.insecure;
            sendRequest(url, insecure);
            """,
            yml="""
            name: JsInt
            script:
              type: javascript
            """,
        )
        verdict = cpd.analyze_integration(d)
        assert verdict["pass"] is True
        assert verdict["unsafe"] == []
        assert verdict["uncertain"] == []
        assert "non-python" in verdict.get("note", "").lower()

    def test_powershell_short_circuits(self, tmp_path):
        d = _write_integration(
            tmp_path,
            "PsInt",
            ps1="""
            $insecure = ConvertTo-Boolean $params.insecure
            """,
            yml="""
            name: PsInt
            script:
              type: powershell
            """,
        )
        verdict = cpd.analyze_integration(d)
        assert verdict["pass"] is True
        assert "non-python" in verdict.get("note", "").lower()


# --------------------------------------------------------------------------
# CLI — exit codes + JSON on stdout
# --------------------------------------------------------------------------


class TestCli:
    SCRIPT = str(Path(__file__).resolve().parent / "check_param_defaults.py")

    def _run(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, self.SCRIPT, *args],
            capture_output=True,
            text=True,
        )

    def test_exit_zero_on_clean(self, tmp_path):
        d = _write_integration(
            tmp_path,
            "Clean",
            py="""
            def main():
                params = demisto.params()
                flag = argToBoolean(params.get("insecure", False))
            """,
            yml="""
            name: Clean
            configuration:
            - name: insecure
              type: 8
            script:
              type: python
            """,
        )
        proc = self._run(str(d))
        assert proc.returncode == 0, proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["pass"] is True

    def test_exit_one_on_unsafe(self, tmp_path):
        d = _write_integration(
            tmp_path,
            "Broken",
            py="""
            def main():
                params = demisto.params()
                n = int(params.get("limit"))
            """,
            yml="""
            name: Broken
            configuration:
            - name: limit
              type: 0
            script:
              type: python
            """,
        )
        proc = self._run(str(d))
        assert proc.returncode == 1
        payload = json.loads(proc.stdout)
        assert "limit" in {e["param"] for e in payload["unsafe"]}
