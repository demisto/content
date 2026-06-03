"""Unit tests for ``connectus/check_command_params.py``.

Coverage map (mirrors the bug log we fixed during the CrowdStrikeFalcon
verification pass):

* **B1** — module-level ``PARAMS = demisto.params()`` reads contribute to
  Scope-1 (``test_b1_*``).
* **B2** — chained ``demisto.params().get(...)`` is recognized inside a
  handler (``test_b2_*``). The dedicated ``test_isfetch_regression``
  case locks in the exact CrowdStrikeFalcon ``module_test`` shape that
  motivated the fix.
* **B3** — ``DockerConfig.resolve_image_for`` honors the YML's
  ``script.dockerimage`` only when ``--use-integration-docker`` was
  passed (``test_b3_*``); ``_parse_args`` wires the flag.
* **B4** — ``analyze_static`` emits per-command breadcrumbs to stderr
  (``test_b4_*``).
* **Bonus 1** — chained ``demisto.command() == "X"`` dispatch is
  recognized (``test_chained_command_dispatch``).
* **Bonus 2** — ``collect_module_level_params`` does NOT descend into
  helper-function bodies (``test_module_level_walk_skips_function_bodies``,
  ``test_close_incident_regression``).

The dynamic-flow tests deliberately avoid spinning up a real proxy or
Docker — ``analyze_dynamic_for_command`` is too coupled to the runtime
to test directly without I/O. We instead test every pure helper that
sits on the dynamic decision path: param-value generation, sentinel
detection, stderr classifiers, the merge function with all of its
narrowing branches, and the diagnostic-to-dict shape.

Run with:

    pytest connectus/check_command_params_test.py -v
"""

from __future__ import annotations

import ast
import textwrap
from pathlib import Path
from unittest import mock
from unittest.mock import MagicMock, patch

import pytest

from connectus import check_command_params as ccp


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def isfetch_source() -> str:
    """Minimal repro of CrowdStrikeFalcon's ``module_test`` + chained dispatch.

    The full file is ~9700 lines; this captures the two patterns that
    every previous bug touched:

    * a module-level ``PARAMS = demisto.params()`` global;
    * a handler that reads ``demisto.params().get("isFetch")`` inline
      (no local ``params`` binding); and
    * a dispatch that uses the chained ``demisto.command()`` form.
    """
    return textwrap.dedent(
        '''
        """Test integration."""
        import demistomock as demisto
        from CommonServerPython import *

        PARAMS = demisto.params()
        SERVER = PARAMS.get("server_url")  # module-level read

        def helper_with_internal_param():
            # This MUST NOT leak into module scope. close_incident is
            # consumed by a helper, not at import time, so it cannot
            # apply to every command.
            return demisto.params().get("close_incident")

        def module_test():
            try:
                if demisto.params().get("isFetch"):
                    pass
            except Exception:
                pass

        def search_device_command():
            return None

        def main():
            command = demisto.command()
            if command == "test-module":
                module_test()
            elif demisto.command() == "cs-falcon-search-device":
                search_device_command()
        '''
    ).lstrip()


@pytest.fixture
def isfetch_tree(isfetch_source: str) -> ast.Module:
    return ast.parse(isfetch_source)


@pytest.fixture
def integration_yml_with_image(tmp_path: Path) -> dict:
    """Mock YML data with a ``script.dockerimage`` declared."""
    return {
        "script": {
            "dockerimage": "demisto/python3:3.11.10.123456",
            "type": "python",
        }
    }


# =============================================================================
# B2 — chained demisto.params() recognition
# =============================================================================


class TestB2ChainedParamsCall:
    """``demisto.params().get/[]/.X`` must be recognized just like ``params.x``."""

    def test_is_demisto_params_call_matches_bare_call(self) -> None:
        node = ast.parse("demisto.params()", mode="eval").body
        assert ccp._is_demisto_params_call(node) is True

    def test_is_demisto_params_call_rejects_args(self) -> None:
        node = ast.parse("demisto.params(foo)", mode="eval").body
        # demisto.params() takes no args; with args it's not the canonical form.
        assert ccp._is_demisto_params_call(node) is False

    def test_is_demisto_params_call_rejects_other_namespace(self) -> None:
        node = ast.parse("not_demisto.params()", mode="eval").body
        assert ccp._is_demisto_params_call(node) is False

    def test_is_demisto_params_call_rejects_other_method(self) -> None:
        node = ast.parse("demisto.args()", mode="eval").body
        assert ccp._is_demisto_params_call(node) is False

    def test_visitor_picks_up_chained_get(self) -> None:
        tree = ast.parse('x = demisto.params().get("foo")')
        v = ccp._ParamAccessVisitor(set(), {})
        v.visit(tree)
        assert v.found == {"foo"}

    def test_visitor_picks_up_chained_subscript(self) -> None:
        tree = ast.parse('x = demisto.params()["bar"]')
        v = ccp._ParamAccessVisitor(set(), {})
        v.visit(tree)
        assert v.found == {"bar"}

    def test_visitor_skips_method_attrs(self) -> None:
        # ``demisto.params().get`` is the *function*, not a param read.
        tree = ast.parse("getter = demisto.params().get")
        v = ccp._ParamAccessVisitor(set(), {})
        v.visit(tree)
        assert v.found == set()


# =============================================================================
# B1 — module-level PARAMS globals fed into Scope-1
# =============================================================================


class TestB1ModuleLevelParamsVars:
    def test_finds_simple_global_assignment(self) -> None:
        tree = ast.parse("PARAMS = demisto.params()")
        assert ccp.find_module_level_params_vars(tree) == {"PARAMS"}

    def test_finds_annotated_global(self) -> None:
        tree = ast.parse("PARAMS: dict = demisto.params()")
        assert ccp.find_module_level_params_vars(tree) == {"PARAMS"}

    def test_finds_multiple_globals(self) -> None:
        tree = ast.parse(
            "FOO = demisto.params()\nBAR = demisto.params()"
        )
        assert ccp.find_module_level_params_vars(tree) == {"FOO", "BAR"}

    def test_ignores_function_local_assignment(self) -> None:
        tree = ast.parse(
            "def main():\n    params = demisto.params()\n"
        )
        # The walker only looks at direct module children — `params`
        # inside main() is NOT a module-level global.
        assert ccp.find_module_level_params_vars(tree) == set()

    def test_ignores_non_demisto_assignments(self) -> None:
        tree = ast.parse("PARAMS = {'a': 1}\nOTHER = some_function()")
        assert ccp.find_module_level_params_vars(tree) == set()

    def test_collect_module_level_params_picks_up_global_reads(
        self, isfetch_tree: ast.Module
    ) -> None:
        params_vars = ccp.find_module_level_params_vars(isfetch_tree)
        func_map = ccp.build_function_map(isfetch_tree)
        main_fn = func_map["main"]
        found = ccp.collect_module_level_params(
            isfetch_tree, main_fn, params_vars, {}
        )
        # ``SERVER = PARAMS.get("server_url")`` runs at import time.
        assert "server_url" in found


# =============================================================================
# Bonus 2 — module-level walk MUST NOT descend into helper bodies
# =============================================================================


class TestModuleLevelWalkScope:
    """The bug: ``ast.walk(tree)`` descended into every helper, fanning
    helper-only param reads (e.g. ``close_incident``) out to every
    command. The fix: ``_walk_module_scope`` skips
    FunctionDef/AsyncFunctionDef/ClassDef bodies.
    """

    def test_module_level_walk_skips_function_bodies(self) -> None:
        src = textwrap.dedent(
            """
            PARAMS = demisto.params()
            EAGER = PARAMS.get("eager_only")  # module scope; should match

            def helper():
                # Only runs when called, NOT at import.
                _ = PARAMS.get("helper_only")
            """
        )
        tree = ast.parse(src)
        params_vars = ccp.find_module_level_params_vars(tree)
        found = ccp.collect_module_level_params(tree, None, params_vars, {})
        assert "eager_only" in found
        assert "helper_only" not in found

    def test_module_level_walk_skips_class_bodies(self) -> None:
        src = textwrap.dedent(
            """
            PARAMS = demisto.params()

            class Holder:
                # Method bodies are not module-level either, even though
                # the class statement itself runs at import.
                def go(self):
                    _ = PARAMS.get("class_method_only")
            """
        )
        tree = ast.parse(src)
        params_vars = ccp.find_module_level_params_vars(tree)
        found = ccp.collect_module_level_params(tree, None, params_vars, {})
        assert "class_method_only" not in found

    def test_module_level_walk_descends_into_if_main_guard(self) -> None:
        # The classic ``if __name__ in ('__main__', 'builtins'): main()``
        # guard at the bottom — non-function statements inside the body
        # ARE module-level.
        src = textwrap.dedent(
            """
            PARAMS = demisto.params()

            if __name__ in ("__main__", "builtins"):
                EAGER_INSIDE_GUARD = PARAMS.get("guarded_global")
            """
        )
        tree = ast.parse(src)
        params_vars = ccp.find_module_level_params_vars(tree)
        found = ccp.collect_module_level_params(tree, None, params_vars, {})
        assert "guarded_global" in found

    def test_module_level_walk_descends_into_try_blocks(self) -> None:
        src = textwrap.dedent(
            """
            PARAMS = demisto.params()
            try:
                EAGER = PARAMS.get("try_global")
            except Exception:
                FALLBACK = PARAMS.get("except_global")
            """
        )
        tree = ast.parse(src)
        params_vars = ccp.find_module_level_params_vars(tree)
        found = ccp.collect_module_level_params(tree, None, params_vars, {})
        assert "try_global" in found
        assert "except_global" in found

    def test_close_incident_regression(self, isfetch_source: str) -> None:
        """Regression test for the false-positive close_incident bug.

        Before the fix, ``close_incident`` (read inside ``helper_with_internal_param``)
        was returned by ``collect_module_level_params`` and fanned out to
        every command. After the fix it must NOT be in the module-level set.
        """
        scope_1, scope_2 = ccp.analyze_static(
            isfetch_source, "cs-falcon-search-device", verbose=False
        )
        assert "close_incident" not in scope_1, (
            "close_incident is read by a helper, NOT at module scope; "
            "it must not be fanned out to commands like search-device "
            "that never reach that helper."
        )
        # Sanity: the legit module-level read IS still captured.
        assert "server_url" in scope_1


# =============================================================================
# B2 + Bonus 1 — the user's "isFetch" case end-to-end
# =============================================================================


class TestIsFetchRegression:
    """User-requested regression test: ``isFetch`` must surface for
    ``test-module`` even when the integration uses chained
    ``demisto.params().get("isFetch")`` and chained ``demisto.command()``
    dispatch.
    """

    def test_isfetch_attributed_to_test_module(
        self, isfetch_source: str
    ) -> None:
        scope_1, scope_2 = ccp.analyze_static(
            isfetch_source, "test-module", verbose=False
        )
        all_static = scope_1 | scope_2
        assert "isFetch" in all_static, (
            f"isFetch must surface for test-module via Scope-2 tracing of "
            f"the chained demisto.params().get('isFetch'). "
            f"scope_1={sorted(scope_1)}, scope_2={sorted(scope_2)}"
        )

    def test_isfetch_only_in_scope_2_for_handler_command(
        self, isfetch_source: str
    ) -> None:
        # isFetch is read only inside module_test() (the test-module
        # handler), so it is per-command Scope-2, NOT module-level Scope-1.
        scope_1, scope_2 = ccp.analyze_static(
            isfetch_source, "test-module", verbose=False
        )
        assert "isFetch" in scope_2
        assert "isFetch" not in scope_1

    def test_other_command_does_not_get_isfetch(
        self, isfetch_source: str
    ) -> None:
        # cs-falcon-search-device's handler does NOT read isFetch, so it
        # must not appear there.
        scope_1, scope_2 = ccp.analyze_static(
            isfetch_source, "cs-falcon-search-device", verbose=False
        )
        all_static = scope_1 | scope_2
        assert "isFetch" not in all_static


# =============================================================================
# Bonus 1 — chained demisto.command() dispatch
# =============================================================================


class TestChainedCommandDispatch:
    def test_is_command_ref_recognizes_bare_name(self) -> None:
        node = ast.parse("command", mode="eval").body
        assert ccp._is_command_ref(node) is True

    def test_is_command_ref_recognizes_chained_call(self) -> None:
        node = ast.parse("demisto.command()", mode="eval").body
        assert ccp._is_command_ref(node) is True

    def test_is_command_ref_rejects_other_attr(self) -> None:
        node = ast.parse("demisto.args()", mode="eval").body
        assert ccp._is_command_ref(node) is False

    def test_is_command_ref_rejects_call_with_args(self) -> None:
        node = ast.parse("demisto.command(extra)", mode="eval").body
        assert ccp._is_command_ref(node) is False

    def test_chained_dispatch_resolves_handler(self, isfetch_source: str) -> None:
        # The crucial integration-level check: even though the
        # search-device branch uses ``elif demisto.command() == "X":``,
        # the static analyzer MUST find the handler call.
        tree = ast.parse(isfetch_source)
        func_map = ccp.build_function_map(tree)
        main_fn = func_map["main"]
        calls = ccp.find_command_handler_calls(main_fn, "cs-falcon-search-device")
        assert calls, (
            "find_command_handler_calls failed to recognize "
            "'elif demisto.command() == \"X\":' as a dispatch site"
        )

    def test_if_test_matches_command_handles_both_forms(self) -> None:
        # if command == "X":
        bare = ast.parse('command == "X"', mode="eval").body
        assert ccp._if_test_matches_command(bare, "X") is True
        # if demisto.command() == "X":
        chained = ast.parse('demisto.command() == "X"', mode="eval").body
        assert ccp._if_test_matches_command(chained, "X") is True
        # Reversed form: "X" == command
        reversed_form = ast.parse('"X" == demisto.command()', mode="eval").body
        assert ccp._if_test_matches_command(reversed_form, "X") is True


# =============================================================================
# Pre-existing static behaviour: regression coverage
# =============================================================================


class TestPydanticAliases:
    def test_extracts_field_alias(self) -> None:
        src = textwrap.dedent(
            """
            class P:
                foo: str = Field(alias="real_foo")
                bar: str = "no alias"
            """
        )
        tree = ast.parse(src)
        assert ccp.find_pydantic_aliases(tree) == {"foo": "real_foo"}

    def test_visitor_resolves_alias_on_attribute_access(self) -> None:
        # params.foo  with alias foo -> real_foo  =>  found contains "real_foo"
        tree = ast.parse("x = params.foo")
        v = ccp._ParamAccessVisitor({"params"}, {"foo": "real_foo"})
        v.visit(tree)
        assert v.found == {"real_foo"}


class TestDispatchVariants:
    def test_match_case_dispatch(self) -> None:
        src = textwrap.dedent(
            """
            def handler_a(): pass
            def handler_b(): pass
            def main():
                command = demisto.command()
                match command:
                    case "a":
                        handler_a()
                    case "b":
                        handler_b()
            """
        )
        tree = ast.parse(src)
        main_fn = ccp.build_function_map(tree)["main"]
        assert ccp.find_command_handler_calls(main_fn, "a")
        assert ccp.find_command_handler_calls(main_fn, "b")
        assert not ccp.find_command_handler_calls(main_fn, "c")

    def test_dict_dispatch(self) -> None:
        src = textwrap.dedent(
            """
            def h_x(): pass
            def main():
                command = demisto.command()
                commands = {"x": h_x}
                commands[command]()
            """
        )
        tree = ast.parse(src)
        main_fn = ccp.build_function_map(tree)["main"]
        calls = ccp.find_command_handler_calls(main_fn, "x")
        assert calls

    def test_in_tuple_dispatch(self) -> None:
        src = textwrap.dedent(
            """
            def h(): pass
            def main():
                command = demisto.command()
                if command in ("a", "b", "c"):
                    h()
            """
        )
        tree = ast.parse(src)
        main_fn = ccp.build_function_map(tree)["main"]
        assert ccp.find_command_handler_calls(main_fn, "b")


class TestPreDispatchScope:
    def test_pre_dispatch_collects_only_unbound_reads(self) -> None:
        # Phase 3 contract: ``collect_pre_dispatch_params`` returns ONLY
        # *unbound* reads — those that are not part of a
        # ``<Name> = RHS`` binding statement and not after the dispatch
        # line. Binding-statement reads are tracked separately by
        # ``build_binding_maps`` and attributed per-command at the
        # dispatch site.
        src = textwrap.dedent(
            """
            def main():
                params = demisto.params()
                # Unbound expression statement — fans out (Scope-1).
                Client(params.get("url"), params.get("api_key"))
                # Binding statement — tracked by binding map, NOT in Scope-1.
                bound = params.get("bound_param")
                command = demisto.command()
                if command == "x":
                    handler(params.get("after_dispatch"))
            """
        )
        tree = ast.parse(src)
        main_fn = ccp.build_function_map(tree)["main"]
        line = ccp.find_command_dispatch_line(main_fn)
        found = ccp.collect_pre_dispatch_params(
            main_fn, {"params"}, {}, line
        )
        # Unbound reads from the bare ``Client(...)`` expression statement
        # remain in Scope-1 (legitimate fan-out for Case-4-style patterns).
        assert "url" in found
        assert "api_key" in found
        # Binding-statement reads are NOT in Scope-1 anymore — they live
        # in ``build_binding_maps`` so they only attach to commands that
        # actually consume the bound local at dispatch time.
        assert "bound_param" not in found
        # Reads after the dispatch line are out of scope for this collector.
        assert "after_dispatch" not in found

    def test_build_binding_maps_captures_direct_and_transitive(self) -> None:
        src = textwrap.dedent(
            """
            def main():
                params = demisto.params()
                api_key = params.get("apikey")
                client = Client(api_key=api_key)
                # Demisto args, no params reads — empty entry but recorded.
                args = demisto.args()
                command = demisto.command()
                if command == "x":
                    handler(client, args)
            """
        )
        tree = ast.parse(src)
        main_fn = ccp.build_function_map(tree)["main"]
        line = ccp.find_command_dispatch_line(main_fn)
        bmap = ccp.build_binding_maps(main_fn, {"params"}, {}, line)
        assert bmap.get("api_key") == {"apikey"}
        # ``client`` carries ``apikey`` transitively via the ``api_key``
        # name reference inside the Client(...) constructor.
        assert bmap.get("client") == {"apikey"}
        # ``args`` is recorded with an empty set (no params reads).
        assert bmap.get("args") == set()
        # ``params = demisto.params()`` is intentionally NOT recorded —
        # it is a params-var, not a binding.
        assert "params" not in bmap


# =============================================================================
# B3 — DockerConfig.resolve_image_for & flag plumbing
# =============================================================================


class TestB3DockerImageResolution:
    def test_default_returns_pinned_image_when_flag_off(self) -> None:
        cfg = ccp.DockerConfig(
            default_image="demisto/py3-native:1.0",
            use_integration_docker=False,
        )
        yml = {"script": {"dockerimage": "demisto/python3:3.11"}}
        assert cfg.resolve_image_for(yml) == "demisto/py3-native:1.0"

    def test_returns_yml_image_when_flag_on(self) -> None:
        cfg = ccp.DockerConfig(
            default_image="demisto/py3-native:1.0",
            use_integration_docker=True,
        )
        yml = {"script": {"dockerimage": "demisto/python3:3.11"}}
        assert cfg.resolve_image_for(yml) == "demisto/python3:3.11"

    def test_falls_back_to_default_when_yml_missing_image(self) -> None:
        cfg = ccp.DockerConfig(
            default_image="demisto/py3-native:1.0",
            use_integration_docker=True,
        )
        # Flag on, but YML has no script.dockerimage.
        yml = {"script": {"type": "python"}}
        assert cfg.resolve_image_for(yml) == "demisto/py3-native:1.0"

    def test_falls_back_to_default_when_yml_is_none(self) -> None:
        cfg = ccp.DockerConfig(
            default_image="demisto/py3-native:1.0",
            use_integration_docker=True,
        )
        assert cfg.resolve_image_for(None) == "demisto/py3-native:1.0"

    def test_strips_whitespace_from_yml_image(self) -> None:
        cfg = ccp.DockerConfig(
            default_image="demisto/py3-native:1.0",
            use_integration_docker=True,
        )
        yml = {"script": {"dockerimage": "  demisto/python3:3.11  "}}
        assert cfg.resolve_image_for(yml) == "demisto/python3:3.11"

    def test_ignores_empty_yml_image(self) -> None:
        cfg = ccp.DockerConfig(
            default_image="demisto/py3-native:1.0",
            use_integration_docker=True,
        )
        yml = {"script": {"dockerimage": "   "}}
        assert cfg.resolve_image_for(yml) == "demisto/py3-native:1.0"

    def test_cli_flag_is_parsed(self) -> None:
        args = ccp._parse_args(
            ["dummy/path", "--static-only", "--use-integration-docker"]
        )
        assert args.use_integration_docker is True

    def test_cli_flag_default_is_false(self) -> None:
        args = ccp._parse_args(["dummy/path", "--static-only"])
        assert args.use_integration_docker is False


# =============================================================================
# B4 — per-command stderr breadcrumbs
# =============================================================================


class TestB4VerboseLogging:
    def test_resolved_handler_breadcrumb(
        self, isfetch_source: str, capsys: pytest.CaptureFixture
    ) -> None:
        ccp.analyze_static(isfetch_source, "test-module", verbose=True)
        err = capsys.readouterr().err
        assert "[static] test-module:" in err
        assert "module_test" in err  # the resolved handler name

    def test_no_dispatch_breadcrumb(
        self, capsys: pytest.CaptureFixture
    ) -> None:
        # An integration whose main() doesn't dispatch on `command` for "X".
        src = textwrap.dedent(
            """
            def main():
                command = demisto.command()
                if command == "y":
                    pass
            """
        )
        ccp.analyze_static(src, "x", verbose=True)
        err = capsys.readouterr().err
        assert "[static] x:" in err
        assert "no dispatch site found" in err

    def test_module_level_globals_listed(
        self, isfetch_source: str, capsys: pytest.CaptureFixture
    ) -> None:
        ccp.analyze_static(isfetch_source, "test-module", verbose=True)
        err = capsys.readouterr().err
        assert "module-level params globals" in err
        assert "PARAMS" in err

    def test_verbose_false_silent(
        self, isfetch_source: str, capsys: pytest.CaptureFixture
    ) -> None:
        ccp.analyze_static(isfetch_source, "test-module", verbose=False)
        err = capsys.readouterr().err
        assert "[static] test-module:" not in err

    def test_skips_non_python_integration(
        self, capsys: pytest.CaptureFixture
    ) -> None:
        scope_1, scope_2 = ccp.analyze_static(
            "function main() {}",
            "x",
            language="javascript",
            integration_name="JsThing",
            verbose=True,
        )
        assert scope_1 == set() and scope_2 == set()
        err = capsys.readouterr().err
        assert "non-Python integration" in err


# =============================================================================
# Dynamic-flow pure helpers
# =============================================================================


class TestBuildParamValues:
    def test_url_param_always_points_to_proxy(self) -> None:
        params = [{"name": "url", "type": ccp.YML_TYPE_SHORT_TEXT,
                   "defaultvalue": "https://api.example.com"}]
        values, sentinels, _ = ccp.build_param_values(
            params, "http://127.0.0.1:9999", set()
        )
        # URL param overrides defaultvalue with proxy URL.
        assert values["url"] == "http://127.0.0.1:9999"
        assert sentinels["url"] == ["http://127.0.0.1:9999"]

    def test_bool_param_traceable_false(self) -> None:
        params = [{"name": "isFetch", "type": ccp.YML_TYPE_BOOL}]
        values, sentinels, non_traceable = ccp.build_param_values(
            params, "http://x", set()
        )
        assert values["isFetch"] is True
        assert sentinels["isFetch"] == []
        assert "isFetch" in non_traceable

    def test_credentials_emits_two_sentinels(self) -> None:
        params = [{"name": "creds", "type": ccp.YML_TYPE_CREDENTIALS}]
        values, sentinels, _ = ccp.build_param_values(
            params, "http://x", set()
        )
        assert isinstance(values["creds"], dict)
        assert "identifier" in values["creds"] and "password" in values["creds"]
        assert len(sentinels["creds"]) == 2

    def test_ignored_param_value_sent_but_no_sentinel(self) -> None:
        params = [
            {"name": "to_ignore", "type": ccp.YML_TYPE_SHORT_TEXT},
            {"name": "kept", "type": ccp.YML_TYPE_SHORT_TEXT},
        ]
        values, sentinels, _ = ccp.build_param_values(
            params, "http://x", {"to_ignore"}
        )
        # Value still seeded (so module-level reads don't crash) ...
        assert "to_ignore" in values
        # ... but it must not contribute to detection.
        assert "to_ignore" not in sentinels
        assert "kept" in sentinels

    def test_default_text_uses_sentinel(self) -> None:
        params = [{"name": "anything"}]
        values, sentinels, _ = ccp.build_param_values(
            params, "http://x", set()
        )
        assert values["anything"].startswith(ccp.SENTINEL_PREFIX)
        assert sentinels["anything"][0].startswith(ccp.SENTINEL_PREFIX)


class TestGetCommandArgs:
    _YML = {
        "script": {
            "commands": [
                {
                    "name": "ip",
                    "arguments": [
                        {"name": "ip", "isArray": True},
                        {"name": "verbose", "defaultValue": "true"},
                    ],
                },
                {"name": "no-args-cmd", "arguments": []},
                {"name": "missing-args-key"},
            ]
        }
    }

    def test_returns_arguments_for_command(self) -> None:
        args = ccp.get_command_args(self._YML, "ip")
        assert [a["name"] for a in args] == ["ip", "verbose"]

    def test_empty_for_command_without_arguments(self) -> None:
        assert ccp.get_command_args(self._YML, "no-args-cmd") == []

    def test_empty_when_arguments_key_missing(self) -> None:
        assert ccp.get_command_args(self._YML, "missing-args-key") == []

    def test_empty_for_synthetic_command(self) -> None:
        # test-module / fetch-incidents have no YML arguments entry.
        assert ccp.get_command_args(self._YML, "test-module") == []

    def test_empty_for_unknown_command(self) -> None:
        assert ccp.get_command_args(self._YML, "does-not-exist") == []

    def test_skips_malformed_argument_entries(self) -> None:
        yml = {"script": {"commands": [{"name": "c", "arguments": [
            {"name": "good"}, {"no_name": "x"}, "not-a-dict",
        ]}]}}
        assert [a["name"] for a in ccp.get_command_args(yml, "c")] == ["good"]


class TestBuildArgValues:
    def test_uses_default_value(self) -> None:
        args = [{"name": "verbose", "defaultValue": "true"}]
        assert ccp.build_arg_values(args) == {"verbose": "true"}

    def test_tolerates_lowercase_defaultvalue(self) -> None:
        args = [{"name": "x", "defaultvalue": "v"}]
        assert ccp.build_arg_values(args) == {"x": "v"}

    def test_first_predefined_when_no_default(self) -> None:
        args = [{"name": "format", "predefined": ["json", "csv"]}]
        assert ccp.build_arg_values(args) == {"format": "json"}

    def test_sentinel_when_no_default_or_predefined(self) -> None:
        args = [{"name": "ip", "isArray": True}]
        out = ccp.build_arg_values(args)
        assert out["ip"] == f"{ccp.ARG_SENTINEL_PREFIX}ip"

    def test_default_wins_over_predefined(self) -> None:
        args = [{"name": "f", "defaultValue": "csv", "predefined": ["json", "csv"]}]
        assert ccp.build_arg_values(args) == {"f": "csv"}

    def test_empty_string_default_falls_through_to_predefined(self) -> None:
        args = [{"name": "f", "defaultValue": "", "predefined": ["json"]}]
        assert ccp.build_arg_values(args) == {"f": "json"}

    def test_seed_arg_overrides_everything(self) -> None:
        args = [
            {"name": "ip", "isArray": True},
            {"name": "verbose", "defaultValue": "true"},
            {"name": "format", "predefined": ["json", "csv"]},
        ]
        out = ccp.build_arg_values(args, seed_args={"ip": "1.1.1.1", "format": "csv"})
        assert out == {"ip": "1.1.1.1", "verbose": "true", "format": "csv"}

    def test_every_arg_gets_a_value(self) -> None:
        # Guarantees required-positional handlers never crash on missing kwarg.
        args = [{"name": "a"}, {"name": "b"}, {"name": "c"}]
        out = ccp.build_arg_values(args)
        assert set(out.keys()) == {"a", "b", "c"}

    def test_empty_args_yields_empty_dict(self) -> None:
        assert ccp.build_arg_values([]) == {}


class TestParseSeedArgs:
    def test_parses_per_command_scoped_pairs(self) -> None:
        out = ccp.parse_seed_args(["ip:ip=1.1.1.1", "report:ip=8.8.8.8"])
        assert out == {"ip": {"ip": "1.1.1.1"}, "report": {"ip": "8.8.8.8"}}

    def test_multiple_args_same_command(self) -> None:
        out = ccp.parse_seed_args(["ip:ip=1.1.1.1", "ip:days=7"])
        assert out == {"ip": {"ip": "1.1.1.1", "days": "7"}}

    def test_none_yields_empty(self) -> None:
        assert ccp.parse_seed_args(None) == {}

    def test_value_may_contain_equals(self) -> None:
        out = ccp.parse_seed_args(["c:q=a=b"])
        assert out == {"c": {"q": "a=b"}}

    def test_missing_colon_raises(self) -> None:
        with pytest.raises(ValueError, match="CMD:NAME=VALUE"):
            ccp.parse_seed_args(["ip=1.1.1.1"])

    def test_missing_equals_raises(self) -> None:
        with pytest.raises(ValueError, match="CMD:NAME=VALUE"):
            ccp.parse_seed_args(["ip:ip"])

    def test_empty_command_raises(self) -> None:
        with pytest.raises(ValueError, match="non-empty"):
            ccp.parse_seed_args([":ip=1.1.1.1"])

    def test_empty_name_raises(self) -> None:
        with pytest.raises(ValueError, match="non-empty"):
            ccp.parse_seed_args(["ip:=1.1.1.1"])


class TestBuildChildEnvArgs:
    def test_args_json_present_and_serialized(self) -> None:
        env = ccp._build_child_env(
            params={"p": 1},
            command="ip",
            proxy_url="http://x",
            unified_path="/u",
            mock_dir="/m",
            args={"ip": "1.1.1.1"},
        )
        import json as _json
        assert _json.loads(env["CHECK_ARGS_JSON"]) == {"ip": "1.1.1.1"}
        assert _json.loads(env["CHECK_PARAMS_JSON"]) == {"p": 1}
        assert env["CHECK_COMMAND"] == "ip"

    def test_args_defaults_to_empty_dict(self) -> None:
        env = ccp._build_child_env(
            params={},
            command="c",
            proxy_url="http://x",
            unified_path="/u",
            mock_dir="/m",
        )
        assert env["CHECK_ARGS_JSON"] == "{}"

    def test_mock_template_reads_check_args_json(self) -> None:
        # The on-disk demistomock must surface CHECK_ARGS_JSON via args().
        assert "CHECK_ARGS_JSON" in ccp._DEMISTOMOCK_TEMPLATE
        assert "_ARGS" in ccp._DEMISTOMOCK_TEMPLATE


class TestTrackingMapping:
    """The params-access spy: an instrumented mapping that records reads."""

    def test_getitem_records_key(self) -> None:
        m = ccp.TrackingMapping({"a": 1, "b": 2})
        _ = m["a"]
        assert m.accessed_keys == {"a"}

    def test_get_records_key(self) -> None:
        m = ccp.TrackingMapping({"a": 1})
        m.get("a")
        assert "a" in m.accessed_keys

    def test_get_records_missing_key_too(self) -> None:
        # params.get("disregard_quota") returns None when absent, but the
        # READ intent is still meaningful — record it.
        m = ccp.TrackingMapping({"a": 1})
        m.get("missing")
        assert "missing" in m.accessed_keys

    def test_contains_records_key(self) -> None:
        m = ccp.TrackingMapping({"a": 1})
        _ = "a" in m
        assert "a" in m.accessed_keys

    def test_behaves_like_dict_for_values(self) -> None:
        m = ccp.TrackingMapping({"a": 1, "b": 2})
        assert m["a"] == 1
        assert m.get("b") == 2
        assert m.get("z", "default") == "default"
        assert ("a" in m) is True
        assert ("z" in m) is False

    def test_nested_get_chain_records_parent(self) -> None:
        # ``params.get("credentials", {}).get("password")`` must record
        # the parent key 'credentials' on the tracking mapping.
        m = ccp.TrackingMapping({"credentials": {"password": "x"}})
        m.get("credentials", {}).get("password")
        assert "credentials" in m.accessed_keys

    def test_accessed_keys_starts_empty(self) -> None:
        m = ccp.TrackingMapping({"a": 1})
        assert m.accessed_keys == set()


class TestParseAccessReport:
    def test_parses_json_list(self) -> None:
        assert ccp.parse_access_report('["a", "b"]') == {"a", "b"}

    def test_empty_or_missing_yields_empty(self) -> None:
        assert ccp.parse_access_report("") == set()
        assert ccp.parse_access_report(None) == set()

    def test_ignores_malformed(self) -> None:
        # Robust to a truncated/garbled child report.
        assert ccp.parse_access_report("not json{{{") == set()


class TestAttributeAccessSpy:
    def test_elevates_above_baseline_only(self) -> None:
        # 'integrationReliability' is read at startup (baseline) → not
        # elevated. 'disregard_quota' is command-specific → elevated.
        elevate = ccp.attribute_access_spy(
            command_accessed={"integrationReliability", "disregard_quota"},
            baseline_accessed={"integrationReliability"},
            yml_param_names={"integrationReliability", "disregard_quota", "threshold"},
            ignore=set(),
        )
        assert elevate == {"disregard_quota"}

    def test_filters_to_yml_params(self) -> None:
        # Keys not in the YML config set are dropped (e.g. internal keys).
        elevate = ccp.attribute_access_spy(
            command_accessed={"disregard_quota", "some_internal_key"},
            baseline_accessed=set(),
            yml_param_names={"disregard_quota"},
            ignore=set(),
        )
        assert elevate == {"disregard_quota"}

    def test_drops_ignored_params(self) -> None:
        elevate = ccp.attribute_access_spy(
            command_accessed={"server", "disregard_quota"},
            baseline_accessed=set(),
            yml_param_names={"server", "disregard_quota"},
            ignore={"server"},
        )
        assert elevate == {"disregard_quota"}

    def test_empty_when_all_in_baseline(self) -> None:
        elevate = ccp.attribute_access_spy(
            command_accessed={"a", "b"},
            baseline_accessed={"a", "b"},
            yml_param_names={"a", "b"},
            ignore=set(),
        )
        assert elevate == set()


class TestDynamicAccessTier:
    def test_dynamic_access_tier_exists_and_is_high_but_not_one(self) -> None:
        # Per decision: spy hit is strong (needs_review) but below the
        # on-wire dynamic_capture gold tier so the agent double-checks.
        assert "dynamic_access" in ccp.TIER_CONFIDENCE
        val = ccp.TIER_CONFIDENCE["dynamic_access"]
        assert 0.5 < val < 1.0
        assert val < ccp.TIER_CONFIDENCE["dynamic_capture"]


class TestAccessSpyEnvWiring:
    def test_mock_template_uses_tracking_mapping(self) -> None:
        assert "TrackingMapping" in ccp._DEMISTOMOCK_TEMPLATE
        assert "CHECK_ACCESS_OUT" in ccp._DEMISTOMOCK_TEMPLATE

    def test_child_env_carries_access_out_path(self) -> None:
        env = ccp._build_child_env(
            params={},
            command="c",
            proxy_url="http://x",
            unified_path="/u",
            mock_dir="/m",
            access_out="/tmp/access.json",
        )
        assert env["CHECK_ACCESS_OUT"] == "/tmp/access.json"


class TestBuildAttributionsAccessSpy:
    """The spy folds into the attribution rollup at the dynamic_access tier."""

    def test_spy_param_gets_dynamic_access_source(self) -> None:
        attrs = ccp._build_attributions(
            handler_evidence=[],
            pre_dispatch_evidence={},
            module_const_to_params={},
            hedged_constants=set(),
            referenced_const_names=set(),
            walk_uncertain=False,
            captured=set(),
            yml_param_names={"disregard_quota"},
            access_spy_params={"disregard_quota"},
        )
        by_param = {a.param: a for a in attrs}
        assert "disregard_quota" in by_param
        assert "dynamic_access" in by_param["disregard_quota"].by_source
        assert by_param["disregard_quota"].rollup_confidence == pytest.approx(0.9)

    def test_spy_does_not_override_higher_dynamic_capture(self) -> None:
        # On-wire capture (1.0) must still win the rollup over spy (0.9).
        attrs = ccp._build_attributions(
            handler_evidence=[],
            pre_dispatch_evidence={},
            module_const_to_params={},
            hedged_constants=set(),
            referenced_const_names=set(),
            walk_uncertain=False,
            captured={"token"},
            yml_param_names={"token"},
            access_spy_params={"token"},
        )
        by_param = {a.param: a for a in attrs}
        assert by_param["token"].rollup_confidence == pytest.approx(1.0)
        # both sources recorded
        assert "dynamic_access" in by_param["token"].by_source
        assert "dynamic_capture" in by_param["token"].by_source

    def test_no_spy_params_means_no_dynamic_access_source(self) -> None:
        attrs = ccp._build_attributions(
            handler_evidence=[],
            pre_dispatch_evidence={"x": "read in main"},
            module_const_to_params={},
            hedged_constants=set(),
            referenced_const_names=set(),
            walk_uncertain=False,
            captured=set(),
            yml_param_names={"x"},
            access_spy_params=set(),
        )
        by_param = {a.param: a for a in attrs}
        assert "dynamic_access" not in by_param["x"].by_source


class TestSentinelDetection:
    def test_hit_in_url(self) -> None:
        reqs = [{"method": "GET", "url": "http://x/SENTINEL_PARAM_foo", "headers": {}}]
        sentinels = {"foo": ["SENTINEL_PARAM_foo"], "bar": ["SENTINEL_PARAM_bar"]}
        assert ccp.detect_sentinel_hits(reqs, sentinels) == {"foo"}

    def test_hit_in_header(self) -> None:
        reqs = [{"method": "GET", "url": "http://x", "headers": {"Auth": "SENTINEL_PARAM_token"}}]
        sentinels = {"token": ["SENTINEL_PARAM_token"]}
        assert ccp.detect_sentinel_hits(reqs, sentinels) == {"token"}

    def test_hit_in_body(self) -> None:
        reqs = [{"method": "POST", "url": "http://x", "headers": {},
                 "body": '{"x": "SENTINEL_PARAM_pw"}'}]
        sentinels = {"pw": ["SENTINEL_PARAM_pw"]}
        assert ccp.detect_sentinel_hits(reqs, sentinels) == {"pw"}

    def test_empty_token_list_skipped(self) -> None:
        reqs = [{"method": "GET", "url": "http://x", "headers": {}}]
        sentinels = {"isFetch": []}  # non-traceable
        assert ccp.detect_sentinel_hits(reqs, sentinels) == set()

    def test_empty_requests_returns_empty(self) -> None:
        assert ccp.detect_sentinel_hits([], {"foo": ["X"]}) == set()


class TestStderrClassifiers:
    def test_extract_failing_params_filters_to_yml_set(self) -> None:
        text = "RETURN_ERROR_PATCHED: invalid SENTINEL_PARAM_real and SENTINEL_PARAM_fake"
        out = ccp.extract_failing_params(text, {"real"})
        assert out == ["real"]  # 'fake' is dropped — not a YML param

    def test_extract_failing_params_unique_sorted(self) -> None:
        text = "SENTINEL_PARAM_b SENTINEL_PARAM_a SENTINEL_PARAM_b"
        out = ccp.extract_failing_params(text, {"a", "b"})
        assert out == ["a", "b"]

    def test_extract_failing_params_empty_text(self) -> None:
        assert ccp.extract_failing_params("", {"a"}) == []

    def test_extract_missing_module_match(self) -> None:
        stderr = (
            "Traceback (most recent call last):\n"
            "  File ...\n"
            "ModuleNotFoundError: No module named 'pymisp'\n"
        )
        result = ccp.extract_missing_module(stderr)
        assert result is not None
        module_name, line = result
        assert module_name == "pymisp"
        assert "ModuleNotFoundError" in line

    def test_extract_missing_module_no_match(self) -> None:
        assert ccp.extract_missing_module("ImportError: foo") is None

    def test_extract_missing_module_handles_double_quotes(self) -> None:
        stderr = "ModuleNotFoundError: No module named \"httpx\""
        result = ccp.extract_missing_module(stderr)
        assert result is not None and result[0] == "httpx"

    def test_short_stderr_prefers_return_error_marker(self) -> None:
        stderr = (
            "some warning\n"
            "RETURN_ERROR_PATCHED: invalid url\n"
            "more noise\n"
        )
        assert "RETURN_ERROR_PATCHED" in ccp._short_stderr(stderr)

    def test_short_stderr_falls_back_to_last_line(self) -> None:
        stderr = "warn 1\nwarn 2\n"
        assert ccp._short_stderr(stderr) == "warn 2"


class TestMergeCommandParams:
    def test_no_dynamic_returns_static_union(self) -> None:
        out = ccp._merge_command_params(
            "x",
            static_pair=({"a", "b"}, {"c"}),
            captured=set(),
            diag=None,
        )
        assert out == {"a", "b", "c"}

    def test_no_capture_returns_static_union(self) -> None:
        diag = ccp.CommandDiagnostic(status="ok_no_capture", captured_requests=0)
        out = ccp._merge_command_params(
            "x",
            static_pair=({"a", "b"}, {"c"}),
            captured=set(),
            diag=diag,
        )
        assert out == {"a", "b", "c"}
        assert diag.scope_1_narrowed is False

    def test_narrows_scope_1_when_dynamic_succeeds(self) -> None:
        diag = ccp.CommandDiagnostic(status="ok", captured_requests=3)
        out = ccp._merge_command_params(
            "x",
            static_pair=({"a", "b", "shared"}, {"c"}),  # scope_1 has a, b, shared
            captured={"shared"},  # dynamic only saw "shared" on the wire
            diag=diag,
        )
        # scope_1 narrowed to scope_1 ∩ captured = {"shared"}
        # final = {"shared"} | scope_2 | captured = {"shared", "c"}
        assert out == {"shared", "c"}
        assert diag.scope_1_narrowed is True
        assert diag.scope_1_dropped == ["a", "b"]

    def test_does_not_narrow_when_status_not_ok(self) -> None:
        diag = ccp.CommandDiagnostic(
            status="param_caused_failure", captured_requests=0
        )
        out = ccp._merge_command_params(
            "x",
            static_pair=({"a", "b"}, {"c"}),
            captured={"a"},  # from sentinel attribution
            diag=diag,
        )
        assert out == {"a", "b", "c"}
        assert diag.scope_1_narrowed is False

    def test_classify_dynamic_error_timeout(self) -> None:
        exc = ccp.DynamicAnalysisError("command 'x' timed out after 60s")
        assert ccp._classify_dynamic_error(exc) == "timeout"

    def test_classify_dynamic_error_docker(self) -> None:
        exc = ccp.DynamicAnalysisError("docker invocation failed: nope")
        assert ccp._classify_dynamic_error(exc) == "docker_error"

    def test_classify_dynamic_error_default(self) -> None:
        exc = ccp.DynamicAnalysisError("something weird")
        assert ccp._classify_dynamic_error(exc) == "no_data"


class TestCommandDiagnostic:
    def test_minimal_to_dict(self) -> None:
        d = ccp.CommandDiagnostic(status="ok", captured_requests=5)
        # Updated per Changes 1-4: analysis_status is now always
        # present in the serialized payload (defaults to
        # ``dispatch_unresolved`` when the diagnostic was created
        # without going through the analyzer pipeline).
        assert d.to_dict() == {
            "status": "ok",
            "captured_requests": 5,
            "analysis_status": "dispatch_unresolved",
        }

    def test_failure_excerpt_only_for_non_ok(self) -> None:
        d = ccp.CommandDiagnostic(
            status="ok",
            captured_requests=1,
            failure_excerpt="should be hidden",
        )
        # ``failure_excerpt`` is suppressed when status is ok / ok_no_capture.
        assert "failure_excerpt" not in d.to_dict()

    def test_module_not_found_emits_field(self) -> None:
        d = ccp.CommandDiagnostic(
            status="module_not_found",
            captured_requests=0,
            failure_excerpt="ModuleNotFoundError: No module named 'httpx'",
            missing_module="httpx",
        )
        out = d.to_dict()
        assert out["status"] == "module_not_found"
        assert out["missing_module"] == "httpx"

    def test_narrowing_fields_serialized(self) -> None:
        d = ccp.CommandDiagnostic(
            status="ok",
            captured_requests=1,
            scope_1_narrowed=True,
            scope_1_dropped=["a", "b"],
        )
        out = d.to_dict()
        assert out["scope_1_narrowed"] is True
        assert out["scope_1_dropped"] == ["a", "b"]

    def test_narrowing_fields_omitted_when_not_narrowed(self) -> None:
        d = ccp.CommandDiagnostic(status="ok", captured_requests=0)
        out = d.to_dict()
        assert "scope_1_narrowed" not in out
        assert "scope_1_dropped" not in out

    def test_narrowing_fields_omitted_when_dropped_is_empty(self) -> None:
        # Fix 3 (Option A): emitting ``scope_1_narrowed: true`` with an
        # empty ``scope_1_dropped`` is misleading. The two fields must
        # both be omitted when narrowing was applied but happened to
        # drop nothing (captured set was a superset of Scope-1).
        d = ccp.CommandDiagnostic(
            status="ok",
            captured_requests=1,
            scope_1_narrowed=True,
            scope_1_dropped=[],
        )
        out = d.to_dict()
        assert "scope_1_narrowed" not in out
        assert "scope_1_dropped" not in out


# =============================================================================
# Misc. small helpers
# =============================================================================


class TestMiscHelpers:
    def test_load_ignore_inline(self) -> None:
        out = ccp.load_ignore_params(["a", "b"], None)
        assert {"a", "b"}.issubset(out)

    def test_load_ignore_file(self, tmp_path: Path) -> None:
        f = tmp_path / "ignore.txt"
        f.write_text(
            "# comment\n"
            "alpha\n"
            "beta\n"
            "\n"
            "# another comment\n"
            "gamma\n"
        )
        out = ccp.load_ignore_params(None, f)
        assert {"alpha", "beta", "gamma"}.issubset(out)

    def test_load_ignore_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            ccp.load_ignore_params(None, tmp_path / "nonexistent.txt")

    def test_coerce_default_value_bool(self) -> None:
        assert ccp._coerce_default_value("true", ccp.YML_TYPE_BOOL) is True
        assert ccp._coerce_default_value("false", ccp.YML_TYPE_BOOL) is False
        assert ccp._coerce_default_value("yes", ccp.YML_TYPE_BOOL) is True

    def test_coerce_default_value_numeric(self) -> None:
        assert ccp._coerce_default_value("42", ccp.YML_TYPE_NUMERIC) == 42
        assert ccp._coerce_default_value("3.14", ccp.YML_TYPE_NUMERIC) == 3.14
        # Non-numeric string falls through.
        assert ccp._coerce_default_value("nope", ccp.YML_TYPE_NUMERIC) == "nope"

    def test_discover_commands(self) -> None:
        yml = {
            "script": {
                "commands": [
                    {"name": "cmd-a"},
                    {"name": "cmd-b"},
                ],
                "isfetch": True,
            }
        }
        cmds = ccp.discover_commands(yml)
        assert "cmd-a" in cmds
        assert "cmd-b" in cmds
        assert "fetch-incidents" in cmds


# =============================================================================
# --- Phase 1: regression baseline ---
#
# These tests lock in the CURRENT (good) behavior of analyze_static for the
# scope-1 / scope-2 split. They MUST continue to pass after Phase 3 introduces
# binding-narrowing. Each test feeds a small inline integration source string
# to ``analyze_static`` and asserts on the (scope_1, scope_2) tuple.
#
# Note on duplicates with earlier sections:
# * Case 8 (match/case dispatch)   — ``TestDispatchVariants.test_match_case_dispatch``
#   already covers it at the ``find_command_handler_calls`` level. The Phase 1
#   variant below adds the analyze_static end-to-end check (param attribution),
#   which is materially different.
# * Case 9 (dict dispatch)         — same situation; existing test only checks
#   handler resolution, the version below also checks param flow.
# * Case 10 (isfetch via script.isfetch) — fully covered already by
#   ``TestMiscHelpers.test_discover_commands``. Skipped here; do NOT duplicate.
# =============================================================================


class TestPhase1RegressionBaseline:
    """Lock in current good behavior of analyze_static."""

    # ---- Case 1: SEE Phase 2 ----
    # The spec for case 1 ("direct dispatch read: handler(params.get('p'))
    # inside an if-command branch") describes the EXPECTED behavior, not the
    # current one. Empirically, the current analyzer drops ``params.get('p')``
    # when it is embedded inline at the dispatch call site (it is past the
    # pre-dispatch line, and the handler body never receives the value).
    # See ``TestPhase2BindingNarrowing.test_case1_direct_dispatch_inline_get``
    # for the contract test (xfail today, must pass after Phase 3).

    # ---- Case 2: per-handler param argument ----
    def test_case2_per_handler_params_arg(self) -> None:
        src = textwrap.dedent(
            """
            import demistomock as demisto

            def handler_x(params):
                return params.get("p")

            def handler_y(params):
                return params.get("q")

            def main():
                params = demisto.params()
                command = demisto.command()
                if command == "X":
                    handler_x(params)
                elif command == "Y":
                    handler_y(params)
            """
        )
        s1_x, s2_x = ccp.analyze_static(src, "X", language="python", verbose=False)
        s1_y, s2_y = ccp.analyze_static(src, "Y", language="python", verbose=False)
        assert "p" in (s1_x | s2_x)
        assert "q" not in (s1_x | s2_x), (
            f"q is read only inside handler_y; must not surface for X. "
            f"scope_1={s1_x}, scope_2={s2_x}"
        )
        assert "q" in (s1_y | s2_y)
        assert "p" not in (s1_y | s2_y)

    # ---- Case 3: module-level PARAMS global with eager read ----
    def test_case3_module_level_global_fanout(self) -> None:
        src = textwrap.dedent(
            """
            import demistomock as demisto

            PARAMS = demisto.params()
            SERVER = PARAMS.get("url")  # eager, runs at import for ALL commands

            def handler_x(): pass
            def handler_y(): pass

            def main():
                command = demisto.command()
                if command == "X":
                    handler_x()
                elif command == "Y":
                    handler_y()
            """
        )
        s1_x, s2_x = ccp.analyze_static(src, "X", language="python", verbose=False)
        s1_y, s2_y = ccp.analyze_static(src, "Y", language="python", verbose=False)
        # Module-level reads belong to scope_1 (eager fan-out), and must
        # surface for every command.
        assert "url" in s1_x, f"scope_1 for X = {s1_x}"
        assert "url" in s1_y, f"scope_1 for Y = {s1_y}"

    # ---- Case 4: Client(...) constructor with inline params.get(...) ----
    def test_case4_client_ctor_inline_get_fans_out(self) -> None:
        src = textwrap.dedent(
            """
            import demistomock as demisto

            class Client:
                def __init__(self, api_key, url): pass

            def handler_x(client): pass
            def handler_y(client): pass

            def main():
                params = demisto.params()
                client = Client(api_key=params.get("apikey"), url=params.get("url"))
                command = demisto.command()
                if command == "X":
                    handler_x(client)
                elif command == "Y":
                    handler_y(client)
            """
        )
        s1_x, s2_x = ccp.analyze_static(src, "X", language="python", verbose=False)
        s1_y, s2_y = ccp.analyze_static(src, "Y", language="python", verbose=False)
        # Inline (unbound) params.get reads inside Client(...) before the
        # dispatch site fan out to ALL commands. This is legitimate Scope-1.
        all_x = s1_x | s2_x
        all_y = s1_y | s2_y
        assert "apikey" in all_x and "url" in all_x, (
            f"X missing apikey/url. scope_1={s1_x}, scope_2={s2_x}"
        )
        assert "apikey" in all_y and "url" in all_y, (
            f"Y missing apikey/url. scope_1={s1_y}, scope_2={s2_y}"
        )

    # ---- Case 5: Pydantic alias resolution ----
    def test_case5_pydantic_alias_resolution(self) -> None:
        src = textwrap.dedent(
            """
            import demistomock as demisto
            from pydantic import BaseModel, Field

            class P(BaseModel):
                my_attr: str = Field(alias="my-yml-name")

            def handler_x(params):
                # accessed as attribute; alias makes the YML name "my-yml-name"
                return params.my_attr

            def main():
                params = demisto.params()
                command = demisto.command()
                if command == "X":
                    handler_x(params)
            """
        )
        s1, s2 = ccp.analyze_static(src, "X", language="python", verbose=False)
        all_static = s1 | s2
        assert "my-yml-name" in all_static, (
            f"alias should resolve to the YML name 'my-yml-name'. "
            f"scope_1={s1}, scope_2={s2}"
        )
        assert "my_attr" not in all_static, (
            f"raw python attribute name should NOT leak. "
            f"scope_1={s1}, scope_2={s2}"
        )

    # ---- Case 6: chained demisto.params().get(...) inside handler ----
    def test_case6_chained_demisto_params_in_handler(self) -> None:
        src = textwrap.dedent(
            """
            import demistomock as demisto

            def handler_x():
                return demisto.params().get("p")

            def main():
                command = demisto.command()
                if command == "X":
                    handler_x()
            """
        )
        s1, s2 = ccp.analyze_static(src, "X", language="python", verbose=False)
        assert "p" in (s1 | s2), f"chained get not traced. s1={s1}, s2={s2}"

    # ---- Case 7: SEE Phase 2 ----
    # Same reason as case 1: ``params.get('z')`` embedded inline inside the
    # ``elif command == "Y":`` handler-call expression is dropped by the
    # current analyzer. The "must not leak to X" half of the assertion
    # holds today (because nothing surfaces at all), but the "must surface
    # for Y" half does not. Moved to Phase 2.

    # ---- Case 8: match/case dispatch (analyze_static end-to-end) ----
    def test_case8_match_case_dispatch_param_flow(self) -> None:
        src = textwrap.dedent(
            """
            import demistomock as demisto

            def handler_x(params):
                return params.get("p")

            def handler_y(params):
                return params.get("q")

            def main():
                params = demisto.params()
                command = demisto.command()
                match command:
                    case "X":
                        handler_x(params)
                    case "Y":
                        handler_y(params)
            """
        )
        s1_x, s2_x = ccp.analyze_static(src, "X", language="python", verbose=False)
        s1_y, s2_y = ccp.analyze_static(src, "Y", language="python", verbose=False)
        assert "p" in (s1_x | s2_x) and "q" not in (s1_x | s2_x)
        assert "q" in (s1_y | s2_y) and "p" not in (s1_y | s2_y)

    # ---- Case 9: dict dispatch (analyze_static end-to-end) ----
    def test_case9_dict_dispatch_param_flow(self) -> None:
        src = textwrap.dedent(
            """
            import demistomock as demisto

            def handler_x(params):
                return params.get("p")

            def handler_y(params):
                return params.get("q")

            def main():
                params = demisto.params()
                command = demisto.command()
                commands = {"X": handler_x, "Y": handler_y}
                commands[command](params)
            """
        )
        s1_x, s2_x = ccp.analyze_static(src, "X", language="python", verbose=False)
        s1_y, s2_y = ccp.analyze_static(src, "Y", language="python", verbose=False)
        assert "p" in (s1_x | s2_x), (
            f"dict-dispatch handler resolution lost 'p' for X. "
            f"scope_1={s1_x}, scope_2={s2_x}"
        )
        assert "q" in (s1_y | s2_y), (
            f"dict-dispatch handler resolution lost 'q' for Y. "
            f"scope_1={s1_y}, scope_2={s2_y}"
        )

    # ---- Case 10: SKIPPED — already covered ----
    # ``fetch-incidents`` discovery via ``script.isfetch: true`` is fully
    # tested by ``TestMiscHelpers.test_discover_commands``. Not duplicated.


# =============================================================================
# --- Phase 2: binding-narrowing (xfail until Phase 3) ---
#
# These tests describe the CONTRACT for the Phase 3 fix. They are marked
# strict-xfail so that:
#   * today they fail (the analyzer over-attributes bound-var reads to every
#     command) without breaking CI;
#   * once Phase 3 lands they will PASS, and strict=True forces removal of the
#     xfail marker — preventing a silent regression of the new behavior.
#
# If any of these unexpectedly XPASS today, that means the analyzer already
# partially narrows for that pattern; the xfail marker will surface the
# surprise as a test failure and the user should be told.
# =============================================================================


class TestPhase2BindingNarrowing:
    """Contract tests for the Phase 3 binding-narrowing fix.

    All five cases initially landed as ``xfail(strict=True)`` to document
    the contract; once Phase 3 implementation in
    :func:`ccp.analyze_static` made them pass, the markers were removed
    so future regressions surface as failing tests.
    """

    # ---- Case 1 (deferred from Phase 1) ----
    def test_case1_direct_dispatch_inline_get(self) -> None:
        # Inline ``params.get("p")`` embedded as an argument at the dispatch
        # site (after the pre-dispatch line, INSIDE an if-command branch).
        # Current analyzer drops the read entirely. Phase 3 must attribute it
        # to X only.
        src = textwrap.dedent(
            """
            import demistomock as demisto

            def handler_x(p): pass

            def main():
                params = demisto.params()
                command = demisto.command()
                if command == "X":
                    handler_x(params.get("p"))
            """
        )
        s1_x, s2_x = ccp.analyze_static(src, "X", language="python", verbose=False)
        s1_y, s2_y = ccp.analyze_static(src, "Y", language="python", verbose=False)
        assert "p" in (s1_x | s2_x), (
            f"'p' should appear for X. scope_1={s1_x}, scope_2={s2_x}"
        )
        assert "p" not in (s1_y | s2_y), (
            f"'p' must not appear for Y. scope_1={s1_y}, scope_2={s2_y}"
        )

    # ---- Case 7 (deferred from Phase 1) ----
    def test_case7_if_elif_branch_isolated_reads(self) -> None:
        src = textwrap.dedent(
            """
            import demistomock as demisto

            def handler_x(): pass
            def handler_y(z): pass

            def main():
                params = demisto.params()
                command = demisto.command()
                if command == "X":
                    handler_x()
                elif command == "Y":
                    handler_y(params.get("z"))
            """
        )
        s1_x, s2_x = ccp.analyze_static(src, "X", language="python", verbose=False)
        s1_y, s2_y = ccp.analyze_static(src, "Y", language="python", verbose=False)
        assert "z" not in (s1_x | s2_x), (
            f"'z' must not appear for X. scope_1={s1_x}, scope_2={s2_x}"
        )
        assert "z" in (s1_y | s2_y), (
            f"'z' should appear for Y. scope_1={s1_y}, scope_2={s2_y}"
        )

    # ---- Case 11: Okta-IAM-style binding ----
    def test_case11_okta_iam_mapper_out_binding(self) -> None:
        src = textwrap.dedent(
            """
            import demistomock as demisto

            class OktaClient:
                def __init__(self, *a, **kw): pass

            def fetch_incidents(client): pass
            def update_user_command(client, args, mapper_out): pass

            def main():
                params = demisto.params()
                mapper_out = params.get("mapper-out")
                client = OktaClient()
                args = demisto.args()
                command = demisto.command()
                if command == "fetch-incidents":
                    fetch_incidents(client)
                elif command == "iam-update-user":
                    update_user_command(client, args, mapper_out)
            """
        )
        s1_fi, s2_fi = ccp.analyze_static(
            src, "fetch-incidents", language="python", verbose=False
        )
        s1_up, s2_up = ccp.analyze_static(
            src, "iam-update-user", language="python", verbose=False
        )
        assert "mapper-out" not in (s1_fi | s2_fi), (
            f"mapper-out is bound but never passed to fetch_incidents; "
            f"it should NOT surface for fetch-incidents. "
            f"scope_1={s1_fi}, scope_2={s2_fi}"
        )
        assert "mapper-out" in (s1_up | s2_up), (
            f"mapper-out IS passed to update_user_command; should surface for "
            f"iam-update-user. scope_1={s1_up}, scope_2={s2_up}"
        )

    # ---- Case 12: multiple bound vars, partially routed ----
    def test_case12_multiple_bound_vars_partial_routing(self) -> None:
        src = textwrap.dedent(
            """
            import demistomock as demisto

            class Client: pass
            def cmd_x(client, a): pass
            def cmd_y(client, b): pass

            def main():
                params = demisto.params()
                a = params.get("alpha")
                b = params.get("beta")
                client = Client()
                if demisto.command() == "X":
                    cmd_x(client, a)
                elif demisto.command() == "Y":
                    cmd_y(client, b)
            """
        )
        s1_x, s2_x = ccp.analyze_static(src, "X", language="python", verbose=False)
        s1_y, s2_y = ccp.analyze_static(src, "Y", language="python", verbose=False)
        all_x = s1_x | s2_x
        all_y = s1_y | s2_y
        assert "alpha" in all_x and "beta" not in all_x, (
            f"X gets only alpha. scope_1={s1_x}, scope_2={s2_x}"
        )
        assert "beta" in all_y and "alpha" not in all_y, (
            f"Y gets only beta. scope_1={s1_y}, scope_2={s2_y}"
        )

    # ---- Case 13: bound var passed via keyword argument ----
    def test_case13_bound_var_via_kwarg(self) -> None:
        src = textwrap.dedent(
            """
            import demistomock as demisto

            class Client: pass
            def update_user_command(client, args, mapper_out=None): pass
            def fetch_incidents(client): pass

            def main():
                params = demisto.params()
                mo = params.get("mapper-out")
                client = Client()
                args = demisto.args()
                if demisto.command() == "iam-update-user":
                    update_user_command(client, args, mapper_out=mo)
                elif demisto.command() == "fetch-incidents":
                    fetch_incidents(client)
            """
        )
        s1_fi, s2_fi = ccp.analyze_static(
            src, "fetch-incidents", language="python", verbose=False
        )
        s1_up, s2_up = ccp.analyze_static(
            src, "iam-update-user", language="python", verbose=False
        )
        assert "mapper-out" not in (s1_fi | s2_fi), (
            f"mapper-out is bound to 'mo' and only passed via kwarg to "
            f"iam-update-user; must NOT surface for fetch-incidents. "
            f"scope_1={s1_fi}, scope_2={s2_fi}"
        )
        assert "mapper-out" in (s1_up | s2_up), (
            f"mapper-out IS passed via kwarg to update_user_command; "
            f"should surface for iam-update-user. "
            f"scope_1={s1_up}, scope_2={s2_up}"
        )

    # ---- Case 14: bound var stored on Client must keep fanning out ----
    # NOTE: This XPASSED on first run — the analyzer ALREADY handles this case.
    # The defensive contract holds today (apikey fans out to both X and Y even
    # though it is bound to a local var, because the bound var is consumed by
    # ``Client(...)`` whose result is then passed to every handler). We keep
    # this as a regular Phase 2 regression test (no xfail) so that Phase 3 is
    # required to PRESERVE the current good behavior — i.e., binding-narrowing
    # must not over-narrow.
    def test_case14_bound_var_stored_on_client_still_fans_out(self) -> None:
        src = textwrap.dedent(
            """
            import demistomock as demisto

            class Client:
                def __init__(self, api_key=None): pass

            def cmd_x(client): pass
            def cmd_y(client): pass

            def main():
                params = demisto.params()
                api_key = params.get("apikey")
                client = Client(api_key=api_key)
                if demisto.command() == "X":
                    cmd_x(client)
                elif demisto.command() == "Y":
                    cmd_y(client)
            """
        )
        s1_x, s2_x = ccp.analyze_static(src, "X", language="python", verbose=False)
        s1_y, s2_y = ccp.analyze_static(src, "Y", language="python", verbose=False)
        # Defensive case: api_key is bound to a local var, but consumed by the
        # Client constructor whose result is then passed to BOTH handlers. The
        # Phase 3 fix MUST NOT over-narrow this — apikey must keep fanning out.
        assert "apikey" in (s1_x | s2_x), (
            f"apikey is bound but flows to every handler via Client(...); "
            f"must remain fanned out for X. scope_1={s1_x}, scope_2={s2_x}"
        )
        assert "apikey" in (s1_y | s2_y), (
            f"apikey is bound but flows to every handler via Client(...); "
            f"must remain fanned out for Y. scope_1={s1_y}, scope_2={s2_y}"
        )

    # ---- Case 15: global re-binding inside main() must keep fanning out ----
    def test_case15_global_rebind_in_main_fans_out(self) -> None:
        # The GitHub-style pattern: ``global X; X = params.get("...")``
        # inside main() re-binds a module-level name. Every command
        # handler then reads that global. Binding-narrowing must NOT
        # treat ``X`` as a local — its reads must remain Scope-1 fan-out.
        src = textwrap.dedent(
            """
            import demistomock as demisto

            BASE_URL = ""
            TOKEN = ""

            def cmd_x(): pass
            def cmd_y(): pass

            def main():
                global BASE_URL
                global TOKEN
                params = demisto.params()
                BASE_URL = params.get("url")
                TOKEN = params.get("token")
                command = demisto.command()
                if command == "X":
                    cmd_x()
                elif command == "Y":
                    cmd_y()
            """
        )
        s1_x, s2_x = ccp.analyze_static(src, "X", language="python", verbose=False)
        s1_y, s2_y = ccp.analyze_static(src, "Y", language="python", verbose=False)
        assert "url" in (s1_x | s2_x) and "token" in (s1_x | s2_x), (
            f"global re-binding must keep params in Scope-1 for X. "
            f"scope_1={s1_x}, scope_2={s2_x}"
        )
        assert "url" in (s1_y | s2_y) and "token" in (s1_y | s2_y), (
            f"global re-binding must keep params in Scope-1 for Y. "
            f"scope_1={s1_y}, scope_2={s2_y}"
        )

    # ---- Case 16: dict-dispatch + Client(...) must keep fanning out ----
    def test_case16_dict_dispatch_with_client_fans_out(self) -> None:
        # MongoDB-style pattern: build a Client with inline params reads,
        # then route every command through ``commands[command](client, ...)``.
        # The shared dispatch site must still propagate the Client's
        # carried params to every command in the dict.
        src = textwrap.dedent(
            """
            import demistomock as demisto

            class Client:
                def __init__(self, **kw): pass

            def cmd_x(client): pass
            def cmd_y(client): pass

            def main():
                params = demisto.params()
                client = Client(
                    url=params.get("url"),
                    api_key=params.get("apikey"),
                )
                command = demisto.command()
                commands = {"X": cmd_x, "Y": cmd_y}
                commands[command](client)
            """
        )
        s1_x, s2_x = ccp.analyze_static(src, "X", language="python", verbose=False)
        s1_y, s2_y = ccp.analyze_static(src, "Y", language="python", verbose=False)
        for cmd, s1, s2 in [("X", s1_x, s2_x), ("Y", s1_y, s2_y)]:
            assert "url" in (s1 | s2) and "apikey" in (s1 | s2), (
                f"dict-dispatch + Client must fan out url/apikey to {cmd}. "
                f"scope_1={s1}, scope_2={s2}"
            )

    # ---- Case 17: bound receiver method call (Oracle-IAM pattern) ----
    def test_case17_bound_receiver_method_call(self) -> None:
        # OracleIAM-style pattern: build an ``iam_command`` object from
        # multiple bound params, then route per-command via
        # ``iam_command.update_user(client, args)``. The bound receiver
        # carries the params (mapper-out, create-user-enabled, …) and
        # those must surface for the dispatched command.
        src = textwrap.dedent(
            """
            import demistomock as demisto

            class IAMCommand:
                def __init__(self, *a, **kw): pass
                def update_user(self, client, args): pass
                def create_user(self, client, args): pass

            class Client: pass
            def fetch_incidents(client): pass

            def main():
                params = demisto.params()
                mapper_out = params.get("mapper-out")
                is_update = params.get("update_user_enabled")
                iam_command = IAMCommand(is_update, mapper_out)
                client = Client()
                args = demisto.args()
                command = demisto.command()
                if command == "iam-update-user":
                    iam_command.update_user(client, args)
                elif command == "iam-create-user":
                    iam_command.create_user(client, args)
                elif command == "fetch-incidents":
                    fetch_incidents(client)
            """
        )
        s1_up, s2_up = ccp.analyze_static(src, "iam-update-user", language="python", verbose=False)
        s1_cu, s2_cu = ccp.analyze_static(src, "iam-create-user", language="python", verbose=False)
        s1_fi, s2_fi = ccp.analyze_static(src, "fetch-incidents", language="python", verbose=False)
        # Both iam-* commands receive iam_command as the method receiver,
        # so its carried params must surface.
        for cmd, s1, s2 in [("iam-update-user", s1_up, s2_up), ("iam-create-user", s1_cu, s2_cu)]:
            assert "mapper-out" in (s1 | s2), (
                f"{cmd} must include mapper-out via bound receiver. "
                f"scope_1={s1}, scope_2={s2}"
            )
            assert "update_user_enabled" in (s1 | s2), (
                f"{cmd} must include update_user_enabled via bound receiver. "
                f"scope_1={s1}, scope_2={s2}"
            )
        # fetch-incidents only receives ``client`` — must NOT see the
        # iam_command receiver's params.
        assert "mapper-out" not in (s1_fi | s2_fi), (
            f"fetch-incidents must NOT include mapper-out (receiver not "
            f"used). scope_1={s1_fi}, scope_2={s2_fi}"
        )
        assert "update_user_enabled" not in (s1_fi | s2_fi), (
            f"fetch-incidents must NOT include update_user_enabled. "
            f"scope_1={s1_fi}, scope_2={s2_fi}"
        )


# =============================================================================
# AWS + Microsoft spot-check fixes (gaps #1–#5 from the validation report)
# =============================================================================
#
# Each ``test_gap_*`` below pins one of the analyzer gaps documented in
# ``check_command_params_validation_report.md`` (AWS + Microsoft
# spot-check section) to a minimal synthetic source so future
# regressions are caught at the unit-test layer rather than during a
# full-integration validation run.


class TestGap1HelperFunctionSharedClient:
    """Gap #1 — helper-function shared-client construction.

    Pattern (AWS-EC2): ``client = build_client(args)`` where
    ``build_client`` reads module-level ``PARAMS.get(...)`` for every
    credential. The original analyzer dropped all credential reads
    because ``_call_passes_params`` rejected the call (no params-shaped
    arg). The fix:

    * :func:`build_binding_maps` now recursively attributes the helper's
      param reads to the local being bound; and
    * :func:`trace_params_in_function` now recurses into helpers that
      read a known module-level params global directly.
    """

    def test_main_local_binding_recovers_helper_credentials(self) -> None:
        # Mirrors AWS-EC2: ``client = build_client(args)`` in main(),
        # then dispatch carries client to per-command handlers.
        src = textwrap.dedent(
            """
            import demistomock as demisto

            PARAMS = demisto.params()

            def build_client(args):
                ak = PARAMS.get("access_key")
                sk = PARAMS.get("secret_key")
                region = PARAMS.get("defaultRegion")
                return (ak, sk, region)

            def describe_instances(client, args): pass
            def create_instance(client, args): pass

            def main():
                client = build_client(demisto.args())
                command = demisto.command()
                if command == "aws-ec2-describe-instances":
                    describe_instances(client, demisto.args())
                elif command == "aws-ec2-create-instance":
                    create_instance(client, demisto.args())
            """
        )
        for cmd in ("aws-ec2-describe-instances", "aws-ec2-create-instance"):
            s1, s2 = ccp.analyze_static(src, cmd, language="python", verbose=False)
            merged = s1 | s2
            for required in ("access_key", "secret_key", "defaultRegion"):
                assert required in merged, (
                    f"{cmd}: helper-function recursion must surface "
                    f"{required!r}; got scope_1={s1}, scope_2={s2}"
                )

    def test_per_handler_recursion_into_helper(self) -> None:
        # Per-command handler calls ``build_client(args)`` directly. The
        # ``trace_params_in_function`` recursion gate must allow this even
        # though no params-shaped arg is passed.
        src = textwrap.dedent(
            """
            import demistomock as demisto

            PARAMS = demisto.params()

            def build_client(args):
                return PARAMS.get("apikey")

            def describe_instances(args):
                client = build_client(args)
                return client

            def main():
                command = demisto.command()
                if command == "aws-ec2-describe-instances":
                    describe_instances(demisto.args())
            """
        )
        s1, s2 = ccp.analyze_static(
            src, "aws-ec2-describe-instances", language="python", verbose=False
        )
        assert "apikey" in (s1 | s2), (
            f"per-handler recursion into build_client must surface 'apikey'; "
            f"scope_1={s1}, scope_2={s2}"
        )


class TestGap2BoolOpOrAliasChain:
    """Gap #2 — ``command == "X" or command == "Y"`` alias chains.

    Pattern (AWS-IAM): ``elif command == "aws-iam-update-access-key" or
    command == "aws-iam-access-key-update-quick-action": handler(...)``.
    The original analyzer matched only the first arm; the alias command
    silently received an empty param set.
    """

    def test_or_chain_attributes_both_arms(self) -> None:
        src = textwrap.dedent(
            """
            import demistomock as demisto

            class Client: pass
            def update_access_key(args, client): pass

            def main():
                params = demisto.params()
                client = Client()
                client.api_key = params.get("apikey")
                command = demisto.command()
                if command == "aws-iam-update-access-key" or command == "aws-iam-access-key-update-quick-action":
                    update_access_key(demisto.args(), client)
            """
        )
        for cmd in (
            "aws-iam-update-access-key",
            "aws-iam-access-key-update-quick-action",
        ):
            s1, s2 = ccp.analyze_static(src, cmd, language="python", verbose=False)
            assert "apikey" in (s1 | s2), (
                f"{cmd}: BoolOp(Or) arm must dispatch to the same handler; "
                f"scope_1={s1}, scope_2={s2}"
            )

    def test_or_chain_three_arms(self) -> None:
        # Three-way alias still attributes correctly (recursion).
        src = textwrap.dedent(
            """
            import demistomock as demisto

            class Client: pass
            def shared_handler(args, client): pass

            def main():
                params = demisto.params()
                client = Client()
                client.api_key = params.get("apikey")
                command = demisto.command()
                if command == "alpha" or command == "beta" or command == "gamma":
                    shared_handler(demisto.args(), client)
            """
        )
        for cmd in ("alpha", "beta", "gamma"):
            s1, s2 = ccp.analyze_static(src, cmd, language="python", verbose=False)
            assert "apikey" in (s1 | s2), (
                f"{cmd}: 3-arm BoolOp(Or) must attribute the shared handler; "
                f"scope_1={s1}, scope_2={s2}"
            )

    def test_and_chain_does_not_match(self) -> None:
        # An ``And`` of equality tests against different command literals
        # is unsatisfiable; ``_if_test_matches_command`` MUST NOT treat
        # it as a match. We verify this at the unit level rather than
        # via ``analyze_static`` because ``apikey`` would also leak via
        # Scope-1 fan-out from any pre-dispatch read — which is correct
        # behaviour, just not what this gap is about.
        tree = ast.parse(
            textwrap.dedent(
                """
                if command == "alpha" and command == "beta":
                    shared_handler()
                """
            )
        )
        if_node = tree.body[0]
        assert isinstance(if_node, ast.If)
        # Neither arm is matched — And of two different command literals
        # can never both hold.
        assert not ccp._if_test_matches_command(if_node.test, "alpha")
        assert not ccp._if_test_matches_command(if_node.test, "beta")


class TestNamedDictDispatch:
    """Regression: ``commands_with_args = {...}; if command in
    commands_with_args: return_results(commands_with_args[command](...))``
    is the AzureKeyVault dispatch shape. Without specific support, the
    flatten-pre-dispatch fix introduced for MDATP would silently
    regress AzureKeyVault to ``[]`` for every command (because
    pre-dispatch fan-out used to walk the entire ``Client(...)`` body
    inside the surrounding ``try:`` and emit Scope-1 noise that
    happened to cover the credentials).

    The fix: :func:`_collect_local_dict_assignments` discovers every
    local Dict assignment in main(), :func:`_find_in_dict_dispatch`
    treats any of them as a dispatch table, and
    :func:`find_command_dispatch_branches` /
    :func:`find_dict_dispatch_call_sites` accept membership tests and
    subscripts on those receivers.
    """

    def test_named_dict_membership_dispatch(self) -> None:
        # AzureKeyVault-shaped main(): client built inside try{}, named
        # dict tables, ``if command in <table>`` membership dispatch.
        src = textwrap.dedent(
            """
            import demistomock as demisto

            class Client:
                def __init__(self, *a, **kw): pass

            def get_key_command(client, args): pass
            def list_keys_command(client, args): pass

            def main():
                params = demisto.params()
                args = demisto.args()
                command = demisto.command()
                try:
                    client = Client(
                        tenant_id=params.get("tenant_id"),
                        client_id=params.get("client_id"),
                    )
                    commands_with_args = {
                        "azure-key-vault-key-get": get_key_command,
                        "azure-key-vault-key-list": list_keys_command,
                    }
                    if command in commands_with_args:
                        commands_with_args[command](client, args)
                except Exception:
                    pass
            """
        )
        for cmd in ("azure-key-vault-key-get", "azure-key-vault-key-list"):
            s1, s2 = ccp.analyze_static(
                src, cmd, language="python", verbose=False
            )
            merged = s1 | s2
            for required in ("tenant_id", "client_id"):
                assert required in merged, (
                    f"{cmd}: named-dict dispatch must surface {required!r} "
                    f"via the bound client; scope_1={s1}, scope_2={s2}"
                )

    def test_canonical_commands_dict_still_works(self) -> None:
        # Legacy MongoDB shape — the canonical ``commands = {...};
        # commands[command](...)`` dispatch must keep working after the
        # generalisation.
        src = textwrap.dedent(
            """
            import demistomock as demisto

            class Client:
                def __init__(self, *a, **kw): pass

            def list_collections_command(client, args): pass

            def main():
                params = demisto.params()
                args = demisto.args()
                command = demisto.command()
                client = Client(url=params.get("url"))
                commands = {
                    "mongodb-list-collections": list_collections_command,
                }
                commands[command](client, **args)
            """
        )
        s1, s2 = ccp.analyze_static(
            src, "mongodb-list-collections", language="python", verbose=False
        )
        assert "url" in (s1 | s2), (
            f"canonical commands-dict must still propagate url; "
            f"scope_1={s1}, scope_2={s2}"
        )


class TestGap3FindIntegrationFilesPicker:
    """Gap #3 — :func:`find_integration_files` picks stub files.

    The unsorted ``Path.glob("*.py")`` could pick ``demistomock.py`` or
    other accidentally-committed shared-tooling modules first. The fix
    adds a deny-list and prefers the .py whose stem matches the
    directory name (the demisto-sdk convention).
    """

    def test_deny_list_skips_demistomock(self, tmp_path: Path) -> None:
        d = tmp_path / "MyIntegration"
        d.mkdir()
        (d / "MyIntegration.yml").write_text("name: MyIntegration\n", encoding="utf-8")
        (d / "demistomock.py").write_text("# stub\n", encoding="utf-8")
        (d / "MyIntegration.py").write_text("def main(): pass\n", encoding="utf-8")
        yml, py = ccp.find_integration_files(d)
        assert py is not None
        assert py.name == "MyIntegration.py"

    def test_prefers_dirname_match(self, tmp_path: Path) -> None:
        # Multiple .py files; one matches the directory name. Picker
        # must prefer that one over alphabetically-earlier candidates.
        d = tmp_path / "MyIntegration"
        d.mkdir()
        (d / "MyIntegration.yml").write_text("name: MyIntegration\n", encoding="utf-8")
        (d / "AAhelpers.py").write_text("# helper\n", encoding="utf-8")
        (d / "MyIntegration.py").write_text("def main(): pass\n", encoding="utf-8")
        yml, py = ccp.find_integration_files(d)
        assert py is not None
        assert py.name == "MyIntegration.py"

    def test_skips_apimodule_files(self, tmp_path: Path) -> None:
        # ``MicrosoftApiModule.py`` is shared tooling; must not be
        # picked even though its name doesn't appear in the deny-list.
        d = tmp_path / "AzureFoo"
        d.mkdir()
        (d / "AzureFoo.yml").write_text("name: AzureFoo\n", encoding="utf-8")
        (d / "MicrosoftApiModule.py").write_text("# shared\n", encoding="utf-8")
        (d / "AzureFoo.py").write_text("def main(): pass\n", encoding="utf-8")
        yml, py = ccp.find_integration_files(d)
        assert py is not None
        assert py.name == "AzureFoo.py"

    def test_alphabetical_fallback_is_deterministic(self, tmp_path: Path) -> None:
        # Two unrelated .py files, neither matches dir/yml stems. Picker
        # must return the alphabetically-first one (deterministic
        # tie-break — no longer dependent on filesystem iteration order).
        d = tmp_path / "Foo"
        d.mkdir()
        (d / "Foo.yml").write_text("name: Foo\n", encoding="utf-8")
        (d / "zeta.py").write_text("# z\n", encoding="utf-8")
        (d / "alpha.py").write_text("# a\n", encoding="utf-8")
        yml, py = ccp.find_integration_files(d)
        assert py is not None
        assert py.name == "alpha.py"


class TestGap4MdatpAssignTryWrapped:
    """Gap #4 — pre-dispatch ``client = MsClient(...)`` assignment is
    wrapped in a ``try:`` block (MDATP shape). The original
    :func:`build_binding_maps` only iterated ``main_fn.body`` flat, so
    bindings nested inside the ``try`` were never recorded.

    The fix flattens compound constructs (``Try``, ``With``, ``If``)
    via :func:`_iter_pre_dispatch_stmts` so these bindings are
    recovered.
    """

    def test_or_chain_assign_inside_try(self) -> None:
        # MDATP textbook shape: locals bound to ``params.get("X") or
        # params.get("Y") or params.get("Z", {}).get("password")``,
        # then ``client = MsClient(tenant_id=tenant_id, ...)``, then
        # dispatch — ALL inside a ``try:`` block.
        src = textwrap.dedent(
            """
            import demistomock as demisto

            class MsClient:
                def __init__(self, *a, **kw): pass

            def get_machine_by_ip_command(client, args): pass
            def fetch_incidents(client): pass

            def main():
                params = demisto.params()
                tenant_id = params.get("tenant_id") or params.get("_tenant_id")
                auth_id = params.get("_auth_id") or params.get("auth_id")
                enc_key = (params.get("credentials") or {}).get("password") or params.get("enc_key")
                command = demisto.command()
                args = demisto.args()
                try:
                    client = MsClient(
                        tenant_id=tenant_id,
                        auth_id=auth_id,
                        enc_key=enc_key,
                    )
                    if command == "microsoft-atp-get-machine-by-ip":
                        get_machine_by_ip_command(client, args)
                    elif command == "fetch-incidents":
                        fetch_incidents(client)
                except Exception:
                    pass
            """
        )
        for cmd in ("microsoft-atp-get-machine-by-ip", "fetch-incidents"):
            s1, s2 = ccp.analyze_static(src, cmd, language="python", verbose=False)
            merged = s1 | s2
            for required in ("tenant_id", "auth_id", "enc_key", "credentials"):
                assert required in merged, (
                    f"{cmd}: pre-dispatch binding inside try{{}} must "
                    f"propagate {required!r} via client; "
                    f"scope_1={s1}, scope_2={s2}"
                )

    def test_with_block_pre_dispatch(self) -> None:
        # Sanity check: ``with`` blocks should also be flattened (some
        # integrations wrap the dispatch in a ``with logging_context():``).
        src = textwrap.dedent(
            """
            import demistomock as demisto

            class Client:
                def __init__(self, *a, **kw): pass

            def handler(client): pass

            def main():
                params = demisto.params()
                api_key = params.get("apikey")
                command = demisto.command()
                with open("/dev/null") as _f:
                    client = Client(api_key=api_key)
                    if command == "do-thing":
                        handler(client)
            """
        )
        s1, s2 = ccp.analyze_static(src, "do-thing", language="python", verbose=False)
        assert "apikey" in (s1 | s2), (
            f"with-wrapped pre-dispatch binding must propagate apikey; "
            f"scope_1={s1}, scope_2={s2}"
        )


class TestGap5CaptureProxyBypassedLimitation:
    """Gap #5 — boto3 / botocore HTTP traffic bypasses the capture proxy.

    The analyzer detects this via static import inspection and tags every
    per-command diagnostic with
    ``limitation: "capture_proxy_bypassed"`` so the calling agent knows
    Hybrid Scope-1 narrowing won't fire and the static union must be
    cross-checked manually.
    """

    def test_detects_bare_boto3_import(self) -> None:
        src = "import boto3\n"
        assert ccp.integration_uses_proxy_bypass(src)

    def test_detects_botocore_import(self) -> None:
        src = "from botocore.config import Config\n"
        assert ccp.integration_uses_proxy_bypass(src)

    def test_detects_boto3_submodule(self) -> None:
        src = "import boto3.session\n"
        assert ccp.integration_uses_proxy_bypass(src)

    def test_detects_awsapimodule(self) -> None:
        # AWS-EC2 / AWS-IAM / etc. only do ``from AWSApiModule import *``
        # — boto3 itself is imported transitively after prepare-content
        # unifies the source. The detector must still fire so every AWS
        # command's diagnostic carries the limitation tag.
        src = "from AWSApiModule import *\n"
        assert ccp.integration_uses_proxy_bypass(src)

    def test_no_bypass_for_normal_integration(self) -> None:
        src = textwrap.dedent(
            """
            import requests
            from CommonServerPython import *
            def main(): pass
            """
        )
        assert not ccp.integration_uses_proxy_bypass(src)

    def test_safely_handles_empty_or_unparseable(self) -> None:
        # Empty source -> False, no exception.
        assert not ccp.integration_uses_proxy_bypass("")
        # Real syntax error -> False, no exception.
        assert not ccp.integration_uses_proxy_bypass("def main(:\n")

    def test_diagnostic_serializes_limitation(self) -> None:
        diag = ccp.CommandDiagnostic(
            status="ok_no_capture",
            captured_requests=0,
            limitation=ccp.LIMITATION_CAPTURE_PROXY_BYPASSED,
        )
        out = diag.to_dict()
        assert out["limitation"] == ccp.LIMITATION_CAPTURE_PROXY_BYPASSED

    def test_diagnostic_omits_limitation_when_none(self) -> None:
        diag = ccp.CommandDiagnostic(status="ok_no_capture", captured_requests=0)
        out = diag.to_dict()
        assert "limitation" not in out

    def test_merge_does_not_narrow_when_no_capture(self) -> None:
        # Regression guard for the boto3 case: when captured_requests=0
        # (the universal AWS-family outcome), narrowing MUST NOT fire —
        # otherwise we'd zero out the per-command static surface.
        diag = ccp.CommandDiagnostic(
            status="ok_no_capture",
            captured_requests=0,
            limitation=ccp.LIMITATION_CAPTURE_PROXY_BYPASSED,
        )
        out = ccp._merge_command_params(
            "x",
            ({"access_key", "secret_key"}, set()),
            set(),
            diag,
        )
        assert out == {"access_key", "secret_key"}, (
            f"narrowing must NOT fire when captured_requests=0; got {out}"
        )
        assert not diag.scope_1_narrowed


# =============================================================================
# Auth-aware ignore composition (--integration-id flag → compose_ignore_set)
# =============================================================================


class TestComposeIgnoreSetAuthAware:
    """Smoke tests for the new ``compose_ignore_set`` helper.

    The composition surface is the unit-test seam. We mock
    ``workflow_state.auth_param_ids`` so we don't depend on the live CSV
    or spin up Docker. Three cases are covered:

    1. File-only path (no integration id) — backward compat.
    2. ``--integration-id`` supplied AND auth-aware pull succeeds —
       result is the union; stderr logs the pulled list.
    3. ``--integration-id`` supplied AND auth-aware pull fails (e.g.
       Auth Details unset / integration not in CSV) — analyzer keeps
       running with file-based ignore only; stderr logs a WARNING.
    """

    def test_no_integration_id_is_file_only(
        self, tmp_path: Path, capsys
    ) -> None:
        ignore_file = tmp_path / "ignore.txt"
        ignore_file.write_text("url\nproxy\n# a comment\ninsecure\n")
        result = ccp.compose_ignore_set(
            inline=None,
            file_path=ignore_file,
            integration_id=None,
        )
        assert result == {"url", "proxy", "insecure"}
        # No auth-aware log line emitted when no integration id.
        err = capsys.readouterr().err
        assert "Auth-aware ignore" not in err

    def test_integration_id_unions_file_and_auth_pulled(
        self, tmp_path: Path, monkeypatch, capsys
    ) -> None:
        ignore_file = tmp_path / "ignore.txt"
        ignore_file.write_text("url\nproxy\n")

        # Patch ``workflow_state.auth_param_ids`` *as imported by*
        # ``compose_ignore_set`` (the lazy ``from workflow_state
        # import auth_param_ids`` happens inside the function body).
        import workflow_state as ws

        monkeypatch.setattr(
            ws,
            "auth_param_ids",
            lambda integration_id: ["api_key", "credentials"],
        )

        result = ccp.compose_ignore_set(
            inline=["explicit_param"],
            file_path=ignore_file,
            integration_id="MyIntegration",
        )
        # Union of inline + file + auth-pulled.
        assert result == {
            "explicit_param", "url", "proxy", "api_key", "credentials",
        }
        err = capsys.readouterr().err
        # Single-line, comma-separated stderr log.
        assert "Auth-aware ignore" in err
        assert "MyIntegration" in err
        assert "api_key" in err
        assert "credentials" in err

    def test_integration_id_with_workflow_error_falls_back_gracefully(
        self, tmp_path: Path, monkeypatch, capsys
    ) -> None:
        ignore_file = tmp_path / "ignore.txt"
        ignore_file.write_text("url\nproxy\n")

        import workflow_state as ws

        def _raise(integration_id):
            raise ws.WorkflowError(
                f"'Auth Details' is not set for integration '{integration_id}'."
            )

        monkeypatch.setattr(ws, "auth_param_ids", _raise)

        # Must NOT crash — analyzer must remain runnable on
        # integrations that haven't been classified yet.
        result = ccp.compose_ignore_set(
            inline=None,
            file_path=ignore_file,
            integration_id="UnclassifiedIntegration",
        )
        assert result == {"url", "proxy"}
        err = capsys.readouterr().err
        assert "WARNING" in err
        assert "UnclassifiedIntegration" in err
        assert "Auth Details" in err

    def test_integration_id_with_empty_auth_pull_logs_zero(
        self, tmp_path: Path, monkeypatch, capsys
    ) -> None:
        ignore_file = tmp_path / "ignore.txt"
        ignore_file.write_text("url\n")

        import workflow_state as ws

        monkeypatch.setattr(ws, "auth_param_ids", lambda integration_id: [])
        result = ccp.compose_ignore_set(
            inline=None,
            file_path=ignore_file,
            integration_id="SomeIntegration",
        )
        assert result == {"url"}
        err = capsys.readouterr().err
        assert "Auth-aware ignore" in err
        assert "0 params" in err

    def test_argparse_wires_integration_id_flag(self) -> None:
        ns = ccp._parse_args([
            "/tmp/some_path",
            "--integration-id", "MyIntegration",
        ])
        assert ns.integration_id == "MyIntegration"

    def test_argparse_default_integration_id_is_none(self) -> None:
        # Backward compat: omitting the flag keeps the existing
        # standalone-script behaviour intact.
        ns = ccp._parse_args(["/tmp/some_path"])
        assert ns.integration_id is None


# ============================================================================
# Change #1: hidden-param exclusion (is_hidden_param + get_yml_params filter)
# ============================================================================


class TestIsHiddenParam:
    """Edge-case coverage for the YML 'hidden:' rule.

    A param is hidden iff ``hidden: True`` OR ``hidden: <non-empty list>``.
    All other shapes (false, [], None, missing, scalar string, etc.) are
    NOT hidden. Per-platform list interpretation is intentionally not
    attempted — the rule is "hidden anywhere → excluded entirely".
    """

    def test_hidden_true_boolean(self) -> None:
        assert ccp.is_hidden_param({"name": "x", "hidden": True}) is True

    def test_hidden_false_boolean(self) -> None:
        assert ccp.is_hidden_param({"name": "x", "hidden": False}) is False

    def test_hidden_missing_key(self) -> None:
        assert ccp.is_hidden_param({"name": "x"}) is False

    def test_hidden_none_value(self) -> None:
        # YAML ``hidden:`` with no value parses as None.
        assert ccp.is_hidden_param({"name": "x", "hidden": None}) is False

    def test_hidden_empty_list(self) -> None:
        # Empty list = "hidden on no platforms" = NOT hidden.
        assert ccp.is_hidden_param({"name": "x", "hidden": []}) is False

    def test_hidden_single_platform_list(self) -> None:
        assert ccp.is_hidden_param({"name": "x", "hidden": ["xsoar"]}) is True

    def test_hidden_multi_platform_list(self) -> None:
        assert ccp.is_hidden_param(
            {"name": "x", "hidden": ["marketplacev2", "platform"]}
        ) is True

    def test_hidden_string_value_not_hidden(self) -> None:
        # A bare string like ``hidden: "true"`` is NEITHER True NOR a
        # non-empty list — we treat it as NOT hidden (the YML is
        # malformed; conservatively keep the param visible so analysis
        # still runs).
        assert ccp.is_hidden_param({"name": "x", "hidden": "true"}) is False

    def test_non_dict_input_returns_false(self) -> None:
        assert ccp.is_hidden_param("not a dict") is False  # type: ignore[arg-type]
        assert ccp.is_hidden_param(None) is False  # type: ignore[arg-type]


class TestGetYmlParamsFiltersHidden:
    def test_visible_only(self) -> None:
        yml = {"configuration": [
            {"name": "url"},
            {"name": "secret_token", "hidden": True},
            {"name": "advanced_xsoar_only", "hidden": ["xsoar"]},
            {"name": "kept_explicit_false", "hidden": False},
        ]}
        names = [p["name"] for p in ccp.get_yml_params(yml)]
        assert names == ["url", "kept_explicit_false"]

    def test_get_yml_params_raw_keeps_hidden(self) -> None:
        yml = {"configuration": [
            {"name": "url"},
            {"name": "secret_token", "hidden": True},
        ]}
        names = [p["name"] for p in ccp.get_yml_params_raw(yml)]
        assert names == ["url", "secret_token"]

    def test_get_hidden_param_names_sorted(self) -> None:
        yml = {"configuration": [
            {"name": "z_secret", "hidden": True},
            {"name": "url"},
            {"name": "a_secret", "hidden": ["xsoar"]},
        ]}
        assert ccp.get_hidden_param_names(yml) == ["a_secret", "z_secret"]

    def test_no_hidden_returns_empty_list(self) -> None:
        yml = {"configuration": [{"name": "url"}, {"name": "port"}]}
        assert ccp.get_hidden_param_names(yml) == []


# ============================================================================
# Change #2: cert/key/thumbprint sentinel coercion + --seed-param override
# ============================================================================


class TestCoerceSentinelForParam:
    """Each of the 3 patterns + a name that matches none + ordering edges."""

    def test_thumbprint_match(self) -> None:
        out = ccp.coerce_sentinel_for_param("certificate_thumbprint")
        assert out is not None
        value, pattern = out
        assert pattern == "thumbprint"
        # 40 hex chars satisfies binascii.a2b_hex.
        assert len(value) == 40
        assert all(c in "0123456789ABCDEFabcdef" for c in value)

    def test_thumbprint_match_case_insensitive(self) -> None:
        out = ccp.coerce_sentinel_for_param("CertificateThumbprint")
        assert out is not None and out[1] == "thumbprint"

    def test_private_key_match(self) -> None:
        out = ccp.coerce_sentinel_for_param("private_key")
        assert out is not None
        value, pattern = out
        assert pattern == "private_key"
        assert "BEGIN PRIVATE KEY" in value
        assert "END PRIVATE KEY" in value

    def test_certificate_match_falls_through_thumbprint(self) -> None:
        # 'certificate' alone (no 'thumbprint') maps to PEM cert.
        out = ccp.coerce_sentinel_for_param("auth_certificate")
        assert out is not None
        value, pattern = out
        assert pattern == "certificate"
        assert "BEGIN CERTIFICATE" in value

    def test_overlap_thumbprint_wins_over_certificate(self) -> None:
        # 'certificate_thumbprint' contains both 'thumbprint' AND
        # 'certificate' — thumbprint wins (checked first).
        out = ccp.coerce_sentinel_for_param("certificate_thumbprint")
        assert out is not None and out[1] == "thumbprint"

    def test_overlap_private_key_wins_over_certificate(self) -> None:
        out = ccp.coerce_sentinel_for_param("private_key_certificate")
        assert out is not None and out[1] == "private_key"

    def test_no_match_returns_none(self) -> None:
        assert ccp.coerce_sentinel_for_param("server_url") is None
        assert ccp.coerce_sentinel_for_param("api_token") is None
        assert ccp.coerce_sentinel_for_param("port") is None

    def test_empty_or_invalid_input_returns_none(self) -> None:
        assert ccp.coerce_sentinel_for_param("") is None
        assert ccp.coerce_sentinel_for_param(None) is None  # type: ignore[arg-type]


class TestBuildParamValuesCoercion:
    def test_thumbprint_coerced_by_default(self) -> None:
        params = [{"name": "certificate_thumbprint",
                   "type": ccp.YML_TYPE_ENCRYPTED}]
        values, sentinels, non_traceable = ccp.build_param_values(
            params, "http://x", set()
        )
        # Coerced value, NOT the generic SENTINEL_PARAM_<name> string.
        assert values["certificate_thumbprint"] != (
            ccp.SENTINEL_PREFIX + "certificate_thumbprint"
        )
        assert len(values["certificate_thumbprint"]) == 40
        # Coerced values are non-traceable (they don't carry the sentinel
        # substring so detect_sentinel_hits cannot find them by name).
        assert "certificate_thumbprint" in non_traceable
        assert sentinels["certificate_thumbprint"] == []

    def test_private_key_coerced_by_default(self) -> None:
        params = [{"name": "private_key", "type": ccp.YML_TYPE_ENCRYPTED}]
        values, _, _ = ccp.build_param_values(params, "http://x", set())
        assert "BEGIN PRIVATE KEY" in values["private_key"]

    def test_certificate_coerced_by_default(self) -> None:
        params = [{"name": "certificate", "type": ccp.YML_TYPE_ENCRYPTED}]
        values, _, _ = ccp.build_param_values(params, "http://x", set())
        assert "BEGIN CERTIFICATE" in values["certificate"]

    def test_coerce_certs_false_uses_generic_sentinel(self) -> None:
        params = [{"name": "private_key", "type": ccp.YML_TYPE_ENCRYPTED}]
        values, sentinels, _ = ccp.build_param_values(
            params, "http://x", set(), coerce_certs=False
        )
        # With coercion off, the generic sentinel comes through.
        assert values["private_key"] == ccp.SENTINEL_PREFIX + "private_key"
        assert sentinels["private_key"] == [ccp.SENTINEL_PREFIX + "private_key"]

    def test_yml_default_value_wins_over_coercion(self) -> None:
        # An operator who hard-codes a real test cert in the YML
        # defaultvalue must still get it — coercion only runs when
        # there's no YML default to honour.
        params = [{
            "name": "certificate_thumbprint",
            "type": ccp.YML_TYPE_ENCRYPTED,
            "defaultvalue": "ABCDEF1234567890ABCDEF1234567890ABCDEF12",
        }]
        values, _, _ = ccp.build_param_values(params, "http://x", set())
        assert values["certificate_thumbprint"] == (
            "ABCDEF1234567890ABCDEF1234567890ABCDEF12"
        )

    def test_unrelated_param_not_coerced(self) -> None:
        params = [{"name": "some_text"}]
        values, _, _ = ccp.build_param_values(params, "http://x", set())
        assert values["some_text"] == ccp.SENTINEL_PREFIX + "some_text"


class TestSeedOverrides:
    def test_override_replaces_generic_sentinel(self) -> None:
        params = [{"name": "api_token"}]
        values, sentinels, _ = ccp.build_param_values(
            params,
            "http://x",
            set(),
            seed_overrides={"api_token": "my-real-test-token-12345"},
        )
        assert values["api_token"] == "my-real-test-token-12345"
        # Long enough to be traceable as an ad-hoc sentinel.
        assert sentinels["api_token"] == ["my-real-test-token-12345"]

    def test_override_wins_over_yml_default(self) -> None:
        params = [{"name": "api_token", "defaultvalue": "yml-default-value"}]
        values, _, _ = ccp.build_param_values(
            params, "http://x", set(),
            seed_overrides={"api_token": "operator-override"},
        )
        assert values["api_token"] == "operator-override"

    def test_override_wins_over_cert_coercion(self) -> None:
        params = [{"name": "private_key", "type": ccp.YML_TYPE_ENCRYPTED}]
        values, _, _ = ccp.build_param_values(
            params, "http://x", set(),
            seed_overrides={"private_key": "REAL-KEY-PEM-CONTENT"},
        )
        assert values["private_key"] == "REAL-KEY-PEM-CONTENT"

    def test_override_wins_over_url_proxy(self) -> None:
        params = [{"name": "url"}]
        values, _, _ = ccp.build_param_values(
            params, "http://proxy:9999", set(),
            seed_overrides={"url": "https://override.example"},
        )
        # Operator can opt out of the proxy redirect for one param.
        assert values["url"] == "https://override.example"

    def test_override_short_value_marked_non_traceable(self) -> None:
        params = [{"name": "x"}]
        values, sentinels, non_traceable = ccp.build_param_values(
            params, "http://x", set(),
            seed_overrides={"x": "ab"},  # < 4 chars
        )
        assert values["x"] == "ab"
        assert sentinels["x"] == []
        assert "x" in non_traceable

    def test_override_for_unmentioned_param_is_ignored(self) -> None:
        # Override targets a name not in yml_params — not an error here
        # (the visibility warning lives in analyze_integration); the
        # builder simply doesn't seed anything for it.
        params = [{"name": "real_param"}]
        values, _, _ = ccp.build_param_values(
            params, "http://x", set(),
            seed_overrides={"unknown_param": "value"},
        )
        assert "unknown_param" not in values

    def test_no_overrides_falls_back_to_default_behaviour(self) -> None:
        params = [{"name": "api_token"}]
        values, _, _ = ccp.build_param_values(
            params, "http://x", set(), seed_overrides=None
        )
        assert values["api_token"] == ccp.SENTINEL_PREFIX + "api_token"


class TestCredentialsSeedOverride:
    """Dotted-leaf ``--seed-param`` support for YML type:9 credentials."""

    def test_dotted_leaf_password_only(self) -> None:
        """Seeding only the password leaf substitutes it; identifier
        keeps its sentinel default."""
        params = [{"name": "creds", "type": ccp.YML_TYPE_CREDENTIALS}]
        values, sentinels, _ = ccp.build_param_values(
            params, "http://x", set(),
            seed_overrides={"creds.password": "my-real-password-12345"},
        )
        assert isinstance(values["creds"], dict)
        # Identifier stays at its sentinel default.
        assert values["creds"]["identifier"] == (
            ccp.SENTINEL_PREFIX + "creds_identifier"
        )
        # Password is the operator-supplied value.
        assert values["creds"]["password"] == "my-real-password-12345"
        # Both values are tracked (each >= 4 chars).
        assert ccp.SENTINEL_PREFIX + "creds_identifier" in sentinels["creds"]
        assert "my-real-password-12345" in sentinels["creds"]

    def test_dotted_leaf_identifier_only(self) -> None:
        """Seeding only the identifier leaf substitutes it; password
        keeps its sentinel default."""
        params = [{"name": "creds", "type": ccp.YML_TYPE_CREDENTIALS}]
        values, _, _ = ccp.build_param_values(
            params, "http://x", set(),
            seed_overrides={"creds.identifier": "stub@example.com"},
        )
        assert values["creds"]["identifier"] == "stub@example.com"
        assert values["creds"]["password"] == (
            ccp.SENTINEL_PREFIX + "creds_password"
        )

    def test_dotted_leaf_both_leaves(self) -> None:
        """Both leaves overridden — neither sentinel default is used."""
        params = [{"name": "user_creds", "type": ccp.YML_TYPE_CREDENTIALS}]
        values, sentinels, _ = ccp.build_param_values(
            params, "http://x", set(),
            seed_overrides={
                "user_creds.identifier": "user@example.com",
                "user_creds.password": '{"key":"value"}',
            },
        )
        assert values["user_creds"] == {
            "identifier": "user@example.com",
            "password": '{"key":"value"}',
        }
        assert "user@example.com" in sentinels["user_creds"]
        assert '{"key":"value"}' in sentinels["user_creds"]

    def test_dotted_leaf_short_value_not_traced(self) -> None:
        """A leaf override < 4 chars is non-traceable (same convention
        as the flat short-override branch)."""
        params = [{"name": "creds", "type": ccp.YML_TYPE_CREDENTIALS}]
        values, sentinels, _ = ccp.build_param_values(
            params, "http://x", set(),
            seed_overrides={"creds.password": "ab"},
        )
        assert values["creds"]["password"] == "ab"
        # The short override is NOT in the sentinel token list.
        assert "ab" not in sentinels["creds"]
        # But the (unseeded) identifier default still is.
        assert ccp.SENTINEL_PREFIX + "creds_identifier" in sentinels["creds"]

    def test_dotted_leaf_with_unknown_parent_silently_skipped(self) -> None:
        """When the dotted-leaf parent isn't a YML param at all, the
        credentials branch never runs for it (the parent never appears
        in yml_params). The override is effectively a no-op here —
        the WARNING is logged at the call site in analyze_integration."""
        params = [{"name": "real_creds", "type": ccp.YML_TYPE_CREDENTIALS}]
        values, _, _ = ccp.build_param_values(
            params, "http://x", set(),
            seed_overrides={"ghost.password": "wont-apply"},
        )
        # `real_creds` keeps its default sentinel shape.
        assert values["real_creds"] == {
            "identifier": ccp.SENTINEL_PREFIX + "real_creds_identifier",
            "password": ccp.SENTINEL_PREFIX + "real_creds_password",
        }
        # `ghost` is not in values.
        assert "ghost" not in values

    def test_flat_override_on_credentials_param_raises(self) -> None:
        """Flat NAME=VALUE on a type:9 credentials param raises with
        an actionable error pointing at the dotted-leaf form."""
        params = [{"name": "user_creds", "type": ccp.YML_TYPE_CREDENTIALS}]
        with pytest.raises(ValueError, match="credentials widget"):
            ccp.build_param_values(
                params, "http://x", set(),
                seed_overrides={"user_creds": '{"identifier":"x"}'},
            )

    def test_flat_override_error_mentions_dotted_form(self) -> None:
        """The error message explicitly tells the user the right form."""
        params = [{"name": "user_creds", "type": ccp.YML_TYPE_CREDENTIALS}]
        with pytest.raises(ValueError) as excinfo:
            ccp.build_param_values(
                params, "http://x", set(),
                seed_overrides={"user_creds": "x"},
            )
        msg = str(excinfo.value)
        assert "user_creds.identifier" in msg
        assert "user_creds.password" in msg

    def test_flat_override_on_non_credentials_still_works(self) -> None:
        """The credentials-shape protection ONLY fires for type:9 —
        flat overrides on type:4 (encrypted) and similar still work."""
        params = [{"name": "api_key", "type": ccp.YML_TYPE_ENCRYPTED}]
        values, _, _ = ccp.build_param_values(
            params, "http://x", set(),
            seed_overrides={"api_key": "operator-override-value"},
        )
        assert values["api_key"] == "operator-override-value"


class TestCredentialsCertCoercion:
    """Per-leaf cert/key/thumbprint coercion for YML type:9 credentials
    widgets. Prevents a flat coerced PEM string from clobbering the dict
    shape that integration consumers (``params.get(name, {}).get(...)``)
    rely on.
    """

    def test_creds_certificate_gets_per_leaf_coercion(self) -> None:
        """A type:9 widget named with 'certificate' substring should
        keep its dict shape AND get cert-stub values per leaf."""
        params = [{"name": "creds_certificate", "type": ccp.YML_TYPE_CREDENTIALS}]
        values, sentinels, non_traceable = ccp.build_param_values(
            params, "http://x", set(),
        )
        # Dict shape preserved.
        assert isinstance(values["creds_certificate"], dict)
        assert set(values["creds_certificate"]) == {"identifier", "password"}
        # Identifier got the thumbprint stub (40-char hex).
        assert values["creds_certificate"]["identifier"] == (
            ccp._COERCED_THUMBPRINT_VALUE
        )
        # Password got the PEM stub.
        assert values["creds_certificate"]["password"] == (
            ccp._COERCED_PRIVATE_KEY_VALUE
        )
        # Both coerced leaves are non-traceable (no SENTINEL_PARAM
        # substring) — sentinel list is empty.
        assert sentinels["creds_certificate"] == []
        assert "creds_certificate" in non_traceable

    def test_creds_certificate_disabled_via_coerce_certs_false(self) -> None:
        """When --no-sentinel-coercion is set, even type:9 cert-named
        widgets keep their default sentinel leaves (no coercion)."""
        params = [{"name": "creds_certificate", "type": ccp.YML_TYPE_CREDENTIALS}]
        values, sentinels, _ = ccp.build_param_values(
            params, "http://x", set(), coerce_certs=False,
        )
        assert values["creds_certificate"]["identifier"] == (
            ccp.SENTINEL_PREFIX + "creds_certificate_identifier"
        )
        assert values["creds_certificate"]["password"] == (
            ccp.SENTINEL_PREFIX + "creds_certificate_password"
        )
        # Both default sentinels are traceable.
        assert len(sentinels["creds_certificate"]) == 2

    def test_operator_override_wins_over_cert_coercion(self) -> None:
        """A dotted-leaf operator override should win over the per-leaf
        cert coercion for that specific leaf. The unseeded leaf still
        gets coerced."""
        params = [{"name": "creds_certificate", "type": ccp.YML_TYPE_CREDENTIALS}]
        values, _, _ = ccp.build_param_values(
            params, "http://x", set(),
            seed_overrides={"creds_certificate.password": "MY-REAL-PEM-12345"},
        )
        # Operator value wins for password.
        assert values["creds_certificate"]["password"] == "MY-REAL-PEM-12345"
        # Identifier still gets the thumbprint stub.
        assert values["creds_certificate"]["identifier"] == (
            ccp._COERCED_THUMBPRINT_VALUE
        )

    def test_non_cert_credentials_widget_uses_plain_sentinels(self) -> None:
        """A type:9 widget whose name doesn't match cert/key/thumbprint
        keeps its plain sentinel leaves (no coercion)."""
        params = [{"name": "user_creds", "type": ccp.YML_TYPE_CREDENTIALS}]
        values, sentinels, _ = ccp.build_param_values(
            params, "http://x", set(),
        )
        assert values["user_creds"]["identifier"] == (
            ccp.SENTINEL_PREFIX + "user_creds_identifier"
        )
        assert values["user_creds"]["password"] == (
            ccp.SENTINEL_PREFIX + "user_creds_password"
        )
        assert len(sentinels["user_creds"]) == 2


class TestParseSeedOverrides:
    def test_simple_pair(self) -> None:
        out = ccp.parse_seed_overrides(["foo=bar"])
        assert out == {"foo": "bar"}

    def test_multiple_pairs(self) -> None:
        out = ccp.parse_seed_overrides(["a=1", "b=two"])
        assert out == {"a": "1", "b": "two"}

    def test_value_can_contain_equals(self) -> None:
        # Only the first '=' splits; the value keeps the rest verbatim
        # (so PEM blocks / base64 with padding work).
        out = ccp.parse_seed_overrides(["pem=---BEGIN==DATA==END---"])
        assert out == {"pem": "---BEGIN==DATA==END---"}

    def test_empty_value_allowed(self) -> None:
        # Operator explicitly seeding an empty value (e.g. to satisfy
        # an integration that requires the key but tolerates "").
        out = ccp.parse_seed_overrides(["key="])
        assert out == {"key": ""}

    def test_none_or_empty_returns_empty_dict(self) -> None:
        assert ccp.parse_seed_overrides(None) == {}
        assert ccp.parse_seed_overrides([]) == {}

    def test_missing_separator_raises(self) -> None:
        with pytest.raises(ValueError, match="missing '=' separator"):
            ccp.parse_seed_overrides(["just_a_name"])

    def test_empty_name_raises(self) -> None:
        with pytest.raises(ValueError, match="empty NAME"):
            ccp.parse_seed_overrides(["=value"])

    def test_duplicate_name_raises(self) -> None:
        with pytest.raises(ValueError, match="more than once"):
            ccp.parse_seed_overrides(["foo=1", "foo=2"])


class TestNewCliFlags:
    def test_no_sentinel_coercion_default_false(self) -> None:
        ns = ccp._parse_args(["/tmp/x"])
        assert ns.no_sentinel_coercion is False

    def test_no_sentinel_coercion_when_set(self) -> None:
        ns = ccp._parse_args(["/tmp/x", "--no-sentinel-coercion"])
        assert ns.no_sentinel_coercion is True

    def test_auto_retry_integration_docker_default_true(self) -> None:
        ns = ccp._parse_args(["/tmp/x"])
        assert ns.auto_retry_integration_docker is True

    def test_no_auto_retry_integration_docker_disables(self) -> None:
        ns = ccp._parse_args(["/tmp/x", "--no-auto-retry-integration-docker"])
        assert ns.auto_retry_integration_docker is False

    def test_seed_param_default_none(self) -> None:
        ns = ccp._parse_args(["/tmp/x"])
        assert ns.seed_param is None

    def test_seed_param_repeatable(self) -> None:
        ns = ccp._parse_args([
            "/tmp/x",
            "--seed-param", "foo=1",
            "--seed-param", "bar=two",
        ])
        assert ns.seed_param == ["foo=1", "bar=two"]

    def test_with_diagnostics_default_false(self) -> None:
        # Fix B: diagnostics is OPT-IN. Default-off keeps stdout
        # pipe-safe for workflow_state.py set-params-to-commands.
        ns = ccp._parse_args(["/tmp/x"])
        assert ns.with_diagnostics is False

    def test_with_diagnostics_when_set(self) -> None:
        ns = ccp._parse_args(["/tmp/x", "--with-diagnostics"])
        assert ns.with_diagnostics is True


# =============================================================================
# Fix C — coverage for _run_dynamic_phase_once
# =============================================================================
#
# ``_run_dynamic_phase_once`` is the most complex orchestration in the
# analyzer (~190 LOC): per-command child invocation, auto-retry signal
# on module_not_found in the FIRST command, fast-fail bookkeeping that
# short-circuits the rest of the loop without invoking the child, and
# per-command sentinel re-attribution when the child raises.
#
# We mock its three I/O dependencies so no real Docker / proxy / disk
# work is required:
#
#   * ``ccp.prepare_unified_content`` — return synthetic paths.
#   * ``ccp.CaptureProxy`` — replaced by a MagicMock-driven double so
#     ``proxy.start()`` / ``proxy.stop()`` are no-ops with port=0.
#   * ``ccp.analyze_dynamic_for_command`` — the per-command runner.
#     Each test rigs its return values / exceptions to drive the
#     branch under test.


def _stub_prep_proxy(monkeypatch, tmp_path: Path) -> MagicMock:
    """Stub ``prepare_unified_content`` and ``CaptureProxy``.

    Returns the proxy class mock so individual tests can assert on
    ``start`` / ``stop`` calls if they care.
    """
    unified = tmp_path / "unified.py"
    unified.write_text("# stub\n")
    mock_dir = tmp_path / "mock"
    mock_dir.mkdir(exist_ok=True)
    monkeypatch.setattr(
        ccp, "prepare_unified_content",
        lambda integration_path, out_dir: (unified, mock_dir),
    )
    proxy_instance = MagicMock()
    proxy_instance.port = 12345
    proxy_class = MagicMock(return_value=proxy_instance)
    monkeypatch.setattr(ccp, "CaptureProxy", proxy_class)
    return proxy_class


class TestRunDynamicPhaseOnce:
    """Direct coverage for :func:`_run_dynamic_phase_once`.

    The function's contract under test:

      * Happy path → all commands succeed, no retry signalled.
      * First command ``module_not_found`` AND auto-retry enabled AND
        not already on integration docker → returns ``True`` (retry
        signal); ``docker_cfg.use_integration_docker`` is flipped on.
      * First command ``module_not_found`` AND auto-retry disabled →
        returns ``False``; remaining commands are fast-failed without
        invoking the child.
      * Per-command failure with sentinels in the exception text →
        diagnostic re-attributed from ``no_data`` to
        ``param_caused_failure`` with ``failing_params`` populated
        from the YML param set.
    """

    def _run(
        self,
        monkeypatch,
        tmp_path: Path,
        commands: list[str],
        per_command_results: list,
        yml_params: list[dict] | None = None,
        docker_cfg: ccp.DockerConfig | None = None,
        auto_retry: bool = True,
    ) -> tuple[bool, dict, dict, MagicMock]:
        """Drive one call to ``_run_dynamic_phase_once`` with mocks.

        ``per_command_results`` is a list whose i-th entry tells the
        mocked ``analyze_dynamic_for_command`` what to do on the i-th
        invocation: either a ``(captured_set, CommandDiagnostic)``
        tuple or an ``Exception`` instance to raise.
        """
        _stub_prep_proxy(monkeypatch, tmp_path)
        runner_mock = MagicMock()

        def _runner(*args, **kwargs):
            if not per_command_results:
                raise AssertionError(
                    "analyze_dynamic_for_command invoked more times "
                    "than the test scripted"
                )
            outcome = per_command_results.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        runner_mock.side_effect = _runner
        monkeypatch.setattr(
            ccp, "analyze_dynamic_for_command", runner_mock
        )

        dynamic_results: dict[str, set[str]] = {c: set() for c in commands}
        diagnostics: dict[str, ccp.CommandDiagnostic] = {}
        if yml_params is None:
            yml_params = []

        retry = ccp._run_dynamic_phase_once(
            integration_path=tmp_path,
            commands=commands,
            yml_params=yml_params,
            ignore=set(),
            timeout=30,
            dynamic_results=dynamic_results,
            diagnostics=diagnostics,
            integration_name="TestInt",
            docker_cfg=docker_cfg,
            image="test-image",
            coerce_certs=True,
            auto_retry_integration_docker=auto_retry,
            yml_data=None,
            seed_overrides=None,
        )
        return retry, dynamic_results, diagnostics, runner_mock

    # ---- Happy path -------------------------------------------------------

    def test_happy_path_all_commands_succeed_no_retry(
        self, monkeypatch, tmp_path: Path
    ) -> None:
        commands = ["cmd-a", "cmd-b", "cmd-c"]
        results = [
            ({"param_x"}, ccp.CommandDiagnostic(status="ok", captured_requests=2)),
            ({"param_y"}, ccp.CommandDiagnostic(status="ok", captured_requests=1)),
            (set(), ccp.CommandDiagnostic(status="ok_no_capture")),
        ]
        retry, dyn, diag, runner = self._run(
            monkeypatch, tmp_path, commands, results,
        )
        assert retry is False
        assert runner.call_count == 3
        assert dyn["cmd-a"] == {"param_x"}
        assert dyn["cmd-b"] == {"param_y"}
        assert dyn["cmd-c"] == set()
        assert diag["cmd-a"].status == "ok"
        assert diag["cmd-b"].status == "ok"
        assert diag["cmd-c"].status == "ok_no_capture"

    # ---- module_not_found auto-retry signal ------------------------------

    def test_module_not_found_first_command_signals_retry(
        self, monkeypatch, tmp_path: Path
    ) -> None:
        # Auto-retry ENABLED and not already using integration docker
        # → caller must restart the phase under integration docker.
        commands = ["cmd-a", "cmd-b"]
        first = ({}, ccp.CommandDiagnostic(
            status="module_not_found",
            captured_requests=0,
            missing_module="splunklib",
            failure_excerpt="ModuleNotFoundError: No module named 'splunklib'",
        ))
        # Second result must NOT be consumed (function returns after
        # signalling retry on the first command's outcome).
        results = [first, ({}, ccp.CommandDiagnostic(status="ok"))]
        docker_cfg = ccp.DockerConfig(use_integration_docker=False)
        retry, _dyn, _diag, runner = self._run(
            monkeypatch, tmp_path, commands, results,
            docker_cfg=docker_cfg, auto_retry=True,
        )
        assert retry is True
        # Side-effect: the function flips the flag so the outer caller
        # re-resolves the image under the integration's own docker.
        assert docker_cfg.use_integration_docker is True
        # Only the first command was actually invoked; the rest of the
        # loop is abandoned because we returned True before iterating.
        assert runner.call_count == 1

    def test_module_not_found_with_auto_retry_disabled_fast_fails_rest(
        self, monkeypatch, tmp_path: Path
    ) -> None:
        # Auto-retry OFF → no restart signal; remaining commands are
        # fast-failed without invoking the child.
        commands = ["cmd-a", "cmd-b", "cmd-c"]
        first = ({}, ccp.CommandDiagnostic(
            status="module_not_found",
            captured_requests=0,
            missing_module="splunklib",
            failure_excerpt="ModuleNotFoundError: No module named 'splunklib'",
        ))
        # Only the first call is real; the others are short-circuited.
        results = [first]
        docker_cfg = ccp.DockerConfig(use_integration_docker=False)
        retry, dyn, diag, runner = self._run(
            monkeypatch, tmp_path, commands, results,
            docker_cfg=docker_cfg, auto_retry=False,
        )
        assert retry is False
        # CRITICAL: child invocation count is bounded — only the first
        # command was actually run; the rest were short-circuited.
        assert runner.call_count == 1
        # Every command carries the module_not_found status with the
        # original missing-module attribution.
        for cmd in commands:
            assert diag[cmd].status == "module_not_found"
            assert diag[cmd].missing_module == "splunklib"
        # And the auto-retry flag was NOT flipped.
        assert docker_cfg.use_integration_docker is False

    def test_module_not_found_already_on_integration_docker_fast_fails_rest(
        self, monkeypatch, tmp_path: Path
    ) -> None:
        # Already on integration docker → can't escalate further.
        # Remaining commands fast-fail; no retry signal.
        commands = ["cmd-a", "cmd-b"]
        first = ({}, ccp.CommandDiagnostic(
            status="module_not_found",
            captured_requests=0,
            missing_module="pymisp",
            failure_excerpt="ModuleNotFoundError: No module named 'pymisp'",
        ))
        results = [first]
        docker_cfg = ccp.DockerConfig(use_integration_docker=True)
        retry, _dyn, diag, runner = self._run(
            monkeypatch, tmp_path, commands, results,
            docker_cfg=docker_cfg, auto_retry=True,  # auto-retry ON but moot
        )
        assert retry is False
        assert runner.call_count == 1
        assert diag["cmd-b"].status == "module_not_found"
        assert diag["cmd-b"].missing_module == "pymisp"

    # ---- Fast-fail bookkeeping --------------------------------------------

    def test_fast_fail_bounds_child_invocation_count(
        self, monkeypatch, tmp_path: Path
    ) -> None:
        # 5 commands, first fails with module_not_found, auto-retry off
        # → exactly 1 child invocation despite 5 commands in the list.
        commands = [f"cmd-{i}" for i in range(5)]
        first = ({}, ccp.CommandDiagnostic(
            status="module_not_found",
            missing_module="missing_pkg",
            failure_excerpt="ModuleNotFoundError: No module named 'missing_pkg'",
        ))
        docker_cfg = ccp.DockerConfig(use_integration_docker=False)
        retry, _dyn, diag, runner = self._run(
            monkeypatch, tmp_path, commands, [first],
            docker_cfg=docker_cfg, auto_retry=False,
        )
        assert retry is False
        # Bookkeeping invariant: the saved-time guarantee is N-1
        # commands skipped after the first.
        assert runner.call_count == 1
        # And every short-circuited command carries the same
        # attribution as the original failure.
        for c in commands[1:]:
            assert diag[c].status == "module_not_found"
            assert diag[c].missing_module == "missing_pkg"

    # ---- Per-command sentinel re-attribution ------------------------------

    def test_dynamic_analysis_error_with_sentinel_promotes_to_param_caused_failure(
        self, monkeypatch, tmp_path: Path
    ) -> None:
        # When ``analyze_dynamic_for_command`` raises and the exception
        # text embeds ``SENTINEL_PARAM_<name>`` for a name in the YML
        # param set, the catch block re-attributes the diagnostic from
        # ``no_data`` (the default classifier) to ``param_caused_failure``
        # with ``failing_params`` populated from the matched YML names.
        commands = ["cmd-with-bad-param"]
        yml_params = [
            {"name": "secret_token"},
            {"name": "behavioral_param"},
            {"name": "limit"},
        ]
        # Exception body contains the canonical sentinel pattern for
        # ``secret_token``; ``behavioral_param`` is unrelated and must
        # NOT be attributed.
        exc = ccp.DynamicAnalysisError(
            "command failed: ValueError: invalid value "
            "SENTINEL_PARAM_secret_token at line 42\n"
            "child stderr:\nTraceback ... SENTINEL_PARAM_secret_token"
        )
        retry, dyn, diag, runner = self._run(
            monkeypatch, tmp_path, commands, [exc],
            yml_params=yml_params,
        )
        assert retry is False
        assert runner.call_count == 1
        d = diag["cmd-with-bad-param"]
        # Re-attribution: status is promoted from no_data to
        # param_caused_failure and failing_params is populated.
        assert d.status == "param_caused_failure"
        assert d.failing_params == ["secret_token"]
        # Captured set carries the failing param name so it surfaces
        # in the merged per-command output.
        assert dyn["cmd-with-bad-param"] == {"secret_token"}
        # Stray YML names that did NOT appear in the stderr stay out.
        assert "behavioral_param" not in d.failing_params
        assert "limit" not in d.failing_params

    def test_dynamic_analysis_error_without_sentinel_stays_no_data(
        self, monkeypatch, tmp_path: Path
    ) -> None:
        # No sentinel in the exception text → status stays ``no_data``
        # (or the appropriate classifier output) and ``failing_params``
        # remains empty. This is the boundary case to the previous test.
        commands = ["cmd-broken"]
        yml_params = [{"name": "secret_token"}]
        exc = ccp.DynamicAnalysisError(
            "command failed: generic error with no sentinel reference"
        )
        retry, dyn, diag, _runner = self._run(
            monkeypatch, tmp_path, commands, [exc],
            yml_params=yml_params,
        )
        assert retry is False
        d = diag["cmd-broken"]
        assert d.status == "no_data"
        assert d.failing_params == []
        assert dyn["cmd-broken"] == set()

    def test_timeout_classified_as_timeout(
        self, monkeypatch, tmp_path: Path
    ) -> None:
        # Smoke-test the classifier mapping for the timeout signal.
        commands = ["slow-cmd"]
        exc = ccp.DynamicAnalysisError(
            "command 'slow-cmd' timed out after 30s (use --timeout to extend)"
        )
        _retry, _dyn, diag, _runner = self._run(
            monkeypatch, tmp_path, commands, [exc],
        )
        assert diag["slow-cmd"].status == "timeout"

    # ---- Mixed-outcome smoke ---------------------------------------------

    def test_mixed_success_and_failure_isolated_per_command(
        self, monkeypatch, tmp_path: Path
    ) -> None:
        # First command succeeds; second command raises with a
        # non-sentinel error; third command succeeds. The per-command
        # bookkeeping must NOT be polluted across commands.
        commands = ["a", "b", "c"]
        results = [
            ({"p1"}, ccp.CommandDiagnostic(status="ok", captured_requests=1)),
            ccp.DynamicAnalysisError("command 'b' failed: generic"),
            ({"p3"}, ccp.CommandDiagnostic(status="ok", captured_requests=1)),
        ]
        _retry, dyn, diag, runner = self._run(
            monkeypatch, tmp_path, commands, results,
            yml_params=[{"name": "p1"}, {"name": "p3"}],
        )
        assert runner.call_count == 3
        assert diag["a"].status == "ok"
        assert diag["b"].status == "no_data"
        assert diag["c"].status == "ok"
        assert dyn["a"] == {"p1"}
        assert dyn["b"] == set()
        assert dyn["c"] == {"p3"}


class TestAnalyzeIntegrationDiagnosticsOptIn:
    """Fix B contract test for :func:`analyze_integration`.

    The result dict's top-level keys are exactly ``{"integration",
    "commands"}`` unless the caller explicitly opts in via
    ``with_diagnostics=True``. Static-only mode is unaffected
    (it never emits diagnostics).
    """

    def test_static_only_never_emits_diagnostics(
        self, monkeypatch, tmp_path: Path
    ) -> None:
        # Build a minimal integration on disk so the static path runs
        # without mocking the file loader.
        integ_dir = tmp_path / "MyInt"
        integ_dir.mkdir()
        (integ_dir / "MyInt.py").write_text(
            "import demistomock as demisto\n"
            "from CommonServerPython import *\n"
            "def main():\n"
            "    pass\n"
        )
        (integ_dir / "MyInt.yml").write_text(
            "name: MyInt\n"
            "display: MyInt\n"
            "configuration:\n"
            "  - name: api_key\n"
            "    type: 4\n"
            "script:\n"
            "  type: python\n"
            "  subtype: python3\n"
            "  script: ''\n"
            "  commands: []\n"
        )
        result = ccp.analyze_integration(
            integration_path=integ_dir,
            commands_filter=None,
            static_only=True,
            ignore=set(),
            timeout=30,
            docker_cfg=None,
            with_diagnostics=False,
        )
        assert sorted(result.keys()) == ["commands", "integration"]

    def test_static_only_with_diagnostics_flag_still_no_diagnostics(
        self, monkeypatch, tmp_path: Path
    ) -> None:
        # Even when the flag is True, static-only mode has nothing to
        # report and must NOT add the key.
        integ_dir = tmp_path / "MyInt"
        integ_dir.mkdir()
        (integ_dir / "MyInt.py").write_text(
            "import demistomock as demisto\n"
            "from CommonServerPython import *\n"
            "def main():\n"
            "    pass\n"
        )
        (integ_dir / "MyInt.yml").write_text(
            "name: MyInt\n"
            "display: MyInt\n"
            "configuration:\n"
            "  - name: api_key\n"
            "    type: 4\n"
            "script:\n"
            "  type: python\n"
            "  subtype: python3\n"
            "  script: ''\n"
            "  commands: []\n"
        )
        result = ccp.analyze_integration(
            integration_path=integ_dir,
            commands_filter=None,
            static_only=True,
            ignore=set(),
            timeout=30,
            docker_cfg=None,
            with_diagnostics=True,
        )
        assert "diagnostics" not in result


# =============================================================================
# FIXES-TODO #11 — JavaScript language gate for the dynamic phase
# =============================================================================


class TestLanguageGateJavaScript:
    """The dynamic phase must NOT run on non-Python integrations.

    Per FIXES-TODO #11 (LOCKED 2026-05-31): static-only had a language
    gate; the dynamic dispatch in :func:`analyze_integration` did not,
    so JS / PowerShell integrations crashed the entire run with a
    ``DynamicPrepError`` from ``ast.parse``. The fix is a language gate
    BEFORE dynamic dispatch + a typed ``DynamicPrepError("non-Python
    unified file: ...")`` in :func:`prepare_unified_content` as
    defense-in-depth.
    """

    def _make_minimal_js_integration(self, tmp_path: Path) -> Path:
        """Synthesize a tiny JavaScript integration on disk."""
        integ_dir = tmp_path / "JsInt"
        integ_dir.mkdir()
        # The actual JS body is irrelevant — we just need the YML to
        # declare ``script.type: javascript`` so the language gate fires.
        (integ_dir / "JsInt.js").write_text(
            "// JS integration body\n"
            "function main() {\n"
            "    return;\n"
            "}\n"
        )
        (integ_dir / "JsInt.yml").write_text(
            "name: JsInt\n"
            "display: JsInt\n"
            "configuration:\n"
            "  - name: api_key\n"
            "    type: 4\n"
            "script:\n"
            "  type: javascript\n"
            "  script: ''\n"
            "  commands:\n"
            "    - name: js-do-thing\n"
            "      arguments: []\n"
        )
        return integ_dir

    def test_default_invocation_does_not_crash_on_js(
        self, tmp_path: Path, capsys: pytest.CaptureFixture
    ) -> None:
        """Without ``--static-only``, JS integration must NOT crash.

        Per the operational workaround in FIXES-TODO #11, this is the
        exact failure mode that lost the entire run on AMP.
        """
        integ_dir = self._make_minimal_js_integration(tmp_path)
        # Default invocation: static_only=False. The language gate
        # should short-circuit the dynamic phase before
        # ``prepare-content`` ever runs (so this test does NOT require
        # docker / demisto-sdk on PATH).
        result = ccp.analyze_integration(
            integration_path=integ_dir,
            commands_filter=None,
            static_only=False,
            ignore=set(),
            timeout=30,
            docker_cfg=None,
            with_diagnostics=False,
        )
        # The result should have the standard shape with empty
        # commands (the static-only outcome for JS).
        assert "commands" in result
        # The dispatched command from the YML should appear with no
        # captured params (static fallback can't trace JS).
        assert result["commands"].get("js-do-thing", []) == []
        # And the stderr message should include the unambiguous hint
        # per the Hints policy (cross-cutting #1).
        err = capsys.readouterr().err
        assert "non-Python" in err
        assert "--static-only" in err

    def test_prepare_unified_content_raises_typed_dynamic_prep_error(
        self, tmp_path: Path
    ) -> None:
        """Defense-in-depth: even if a caller bypasses the
        ``analyze_integration`` gate, ``prepare_unified_content`` must
        emit a typed ``DynamicPrepError("non-Python unified file: ...")``
        rather than a confusing SyntaxError-shaped error from
        ``ast.parse``.

        We can't easily run real ``demisto-sdk prepare-content`` from a
        test, so we monkeypatch the subprocess call to write a unified
        YAML with ``script.type: javascript`` and assert the language
        gate inside ``prepare_unified_content`` catches it.
        """
        import subprocess

        out_dir = tmp_path / "out"
        out_dir.mkdir()
        integ_dir = tmp_path / "DummyInt"
        integ_dir.mkdir()

        # Synthesize the unified.yml that prepare-content would normally
        # produce. The language gate reads ``script.type`` from this
        # file.
        def _fake_subprocess_run(cmd, *args, **kwargs):  # noqa: ANN001
            # cmd is ["demisto-sdk", "prepare-content", "-i", ..., "-o", out_path]
            # find the -o argument
            out_path = Path(cmd[cmd.index("-o") + 1])
            out_path.write_text(
                "name: JsInt\n"
                "script:\n"
                "  type: javascript\n"
                "  script: '// hello'\n",
                encoding="utf-8",
            )

            class _R:
                returncode = 0
                stdout = ""
                stderr = ""

            return _R()

        # Force shutil.which to return a non-None value so the early
        # ``demisto-sdk not found on PATH`` check passes.
        import shutil

        with mock.patch.object(subprocess, "run", _fake_subprocess_run):
            with mock.patch.object(shutil, "which", return_value="/fake/demisto-sdk"):
                with pytest.raises(ccp.DynamicPrepError) as exc_info:
                    ccp.prepare_unified_content(integ_dir, out_dir)
        assert "non-Python" in str(exc_info.value)
        assert "javascript" in str(exc_info.value)
        assert "--static-only" in str(exc_info.value)


# =============================================================================
# Fix A — call-graph depth bump + class-constructor resolution
# =============================================================================


class TestFixA_CallGraphDepth:
    """Fix A: ``trace_params_in_function`` default depth bumped 2→3,
    ``_resolve_call_target`` resolves ``ast.ClassDef`` to its
    ``__init__``, and ``build_function_map`` walks ClassDefs into the
    map. CLI knob ``--call-graph-depth`` (range [1, 5]) overrides.
    """

    def test_depth_3_picks_up_two_levels_deep(self) -> None:
        # handler -> wrapper -> leaf(params.get("X")). At the legacy
        # depth=2 ceiling this would be missed; at the new default
        # depth=3 it MUST be recovered.
        src = textwrap.dedent(
            '''
            import demistomock as demisto

            def leaf(params):
                return params.get("deep_param")

            def wrapper(params):
                return leaf(params)

            def handler(params):
                return wrapper(params)

            def main():
                params = demisto.params()
                command = demisto.command()
                if command == "do-thing":
                    handler(params)
            '''
        ).lstrip()
        _scope_1, scope_2 = ccp.analyze_static(
            src, command="do-thing", verbose=False
        )
        assert "deep_param" in scope_2

    def test_class_constructor_resolved_to_init(self) -> None:
        # ``UserMappingObject(params)`` resolved via _resolve_call_target
        # must land on the class's __init__ and read its params.get()
        # calls. Reads in main()'s pre-dispatch body land in scope_1.
        src = textwrap.dedent(
            '''
            import demistomock as demisto

            class UserMappingObject:
                def __init__(self, params):
                    self.user_field = params.get("xsoar_user_field")

            def handler(mapper):
                return None

            def main():
                params = demisto.params()
                command = demisto.command()
                mapper = UserMappingObject(params)
                if command == "do-thing":
                    handler(mapper)
            '''
        ).lstrip()
        scope_1, scope_2 = ccp.analyze_static(
            src, command="do-thing", verbose=False
        )
        # Direct unit-level proof: _resolve_call_target now resolves
        # the constructor call to __init__.
        tree = ast.parse(src)
        func_map = ccp.build_function_map(tree)
        # Find the UserMappingObject(...) Call inside main().
        main_fn = func_map["main"]
        assert isinstance(main_fn, ast.FunctionDef)
        ctor_call = None
        for sub in ast.walk(main_fn):
            if (
                isinstance(sub, ast.Call)
                and isinstance(sub.func, ast.Name)
                and sub.func.id == "UserMappingObject"
            ):
                ctor_call = sub
                break
        assert ctor_call is not None, "ctor Call should be findable"
        target = ccp._resolve_call_target(ctor_call, func_map)
        assert target is not None
        assert target.name == "__init__"
        # And the pre-dispatch xsoar_user_field read in __init__ is
        # visible somewhere in the merged static union for this command
        # (scope_1 covers pre-dispatch reads via the binding-narrowing
        # path; either union must surface the param).
        assert "xsoar_user_field" in (scope_1 | scope_2)

    def test_max_depth_5_does_not_hang(self) -> None:
        # 6-level chain; depth=5 should reach exactly through level 5,
        # never blow recursion, and complete in <1s.
        src = textwrap.dedent(
            '''
            import demistomock as demisto

            def lvl6(params):
                return params.get("p6")

            def lvl5(params):
                return lvl6(params)

            def lvl4(params):
                return lvl5(params)

            def lvl3(params):
                return lvl4(params)

            def lvl2(params):
                return lvl3(params)

            def lvl1(params):
                return lvl2(params)

            def main():
                params = demisto.params()
                command = demisto.command()
                if command == "do-thing":
                    lvl1(params)
            '''
        ).lstrip()
        import time as _t

        t0 = _t.time()
        _scope_1, scope_2 = ccp.analyze_static(
            src, command="do-thing", verbose=False, call_graph_depth=5
        )
        elapsed = _t.time() - t0
        assert elapsed < 1.0, f"depth=5 took {elapsed:.2f}s; expected <1s"
        # depth=5 reaches lvl1, lvl2, lvl3, lvl4, lvl5, lvl6 — but the
        # call from lvl5 -> lvl6 is at recursion depth 5 from the
        # handler call site (lvl1 itself is depth-1, so the chain
        # consumes 5 budget steps to reach lvl6). The param at the
        # deepest reachable level MUST appear.
        assert "p6" in scope_2


# =============================================================================
# Fix B — confidence-tier attribution system
# =============================================================================


def _attribution_for(
    attributions: list[ccp.ParamAttribution], param: str
) -> ccp.ParamAttribution | None:
    for attr in attributions:
        if attr.param == param:
            return attr
    return None


class TestFixB_ConfidenceTiers:
    """Fix B: per-(command, param) confidence-tier attribution system."""

    def test_handler_body_attribution_confidence_1(self) -> None:
        src = textwrap.dedent(
            '''
            import demistomock as demisto

            def handler(params):
                return params.get("X")

            def main():
                params = demisto.params()
                command = demisto.command()
                if command == "do-thing":
                    handler(params)
            '''
        ).lstrip()
        _s1, _s2, attributions = ccp.analyze_static_attributions(
            src, command="do-thing"
        )
        attr = _attribution_for(attributions, "X")
        assert attr is not None, "X should be attributed"
        assert "handler_body" in attr.by_source
        assert attr.by_source["handler_body"].confidence == 1.0
        assert attr.rollup_confidence == 1.0

    def test_helper_depth_1_confidence_0_8(self) -> None:
        src = textwrap.dedent(
            '''
            import demistomock as demisto

            def leaf(params):
                return params.get("X")

            def handler(params):
                return leaf(params)

            def main():
                params = demisto.params()
                command = demisto.command()
                if command == "do-thing":
                    handler(params)
            '''
        ).lstrip()
        _s1, _s2, attributions = ccp.analyze_static_attributions(
            src, command="do-thing"
        )
        attr = _attribution_for(attributions, "X")
        assert attr is not None
        assert "helper" in attr.by_source
        assert attr.by_source["helper"].confidence == 0.8
        assert attr.by_source["helper"].call_graph_depth == 1

    def test_helper_depth_3_confidence_0_5(self) -> None:
        src = textwrap.dedent(
            '''
            import demistomock as demisto

            def leaf(params):
                return params.get("X")

            def mid(params):
                return leaf(params)

            def wrapper(params):
                return mid(params)

            def handler(params):
                return wrapper(params)

            def main():
                params = demisto.params()
                command = demisto.command()
                if command == "do-thing":
                    handler(params)
            '''
        ).lstrip()
        _s1, _s2, attributions = ccp.analyze_static_attributions(
            src, command="do-thing"
        )
        attr = _attribution_for(attributions, "X")
        assert attr is not None
        assert "helper" in attr.by_source
        assert attr.by_source["helper"].confidence == 0.5
        assert attr.by_source["helper"].call_graph_depth == 3

    def test_module_const_referenced_attributed_0_5(self) -> None:
        src = textwrap.dedent(
            '''
            import demistomock as demisto

            FETCH = demisto.params().get("max_fetch")

            def handler_a():
                return FETCH

            def handler_b():
                return 1

            def main():
                command = demisto.command()
                if command == "A":
                    handler_a()
                elif command == "B":
                    handler_b()
            '''
        ).lstrip()
        _s1, _s2, a_attrs = ccp.analyze_static_attributions(src, "A")
        _s1, _s2, b_attrs = ccp.analyze_static_attributions(src, "B")
        attr_a = _attribution_for(a_attrs, "max_fetch")
        assert attr_a is not None, "A should have max_fetch via module_const_referenced"
        assert "module_const_referenced" in attr_a.by_source
        assert attr_a.by_source["module_const_referenced"].confidence == 0.5
        # B does not reference FETCH; max_fetch must not appear
        # from the module_const_referenced tier on B.
        attr_b = _attribution_for(b_attrs, "max_fetch")
        if attr_b is not None:
            assert "module_const_referenced" not in attr_b.by_source

    def test_module_const_hedged_when_walk_uncertain(self) -> None:
        # handler_a *references* FETCH directly (so the const is
        # reachable in the AST) AND uses dynamic dispatch
        # (globals()[name]() pattern) which sets walk_uncertain.
        # The combination MUST flip the constant's attribution to
        # ``module_const_hedged`` instead of ``module_const_referenced``.
        src = textwrap.dedent(
            '''
            import demistomock as demisto

            FETCH = demisto.params().get("max_fetch")

            def handler_a():
                _ = FETCH  # direct reference to const
                fn = globals()["something"]
                return fn()

            def main():
                command = demisto.command()
                if command == "A":
                    handler_a()
            '''
        ).lstrip()
        _s1, _s2, attrs = ccp.analyze_static_attributions(src, "A")
        attr = _attribution_for(attrs, "max_fetch")
        assert attr is not None
        assert "module_const_hedged" in attr.by_source
        assert attr.by_source["module_const_hedged"].confidence == 0.1
        assert "module_const_referenced" not in attr.by_source

    def test_module_const_hedged_when_binding_non_literal(self) -> None:
        src = textwrap.dedent(
            '''
            import demistomock as demisto

            VAR = "max_fetch"
            KEY = demisto.params().get(VAR)

            def handler_a():
                return KEY

            def main():
                command = demisto.command()
                if command == "A":
                    handler_a()
            '''
        ).lstrip()
        _s1, _s2, attrs = ccp.analyze_static_attributions(src, "A")
        # The non-literal-key params.get(VAR) creates a hedged
        # constant. KEY is referenced in handler_a, so the
        # attribution surfaces as module_const_hedged with no real
        # param name attached (because we can't know what VAR is).
        # The sentinel _NON_LITERAL_PARAM_KEY isn't surfaced as a
        # YML param. But the constant is in hedged_constants so any
        # *known* literal also bound to KEY (none here) would be
        # hedged. This test simply asserts that KEY is in
        # hedged_constants and no module_const_referenced row exists.
        attr = _attribution_for(attrs, "max_fetch")
        # There's no literal binding to max_fetch via KEY, so no
        # max_fetch attribution should appear via module_const_*.
        if attr is not None:
            assert "module_const_referenced" not in attr.by_source
        # Direct check on the index helper:
        tree = ast.parse(src)
        const_index, hedged = ccp._build_module_const_index(
            tree, {"params", "PARAMS"}, {}
        )
        assert "KEY" in hedged

    def test_pre_dispatch_main_attributed_to_all_commands(self) -> None:
        src = textwrap.dedent(
            '''
            import demistomock as demisto

            def handler_a():
                return None

            def handler_b():
                return None

            def main():
                params = demisto.params()
                _ = params.get("Y")  # pre-dispatch read
                command = demisto.command()
                if command == "A":
                    handler_a()
                elif command == "B":
                    handler_b()
            '''
        ).lstrip()
        _s1, _s2, a_attrs = ccp.analyze_static_attributions(src, "A")
        _s1, _s2, b_attrs = ccp.analyze_static_attributions(src, "B")
        for attrs, label in [(a_attrs, "A"), (b_attrs, "B")]:
            attr = _attribution_for(attrs, "Y")
            assert attr is not None, f"Y missing on command {label}"
            assert "pre_dispatch_main" in attr.by_source
            assert attr.by_source["pre_dispatch_main"].confidence == 0.2

    def test_pre_dispatch_constructor_arg_attributed(self) -> None:
        src = textwrap.dedent(
            '''
            import demistomock as demisto

            class UserMappingObject:
                def __init__(self, params):
                    self.z = params.get("Z")

            def handler_a(mapper):
                return mapper

            def main():
                params = demisto.params()
                mapper = UserMappingObject(params)
                command = demisto.command()
                if command == "A":
                    handler_a(mapper)
            '''
        ).lstrip()
        _s1, _s2, attrs = ccp.analyze_static_attributions(src, "A")
        attr = _attribution_for(attrs, "Z")
        assert attr is not None
        assert "pre_dispatch_main" in attr.by_source
        evidence_text = attr.by_source["pre_dispatch_main"].evidence
        assert "UserMappingObject" in evidence_text
        assert "__init__" in evidence_text

    def test_multi_source_rollup_takes_max(self) -> None:
        src = textwrap.dedent(
            '''
            import demistomock as demisto

            CONST = demisto.params().get("X")

            def handler(params):
                # direct handler-body read AND uses CONST
                _ = CONST
                return params.get("X")

            def main():
                params = demisto.params()
                command = demisto.command()
                if command == "A":
                    handler(params)
            '''
        ).lstrip()
        _s1, _s2, attrs = ccp.analyze_static_attributions(src, "A")
        attr = _attribution_for(attrs, "X")
        assert attr is not None
        # handler_body 1.0 + module_const_referenced 0.5 → rollup 1.0
        assert "handler_body" in attr.by_source
        assert "module_const_referenced" in attr.by_source
        assert attr.rollup_confidence == 1.0

    def test_dynamic_capture_folded_in(self) -> None:
        src = textwrap.dedent(
            '''
            import demistomock as demisto

            def handler():
                return None

            def main():
                command = demisto.command()
                if command == "A":
                    handler()
            '''
        ).lstrip()
        _s1, _s2, attrs = ccp.analyze_static_attributions(
            src, command="A", captured={"A"}
        )
        attr = _attribution_for(attrs, "A")
        assert attr is not None
        assert "dynamic_capture" in attr.by_source
        assert attr.by_source["dynamic_capture"].confidence == 1.0
        assert attr.rollup_confidence == 1.0

    def test_headline_filter_drops_below_threshold(
        self, tmp_path: Path
    ) -> None:
        # End-to-end: create a tiny integration on disk, run
        # analyze_integration with headline_min_confidence=0.5, and
        # confirm that pre_dispatch_main-only params (0.2) and
        # module_const_hedged-only params (0.1) are dropped from
        # commands[cmd] but remain in attributions.
        integ_dir = tmp_path / "TinyInt"
        integ_dir.mkdir()
        # Pre-dispatch reads "preflight"; handler reads "real".
        py = textwrap.dedent(
            '''
            import demistomock as demisto

            def handler(params):
                return params.get("real")

            def main():
                params = demisto.params()
                _ = params.get("preflight")
                command = demisto.command()
                if command == "do-thing":
                    handler(params)
            '''
        ).lstrip()
        (integ_dir / "TinyInt.py").write_text(py)
        (integ_dir / "TinyInt.yml").write_text(
            "commonfields:\n  id: TinyInt\nname: TinyInt\n"
            "display: TinyInt\nscript:\n  type: python\n  subtype: python3\n"
            "  commands:\n    - name: do-thing\n      description: x\n"
            "configuration:\n"
            "  - name: real\n    display: Real\n    type: 0\n"
            "  - name: preflight\n    display: Preflight\n    type: 0\n"
        )
        result = ccp.analyze_integration(
            integration_path=integ_dir,
            commands_filter=None,
            static_only=True,
            ignore=set(),
            timeout=30,
            docker_cfg=None,
            with_diagnostics=True,
            headline_min_confidence=0.5,
        )
        # Headline drops 0.2 preflight, keeps 1.0 real.
        assert result["commands"]["do-thing"] == ["real"]
        # diagnostics is suppressed under static_only by design — so
        # we can't assert on the in-result attributions field. Instead
        # we call analyze_static_attributions directly to confirm
        # the structured payload still contains preflight.
        _s1, _s2, attrs = ccp.analyze_static_attributions(
            py, command="do-thing"
        )
        attr = _attribution_for(attrs, "preflight")
        assert attr is not None
        assert "pre_dispatch_main" in attr.by_source

    def test_q3_downgrade_hook_is_present_but_inactive(self) -> None:
        # Confirm the hook exists (so Fix C can flip the flag) but is
        # off by default — pre_dispatch_main stays at 0.2.
        src = textwrap.dedent(
            '''
            import demistomock as demisto

            def handler():
                return None

            def main():
                params = demisto.params()
                _ = params.get("Y")
                command = demisto.command()
                if command == "A":
                    handler()
            '''
        ).lstrip()
        # Default: dynamic_confirmed_no_execution = False.
        _s1, _s2, attrs = ccp.analyze_static_attributions(src, "A")
        attr = _attribution_for(attrs, "Y")
        assert attr is not None
        assert "pre_dispatch_main" in attr.by_source
        assert (
            attr.by_source["pre_dispatch_main"].confidence == 0.2
        )
        assert "pre_dispatch_main_dynamic_disproven" not in attr.by_source
        # Hook works when explicitly flipped.
        _s1, _s2, attrs_off = ccp.analyze_static_attributions(
            src, "A", dynamic_confirmed_no_execution=True
        )
        attr_off = _attribution_for(attrs_off, "Y")
        assert attr_off is not None
        assert (
            "pre_dispatch_main_dynamic_disproven" in attr_off.by_source
        )
        assert (
            attr_off.by_source[
                "pre_dispatch_main_dynamic_disproven"
            ].confidence == 0.1
        )

    def test_splunkpy_style_no_fanout_when_certain(self) -> None:
        # SplunkPy-shape mini-integration: 4 module constants, 3
        # commands each referencing exactly 1 constant via a helper.
        # Each command's attributions must contain exactly 1
        # module_const_referenced row, not 4 (the pre-Fix-B
        # fan-out bug).
        src = textwrap.dedent(
            '''
            import demistomock as demisto

            params = demisto.params()
            FETCH_LIMIT = params.get("max_fetch")
            REPLACE_FLAG = params.get("replaceKeys")
            FIRST_FETCH = params.get("first_fetch")
            ENABLED = params.get("enabled_enrichments")

            def handler_a(params_arg):
                return FETCH_LIMIT

            def handler_b(params_arg):
                return REPLACE_FLAG

            def handler_c(params_arg):
                return FIRST_FETCH

            def main():
                command = demisto.command()
                if command == "fetch":
                    handler_a(params)
                elif command == "replace":
                    handler_b(params)
                elif command == "first":
                    handler_c(params)
            '''
        ).lstrip()

        def _module_const_refs(attrs: list[ccp.ParamAttribution]) -> set[str]:
            out = set()
            for a in attrs:
                if "module_const_referenced" in a.by_source:
                    out.add(a.param)
            return out

        _, _, fetch_attrs = ccp.analyze_static_attributions(src, "fetch")
        _, _, replace_attrs = ccp.analyze_static_attributions(src, "replace")
        _, _, first_attrs = ccp.analyze_static_attributions(src, "first")
        assert _module_const_refs(fetch_attrs) == {"max_fetch"}
        assert _module_const_refs(replace_attrs) == {"replaceKeys"}
        assert _module_const_refs(first_attrs) == {"first_fetch"}
        # ENABLED is referenced by nobody, so it must not surface.
        for attrs in (fetch_attrs, replace_attrs, first_attrs):
            attr = _attribution_for(attrs, "enabled_enrichments")
            if attr is not None:
                assert "module_const_referenced" not in attr.by_source

    def test_dataclasses_serialize_via_asdict(self) -> None:
        # Fix B.9: confirm asdict() on the new dataclasses produces
        # JSON-friendly output (no enum / custom types in the way).
        import dataclasses as _dc
        import json as _json

        ev = ccp.ParamSourceEvidence(
            source="helper",
            confidence=0.7,
            evidence="params.get() reached at depth=2 via foo",
            call_graph_depth=2,
        )
        attr = ccp.ParamAttribution(
            param="X",
            by_source={"helper": ev},
            rollup_confidence=0.7,
        )
        d = _dc.asdict(attr)
        assert d["param"] == "X"
        assert d["rollup_confidence"] == 0.7
        assert d["by_source"]["helper"]["confidence"] == 0.7
        # Round-trip via JSON to confirm everything serializes.
        _json.dumps(d)


# =============================================================================
# Changes 1-4: Verdicts + dispatch-pattern coverage
# =============================================================================


class TestVerdictsAndDispatchPatterns:
    """End-to-end coverage for the four coordinated improvements.

    Each test wires a minimal synthetic integration source through
    :func:`ccp.analyze_static_attributions_with_status` and asserts
    on the per-command ``analysis_status`` + per-param ``verdict``
    output. The tests live in their own class so the broader fixture
    set doesn't leak in.
    """

    YML_PARAMS = {"X", "Y", "Z", "Q", "url"}

    # --- Helpers ----------------------------------------------------------

    @staticmethod
    def _attr_by_param(
        attrs: list, name: str
    ):  # type: ignore[no-untyped-def]
        for a in attrs:
            if a.param == name:
                return a
        return None

    # --- 1. proven_used --------------------------------------------------

    def test_proven_used_when_handler_body_attributes_with_conf_1(self) -> None:
        src = textwrap.dedent(
            '''
            import demistomock as demisto
            def do_thing_command():
                params = demisto.params()
                return params.get("X")
            def main():
                params = demisto.params()
                if demisto.command() == "do-thing":
                    do_thing_command()
            '''
        ).lstrip()
        _s1, _s2, attrs, status = ccp.analyze_static_attributions_with_status(
            src, "do-thing", yml_param_names=self.YML_PARAMS
        )
        assert status == ccp.ANALYSIS_STATUS_HANDLER_BODY
        attr = self._attr_by_param(attrs, "X")
        assert attr is not None
        assert attr.rollup_confidence == 1.0
        assert attr.verdict == ccp.VERDICT_PROVEN_USED

    # --- 2. proven_unused ------------------------------------------------

    def test_proven_unused_when_yml_declares_param_not_referenced(self) -> None:
        src = textwrap.dedent(
            '''
            import demistomock as demisto
            def do_thing_command():
                params = demisto.params()
                return params.get("X")
            def main():
                params = demisto.params()
                if demisto.command() == "do-thing":
                    do_thing_command()
            '''
        ).lstrip()
        _s1, _s2, attrs, status = ccp.analyze_static_attributions_with_status(
            src, "do-thing", yml_param_names=self.YML_PARAMS
        )
        # Y is YML-declared but never referenced anywhere reachable.
        assert status == ccp.ANALYSIS_STATUS_HANDLER_BODY
        attr_y = self._attr_by_param(attrs, "Y")
        assert attr_y is not None
        assert attr_y.verdict == ccp.VERDICT_PROVEN_UNUSED
        assert attr_y.rollup_confidence == 0.0
        assert attr_y.by_source == {}

    # --- 3. needs_review (helper only) -----------------------------------

    def test_needs_review_when_helper_attribution_only(self) -> None:
        src = textwrap.dedent(
            '''
            import demistomock as demisto
            def helper(params):
                return params.get("X")
            def do_thing_command(params):
                return helper(params)
            def main():
                params = demisto.params()
                if demisto.command() == "do-thing":
                    do_thing_command(params)
            '''
        ).lstrip()
        _s1, _s2, attrs, status = ccp.analyze_static_attributions_with_status(
            src, "do-thing", yml_param_names=self.YML_PARAMS
        )
        assert status == ccp.ANALYSIS_STATUS_HELPER_CHAIN
        attr = self._attr_by_param(attrs, "X")
        assert attr is not None
        # Helper at depth 1 gives confidence 0.8 < 1.0 → needs_review.
        assert 0.0 < attr.rollup_confidence < 1.0
        assert attr.verdict == ccp.VERDICT_NEEDS_REVIEW

    # --- 4. needs_review (module_const_hedged only) ----------------------

    def test_needs_review_when_module_const_hedged_only(self) -> None:
        src = textwrap.dedent(
            '''
            import demistomock as demisto
            params = demisto.params()
            KEY = params.get("X")
            def do_thing_command():
                # Dynamic dispatch makes the walk uncertain.
                getattr(__import__("os"), "name")
                return KEY
            def main():
                if demisto.command() == "do-thing":
                    do_thing_command()
            '''
        ).lstrip()
        _s1, _s2, attrs, status = ccp.analyze_static_attributions_with_status(
            src, "do-thing", yml_param_names=self.YML_PARAMS
        )
        attr = self._attr_by_param(attrs, "X")
        # The dynamic-dispatch shape forces walk_uncertain, hedging
        # the module-const attribution to 0.1.
        assert attr is not None
        assert attr.verdict == ccp.VERDICT_NEEDS_REVIEW

    # --- 5. walk_uncertain prevents proven_unused ------------------------

    def test_no_proven_unused_when_walk_uncertain(self) -> None:
        src = textwrap.dedent(
            '''
            import demistomock as demisto
            def do_thing_command():
                # Dynamic dispatch — analyzer cannot prove what's used.
                cmd = "do_other"
                globals()[cmd]()
            def do_other():
                pass
            def main():
                if demisto.command() == "do-thing":
                    do_thing_command()
            '''
        ).lstrip()
        _s1, _s2, attrs, status = ccp.analyze_static_attributions_with_status(
            src, "do-thing", yml_param_names=self.YML_PARAMS
        )
        # No positive evidence for Y, but walk is uncertain — must
        # NOT be proven_unused.
        attr_y = self._attr_by_param(attrs, "Y")
        assert attr_y is not None
        assert attr_y.verdict == ccp.VERDICT_NEEDS_REVIEW
        assert attr_y.rollup_confidence == 0.0

    # --- 6. module-scope dispatch detected -------------------------------

    def test_module_scope_dispatch_detected(self) -> None:
        src = textwrap.dedent(
            '''
            import demistomock as demisto
            def ip_command():
                params = demisto.params()
                return params.get("X")
            if demisto.command() == "ip":
                ip_command()
            elif demisto.command() == "search":
                pass
            '''
        ).lstrip()
        _s1, _s2, attrs, status = ccp.analyze_static_attributions_with_status(
            src, "ip", yml_param_names=self.YML_PARAMS
        )
        assert status == ccp.ANALYSIS_STATUS_MODULE_SCOPE
        attr = self._attr_by_param(attrs, "X")
        assert attr is not None
        assert attr.rollup_confidence == 1.0
        assert attr.verdict == ccp.VERDICT_PROVEN_USED

    # --- 7. dict-dispatch resolves handler ------------------------------

    def test_dict_dispatch_extracts_handler_map(self) -> None:
        src = textwrap.dedent(
            '''
            import demistomock as demisto
            def handler_a():
                params = demisto.params()
                return params.get("X")
            def handler_b():
                params = demisto.params()
                return params.get("Y")
            def main():
                commands = {"cmd-a": handler_a, "cmd-b": handler_b}
                command = demisto.command()
                if command in commands:
                    commands[command]()
            '''
        ).lstrip()
        # cmd-a should resolve handler_a → params.get("X")
        _s1, _s2, attrs_a, status_a = ccp.analyze_static_attributions_with_status(
            src, "cmd-a", yml_param_names=self.YML_PARAMS
        )
        assert status_a == ccp.ANALYSIS_STATUS_DICT_DISPATCH
        x_attr = self._attr_by_param(attrs_a, "X")
        assert x_attr is not None
        assert x_attr.verdict == ccp.VERDICT_PROVEN_USED

        _s1, _s2, attrs_b, status_b = ccp.analyze_static_attributions_with_status(
            src, "cmd-b", yml_param_names=self.YML_PARAMS
        )
        assert status_b == ccp.ANALYSIS_STATUS_DICT_DISPATCH
        y_attr = self._attr_by_param(attrs_b, "Y")
        assert y_attr is not None
        assert y_attr.verdict == ccp.VERDICT_PROVEN_USED

    # --- 8. scattered-dispatch guard skip --------------------------------

    def test_scattered_dispatch_skips_early_return_guard(self) -> None:
        src = textwrap.dedent(
            '''
            import demistomock as demisto
            def guard_handler():
                pass
            def real_command():
                pass
            def main():
                command = demisto.command()
                if command == "guard":
                    guard_handler()
                    return
                params = demisto.params()
                z = params.get("Z")  # this lives after the guard
                if command == "real":
                    real_command()
            '''
        ).lstrip()
        # 'real' command should see Z via pre_dispatch_main AND get
        # the scattered_truncated tag.
        _s1, _s2, attrs, status = ccp.analyze_static_attributions_with_status(
            src, "real", yml_param_names=self.YML_PARAMS
        )
        assert status == ccp.ANALYSIS_STATUS_SCATTERED_TRUNCATED
        z_attr = self._attr_by_param(attrs, "Z")
        assert z_attr is not None
        assert "pre_dispatch_main" in z_attr.by_source

    # --- 9. guard's own command still resolves ---------------------------

    def test_scattered_dispatch_guard_command_still_resolves(self) -> None:
        src = textwrap.dedent(
            '''
            import demistomock as demisto
            def guard_handler():
                params = demisto.params()
                return params.get("Q")
            def main():
                command = demisto.command()
                if command == "guard":
                    guard_handler()
                    return
                params = demisto.params()
                z = params.get("Z")
                if command == "real":
                    pass
            '''
        ).lstrip()
        _s1, _s2, attrs, _status = ccp.analyze_static_attributions_with_status(
            src, "guard", yml_param_names=self.YML_PARAMS
        )
        q_attr = self._attr_by_param(attrs, "Q")
        assert q_attr is not None
        # Q reads inside the guard's handler body — must attribute.
        assert "handler_body" in q_attr.by_source
        assert q_attr.verdict == ccp.VERDICT_PROVEN_USED

    # --- 10. handler_not_found status ------------------------------------

    def test_handler_not_found_status_when_dispatch_resolves_but_handler_undefined(
        self,
    ) -> None:
        src = textwrap.dedent(
            '''
            import demistomock as demisto
            from some_module import imported_handler
            def main():
                if demisto.command() == "x":
                    imported_handler()
            '''
        ).lstrip()
        _s1, _s2, _attrs, status = ccp.analyze_static_attributions_with_status(
            src, "x", yml_param_names=self.YML_PARAMS
        )
        assert status == ccp.ANALYSIS_STATUS_HANDLER_NOT_FOUND

    # --- 11. verdict / analysis_status serialize in to_dict --------------

    def test_verdict_serializes_in_to_dict(self) -> None:
        diag = ccp.CommandDiagnostic(status="ok", captured_requests=1)
        diag.analysis_status = ccp.ANALYSIS_STATUS_HANDLER_BODY
        diag.attributions = [
            ccp.ParamAttribution(
                param="X",
                by_source={
                    "handler_body": ccp.ParamSourceEvidence(
                        source="handler_body", confidence=1.0, evidence="test"
                    )
                },
                rollup_confidence=1.0,
                verdict=ccp.VERDICT_PROVEN_USED,
            )
        ]
        d = diag.to_dict()
        assert d["analysis_status"] == ccp.ANALYSIS_STATUS_HANDLER_BODY
        assert d["attributions"][0]["verdict"] == ccp.VERDICT_PROVEN_USED

    # --- 12. --emit-proven-unused filter ---------------------------------

    def test_emit_proven_unused_flag_filters_when_false(self) -> None:
        src = textwrap.dedent(
            '''
            import demistomock as demisto
            def do_thing_command():
                params = demisto.params()
                return params.get("X")
            def main():
                if demisto.command() == "do-thing":
                    do_thing_command()
            '''
        ).lstrip()
        # With emit_proven_unused=True (default), the proven_unused
        # row for Y is included.
        _s1, _s2, attrs_on, _ = ccp.analyze_static_attributions_with_status(
            src,
            "do-thing",
            yml_param_names=self.YML_PARAMS,
            emit_proven_unused=True,
        )
        assert any(
            a.param == "Y" and a.verdict == ccp.VERDICT_PROVEN_UNUSED
            for a in attrs_on
        )
        # With emit_proven_unused=False, Y is excluded entirely (it
        # had no positive evidence AND would have been proven_unused).
        _s1, _s2, attrs_off, _ = ccp.analyze_static_attributions_with_status(
            src,
            "do-thing",
            yml_param_names=self.YML_PARAMS,
            emit_proven_unused=False,
        )
        assert not any(
            a.param == "Y" and a.verdict == ccp.VERDICT_PROVEN_UNUSED
            for a in attrs_off
        )


# =============================================================================
# integration_path / --integration-id resolution (CLI simplification)
# =============================================================================


class TestResolveIntegrationPath:
    """``resolve_integration_path`` maps a CSV id to its directory."""

    def test_resolves_directory_from_yml(self) -> None:
        fake = {"yml": "Packs/Foo/Integrations/Foo/Foo.yml"}
        with patch("workflow_state.get_integration_files", return_value=fake):
            result = ccp.resolve_integration_path("Foo")
        assert result == (Path("Packs/Foo/Integrations/Foo/Foo.yml").resolve()).parent
        assert result.name == "Foo"

    def test_unknown_id_raises_valueerror(self) -> None:
        fake = {"error": "Integration 'Nope' not found."}
        with patch("workflow_state.get_integration_files", return_value=fake):
            with pytest.raises(ValueError, match="not found"):
                ccp.resolve_integration_path("Nope")

    def test_missing_yml_key_raises_valueerror(self) -> None:
        with patch("workflow_state.get_integration_files", return_value={}):
            with pytest.raises(ValueError, match="no resolvable YML path"):
                ccp.resolve_integration_path("Foo")

    def test_import_failure_raises_valueerror(self) -> None:
        with patch(
            "workflow_state.get_integration_files",
            side_effect=ImportError("boom"),
        ):
            with pytest.raises(ValueError, match="could not import workflow_state"):
                ccp.resolve_integration_path("Foo")


class TestMainPathResolution:
    """``main`` accepts path-only, id-only, both, or neither."""

    @staticmethod
    def _patch_analysis(returned: dict | None = None):
        """Patch the heavy analysis + ignore-set so main() stays pure."""
        result = returned or {"integration": "X", "commands": {}}
        return (
            patch.object(ccp, "analyze_integration", return_value=result),
            patch.object(ccp, "compose_ignore_set", return_value=set()),
            patch.object(ccp, "resolve_docker_config", return_value=None),
            patch.object(ccp, "_ensure_demisto_sdk_log_path"),
        )

    def test_path_only_uses_explicit_path(self, tmp_path: Path) -> None:
        ai, ci, rd, el = self._patch_analysis()
        with ai as m_ai, ci, rd, el:
            rc = ccp.main([str(tmp_path), "--static-only"])
        assert rc == 0
        assert m_ai.call_args.kwargs["integration_path"] == tmp_path.resolve()

    def test_id_only_resolves_path(self, tmp_path: Path) -> None:
        ai, ci, rd, el = self._patch_analysis()
        with ai as m_ai, ci, rd, el, patch.object(
            ccp, "resolve_integration_path", return_value=tmp_path
        ) as m_resolve:
            rc = ccp.main(["--integration-id", "Foo", "--static-only"])
        assert rc == 0
        m_resolve.assert_called_once_with("Foo")
        assert m_ai.call_args.kwargs["integration_path"] == tmp_path

    def test_both_explicit_path_wins(self, tmp_path: Path) -> None:
        ai, ci, rd, el = self._patch_analysis()
        with ai as m_ai, ci, rd, el, patch.object(
            ccp, "resolve_integration_path"
        ) as m_resolve:
            rc = ccp.main([str(tmp_path), "--integration-id", "Foo", "--static-only"])
        assert rc == 0
        # Explicit path wins → the CSV resolver is never consulted.
        m_resolve.assert_not_called()
        assert m_ai.call_args.kwargs["integration_path"] == tmp_path.resolve()

    def test_neither_errors(self, capsys: pytest.CaptureFixture[str]) -> None:
        ai, ci, rd, el = self._patch_analysis()
        with ai, ci, rd, el:
            rc = ccp.main(["--static-only"])
        assert rc == 2
        assert "one is required" in capsys.readouterr().err

    def test_id_resolution_failure_exits_2(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        ai, ci, rd, el = self._patch_analysis()
        with ai, ci, rd, el, patch.object(
            ccp,
            "resolve_integration_path",
            side_effect=ValueError("stale path"),
        ):
            rc = ccp.main(["--integration-id", "Foo", "--static-only"])
        assert rc == 2
        assert "stale path" in capsys.readouterr().err
