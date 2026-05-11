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
        assert d.to_dict() == {"status": "ok", "captured_requests": 5}

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
