import pytest
import demistomock as demisto
from CommonServerPython import DemistoException, entryTypes, Common
from AggregatedCommandApiModule import *
from datetime import datetime, timedelta, UTC


# =================================================================================================
# == Test Helper Functions
# =================================================================================================
class DummyModule(AggregatedCommand):
    def process_batch_results(self, execution_results):
        pass

    def run(self):
        pass

    def validate_input(self) -> None:
        pass


def stub_modules(mocker, modules_list):
    """
    modules_list: list of dicts with 'brand' and 'state'
    demisto.getModules() will return a dict mapping keys to those dicts.
    """
    fake = {f"m{i}": m for i, m in enumerate(modules_list)}
    mocker.patch.object(demisto, "getModules", return_value=fake)


def build_ioc(
    scores: dict,
    *,
    value: str = "indicator1",
    score: int | None = None,
    custom_fields: dict | None = None,
) -> dict:
    """
    Build a TIM IOC shaped for process_tim_results/create_tim_indicator.
    - scores: mapping of brand -> { "score": int, "context": {...} }
    - value: indicator value
    - score: overall TIM score (optional)
    - custom_fields: lower-cased custom fields (optional)
    """
    out = {
        "value": value,
        "insightCache": {"scores": scores or {}},
    }
    if score is not None:
        out["score"] = score
    if custom_fields is not None:
        out["CustomFields"] = custom_fields
    return out


def as_map(merged_list, value_key):
    """Turn the merged list into {value: results} for easy assertions."""
    return {item[value_key]: item["Results"] for item in merged_list}


def make_entry_result(name, brand, status, msg):
    """Creates an entry result."""
    return EntryResult(command_name=name, args="", brand=brand, status=status, message=msg)


def make_dbot(indicator, vendor, score):
    """A helper to create DBotScore dicts for tests."""
    return {"Indicator": indicator, "Vendor": vendor, "Score": score}


# =================================================================================================
# == Global Mocks & Fixtures
# =================================================================================================
default_indicator = Indicator(
    type="indicator", value_field="Value", context_path_prefix="Indicator(", context_output_mapping={"Score": "Score"}
)


@pytest.fixture
def module_factory():
    """
    Pytest fixture that returns a factory function for creating
    ReputationAggregatedCommand instances with default or custom arguments.
    """

    def _factory(**kwargs):
        """The actual factory function."""
        factory_defaults = {
            "args": {},
            "brands": [],
            "indicator": default_indicator,
            "data": [],
            "final_context_path": "ctx",
            "external_enrichment": False,
            "additional_fields": False,
            "verbose": False,
            "commands": [[]],
        }
        factory_defaults.update(kwargs)
        return ReputationAggregatedCommand(**factory_defaults)

    return _factory


# =================================================================================================
# == Unit Tests
# =================================================================================================


# -------------------------------------------------------------------------------------------------
# -- Level 1: Standalone Helper Functions
# -------------------------------------------------------------------------------------------------
# --- Validation Tests ---
@pytest.mark.parametrize(
    "data, indicator_type, extracted, expected_set",
    [
        # Exact match
        (["https://a.com"], "URL", {"URL": ["https://a.com"]}, {"https://a.com"}),
        # Case-insensitive type
        (["https://a.com"], "url", {"URL": ["https://a.com"]}, {"https://a.com"}),
        # Duplicates in input are OK → output is the deduped extracted set
        (
            ["https://a.com", "https://b.com", "https://b.com"],
            "URL",
            {"URL": ["https://a.com", "https://b.com"]},
            {"https://a.com", "https://b.com"},
        ),
        # Irrelevant types can be present; we only take the requested type
        (["https://a.com"], "URL", {"URL": ["https://a.com"], "Domain": ["irrelevant.com"]}, {"https://a.com"}),
    ],
)
def test_extract_input_success_sets_data(mocker, data, indicator_type, extracted, expected_set):
    """
    Given:
        - Different input lists and extractIndicators outputs.
    When:
        - Calling extract_input.
    Then:
        - self.data is replaced with the deduped extracted set for the requested type.
        - No exception is raised.
    """
    mocker.patch(
        "AggregatedCommandApiModule.execute_command",
        return_value=[{"EntryContext": {"ExtractedIndicators": extracted}}],
    )
    data = extract_indicators(data, indicator_type)
    assert set(data) == expected_set


@pytest.mark.parametrize(
    "data, indicator_type, extracted",
    [
        # No key for the requested type at all
        (["https://a.com"], "URL", {"Domain": ["a.com"]}),
        # Requested key present but empty
        (["https://a.com", "https://b.com"], "URL", {"URL": []}),
        # Completely empty extraction
        (["https://a.com", "https://b.com"], "URL", {}),
    ],
)
def test_extract_input_raises_when_no_valid_indicators(mocker, data, indicator_type, extracted):
    """
    Given:
        - extractIndicators returns no items for the requested indicator type.
    When:
        - Calling extract_input.
    Then:
        - Raises ValueError("No valid indicators found in the input data.").
    """
    mocker.patch(
        "AggregatedCommandApiModule.execute_command",
        return_value=[{"EntryContext": {"ExtractedIndicators": extracted}}],
    )

    with pytest.raises(ValueError, match="No valid indicators found in the input data"):
        data = extract_indicators(data, indicator_type)


def test_extract_input_raises_on_empty_execute_command_result(mocker):
    """
    Given:
        - execute_command('extractIndicators', ...) returns a falsy/empty result.
    When:
        - Calling extract_input.
    Then:
        - Raises DemistoException with a validation failure message.
    """
    mocker.patch("AggregatedCommandApiModule.execute_command", return_value=[])

    with pytest.raises(DemistoException, match="Failed to Validate input using extract indicator"):
        extract_indicators(["https://a.com"], "url")


@pytest.mark.parametrize(
    "dict1, dict2, expected",
    [
        # non-overlapping keys → dict1 extended with dict2
        (
            {"a": {"X": [1]}},
            {"b": {"Y": [2, 3]}},
            {"a": {"X": [1]}, "b": {"Y": [2, 3]}},
        ),
        # overlapping key with nested dict → lists extended
        (
            {"a": {"X": [1], "Z": [9]}},
            {"a": {"X": [2, 3]}},
            {"a": {"X": [1, 2, 3], "Z": [9]}},
        ),
        # overlapping key where dict2 value is not dict → extend at top level
        (
            {"a": [1]},
            {"a": [2, 3]},
            {"a": [1, 2, 3]},
        ),
    ],
)
def test_deep_merge_in_place(dict1, dict2, expected):
    """
    Given:
        - Two dictionaries to merge.
    When:
        - Calling deep_merge_in_place.
    Then:
        - The first dictionary is merged with the second dictionary.
    """
    deep_merge_in_place(dict1, dict2)
    assert dict1 == expected


@pytest.mark.parametrize(
    "nested, expected",
    [
        ([], []),
        ([1, 2, 3], [1, 2, 3]),
        ([1, [2, 3], [[4], 5]], [1, 2, 3, 4, 5]),
        ([[[[]]]], []),
    ],
)
def test_flatten_list(nested, expected):
    """
    Given:
        - A nested list.
    When:
        - Calling flatten_list.
    Then:
        - The list is flattened.
    """
    assert flatten_list(nested) == expected


@pytest.mark.parametrize(
    "initial, path, value, expected",
    [
        ({}, "A", 1, {"A": 1}),
        ({}, "A..B..C", "x", {"A": {"B": {"C": "x"}}}),
        ({}, "List..Items[]", 5, {"List": {"Items": [5]}}),
        ({"List": {"Items": [1]}}, "List..Items[]", 2, {"List": {"Items": [1, 2]}}),
    ],
)
def test_set_dict_value(initial, path, value, expected):
    """
    Given:
        - A dictionary to modify.
        - A path to set the value at.
        - A value to set.
    When:
        - Calling set_dict_value.
    Then:
        - The dictionary is modified.
    """
    set_dict_value(initial, path, value)
    assert initial == expected


@pytest.mark.parametrize(
    "initial, path, expected_value, expected_remaining",
    [
        ({"A": 1}, "A", 1, {}),
        ({"A": {"B": 2}}, "A..B", 2, {"A": {}}),
        ({"X": 1}, "A..B", None, {"X": 1}),
        ({"A": {"C": 3}}, "A..B", None, {"A": {"C": 3}}),
    ],
)
def test_pop_dict_value(initial, path, expected_value, expected_remaining):
    """
    Given:
        - A dictionary to modify.
        - A path to get the value at.
    When:
        - Calling get_and_remove_dict_value.
    Then:
        - The dictionary is modified.
    """
    result = pop_dict_value(initial, path)
    assert result == expected_value
    assert initial == expected_remaining


@pytest.mark.parametrize(
    "input_val, expected",
    [
        (None, False),
        ([], False),
        ([{"Type": entryTypes["note"]}], False),
        ([{"Type": entryTypes["debug"]}], True),
        ({"Type": entryTypes["debug"]}, True),
    ],
)
def test_is_debug_various(input_val, expected):
    """
    Given:
        - A list of entries.
    When:
        - Calling is_debug.
    Then:
        - The list is flattened.
    """
    assert is_debug_entry(input_val) is expected


@pytest.mark.parametrize(
    "data, exceptions, expected",
    [
        # --- Case 1: simple dict with None, empty list, empty dict ---
        ({"a": None, "b": [], "c": {}, "d": 1}, None, {"d": 1}),
        # --- Case 2: keep None if key in exceptions ---
        ({"a": None, "b": [], "c": {}, "d": 1}, {"a"}, {"a": None, "d": 1}),
        # --- Case 3: nested dict with empty values ---
        ({"outer": {"inner1": None, "inner2": []}, "x": "val"}, None, {"x": "val"}),
        # --- Case 4: nested dict with exceptions ---
        ({"outer": {"inner1": None, "inner2": []}, "x": "val"}, {"inner1"}, {"outer": {"inner1": None}, "x": "val"}),
        # --- Case 5: list of dicts ---
        ([{"a": None}, {"b": 2}, {}, []], None, [{"b": 2}]),
        # --- Case 6: list of dicts with exceptions ---
        ([{"a": None}, {"b": 2}, {}, []], {"a"}, [{"a": None}, {"b": 2}]),
        # --- Case 7: deeply nested structures ---
        ({"lvl1": {"lvl2": {"lvl3": None}}, "keep": "ok"}, None, {"keep": "ok"}),
        ({"lvl1": {"lvl2": {"lvl3": None}}, "keep": "ok"}, {"lvl3"}, {"lvl1": {"lvl2": {"lvl3": None}}, "keep": "ok"}),
    ],
)
def test_remove_empty_elements_with_exceptions(data, exceptions, expected):
    """
    Given:
        - A dictionary or list with None, empty dicts/lists, and some values.
        - Optionally, an exceptions set specifying which keys should not be removed.
    When:
        - remove_empty_elements_with_exceptions is called.
    Then:
        - The output should have empty values stripped unless they are in exceptions.
    """
    result = remove_empty_elements_with_exceptions(data, exceptions)
    assert result == expected


# -------------------------------------------------------------------------------------------------
# -- Level 2: Core Class Units (Command + EntryResult)
# -------------------------------------------------------------------------------------------------


def test_entry_result_to_entry():
    """
    Given:
        - An EntryResult instance.
    When:
        - Calling to_entry.
    Then:
        - Returns a dictionary with the expected structure.
    """
    entry_result = EntryResult(
        command_name="test-command",
        args={"arg1": "value1"},
        brand="test-brand",
        status=Status.SUCCESS,
        message="test-message",
    )
    entry = entry_result.to_entry()
    assert entry == {
        "Arguments": {"arg1": "value1"},
        "Brand": "test-brand",
        "Status": "Success",
        "Message": "test-message",
    }


@pytest.mark.parametrize(
    "brands_to_run, ignore_using_brand, expected_result",
    [
        (["brand1", "brand2"], False, {"test-command": {"arg1": "value1", "using-brand": "brand1,brand2"}}),
        ([], False, {"test-command": {"arg1": "value1"}}),
        (["brand1", "brand2"], True, {"test-command": {"arg1": "value1"}}),
    ],
)
def test_to_batch_item_with_brands(brands_to_run, ignore_using_brand, expected_result):
    """
    Given:
        - A Command instance with name and args.
        - A list of brands to run (may be empty).
    When:
        - Calling to_batch_item method with brands.
    Then:
        - Returns a dictionary with the command name as key and args as value.
        - The using-brand parameter is added only when brands are provided.
    """
    cmd = Command(name="test-command", args={"arg1": "value1"}, ignore_using_brand=ignore_using_brand)
    batch_item = cmd.to_batch_item(brands_to_run)

    assert batch_item == expected_result


# -------------------------------------------------------------------------------------------------
# -- Level 3: Core Class Units (BatchExecutor)
# -------------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "results, commands_list, expected_result",
    [
        (
            # One Command return 3 results
            [[{"Brand": "TIM", "Type": 1}, {"Brand": "brandA", "Type": 1}, {"Brand": "TIM", "Type": 1}]],
            [Command(name="test-command", args={"arg1": "value1"})],
            [
                [
                    ({"Brand": "TIM", "Type": 1}, "", ""),
                    ({"Brand": "brandA", "Type": 1}, "", ""),
                    ({"Brand": "TIM", "Type": 1}, "", ""),
                ]
            ],
        ),
        (
            # First and last Command dont return, middle command return 2 results
            [[], [{"Type": 1}, {"Type": 1}], []],
            [Command(name="test", args={"a": "a"}), Command(name="test", args={"a": "a"}), Command(name="test", args={"a": "a"})],
            [[], [({"Type": 1}, "", ""), ({"Type": 1}, "", "")], []],
        ),
        (
            # First command return 2 results one is debug, second Command return only debug
            [[{"Type": 16}, {"Type": 1}], [{"Type": 16}]],
            [Command(name="test", args={"a": "a"}), Command(name="test", args={"a": "a"})],
            [[({"Type": 1}, "", "")], []],
        ),
    ],
)
def test_batch_executer_process_results_various(results, commands_list, expected_result):
    """
    Given:
        - A BatchExecutor instance.
    When:
        - Calling process_results method with results and commands list.
    Then:
        - Returns a list of lists of tuples (result, hr_output, error_message).
    """
    batch_executor = BatchExecutor()
    processed_results = batch_executor.process_results(results, commands_list)
    assert processed_results == expected_result


# -------------------------------------------------------------------------------------------------
# -- Level 3: Core Class Units (ContextBuilder)
# -------------------------------------------------------------------------------------------------
def test_create_indicator_lifts_tim_fields_and_pops_from_tim_result():
    """
    Given:
        - tim_context with one indicator value containing a TIM result and two other brand results.
        - Indicator mapping includes both "Score" and "CVSS".
        - TIM result has Score, CVSS, Status, ModifiedTime.
    When:
        - create_indicator() is called.
    Then:
        - The returned item has top-level Value, TIMScore, TIMCVSS, Status, ModifiedTime.
        - The TIM entry inside "Results" had its Status and ModifiedTime popped out.
        - Non-TIM entries are unchanged.
    """
    indicator = Indicator(
        type="url",
        value_field="Data",
        context_path_prefix="URL(",
        context_output_mapping={"Score": "Score", "CVSS": "CVSS"},
    )
    builder = ContextBuilder(indicator=indicator, final_context_path="X")
    tim = {"Brand": "TIM", "Score": 2, "CVSS": {"Score": 7.1}, "Status": "Fresh", "ModifiedTime": "2025-09-01T00:00:00Z"}
    brand_a = {"Brand": "A", "Score": 3, "Data": "a.com"}
    brand_b = {"Brand": "B", "Score": 1, "Data": "b.com"}
    builder.tim_context = {"indicator1": [tim, brand_a, brand_b]}

    out = builder.create_indicator()
    assert len(out) == 1
    item = out[0]
    # Top-level lifted fields
    assert item["Value"] == "indicator1"
    assert item["TIMScore"] == 2
    assert item["TIMCVSS"] == {"Score": 7.1}
    assert item["Status"] == "Fresh"
    assert item["ModifiedTime"] == "2025-09-01T00:00:00Z"
    # TIM result had Status/ModifiedTime popped
    tim_after = item["Results"][0]
    assert tim_after["Brand"] == "TIM"
    assert "Status" not in tim_after
    assert "ModifiedTime" not in tim_after
    # Non-TIM results untouched
    assert item["Results"][1] == brand_a
    assert item["Results"][2] == brand_b


def test_add_tim_context():
    """
    Given:
        - A ContextBuilder instance.
    When:
        - add_tim_context is called with TIM and DBot score data.
    Then:
        - The internal state should be updated with the provided data.
    """
    builder = ContextBuilder(indicator=default_indicator, final_context_path="Test.Path")
    tim_ctx = {"indicator1": [{"Brand": "brandA", "data": "value"}]}
    dbot_list = [make_dbot("indicator1", "brandA", 2)]

    builder.add_tim_context(tim_ctx, dbot_list)

    assert builder.tim_context == tim_ctx
    assert builder.dbot_context == dbot_list


def test_add_other_commands_results():
    """
    Given:
        - A ContextBuilder instance.
    When:
        - add_other_commands_results is called multiple times.
    Then:
        - The internal other_context dictionary should be correctly updated.
    """
    builder = ContextBuilder(indicator=default_indicator, final_context_path="Test.Path")

    builder.add_other_commands_results({"Command1": {"data": "value1"}})
    builder.add_other_commands_results({"Command2": {"data": "value2"}})

    assert builder.other_context == {"Command1": {"data": "value1"}, "Command2": {"data": "value2"}}


def test_build_preserves_exception_keys_when_empty():
    indicator = Indicator(
        type="url", value_field="Data", context_path_prefix="URL(", context_output_mapping={"Score": "Score", "CVSS": "CVSS"}
    )
    builder = ContextBuilder(indicator=indicator, final_context_path="Test.Path")

    # TIM entry where TIM has no CVSS and explicit None ModifiedTime
    tim_ctx = {"v1": [{"Brand": "TIM", "Score": 2, "ModifiedTime": None, "CVSS": None, "Status": None}]}
    builder.add_tim_context(tim_ctx, dbot_scores=[])

    final_context = builder.build()
    item = final_context["Test.Path(val.Value && val.Value == obj.Value)"][0]
    # Exceptions set in build(): {"TIMCVSS","Status","ModifiedTime"}
    # "ModifiedTime" is None → should be kept
    assert "ModifiedTime" in item
    assert item["ModifiedTime"] is None
    assert "TIMCVSS" in item
    assert item["TIMCVSS"] is None
    assert "Status" in item
    assert item["Status"] is None


# --- Tests for the build() method and its helpers ---
def test_build_extract_tim_score():
    """
    Given:
        - A list of indicator results from various brands.
    When:
        - The build() method is called.
    Then:
        - TIMScore is computed only from entries where Brand == "TIM" (max over those), ignoring others.
    """
    indicator_with_score = Indicator(
        type="test",
        value_field="ID",
        context_path_prefix="Test(",
        context_output_mapping={"Score": "Score"},
    )
    builder = ContextBuilder(indicator=indicator_with_score, final_context_path="Test.Path")

    # Only the TIM scores (5 and 3) should be considered => max is 5
    tim_ctx = {
        "indicator1": [
            {"Score": 5, "Brand": "TIM"},
            {"Score": 8, "Brand": "brandA"},  # should be ignored for TIMScore
            {"Score": 3, "Brand": "TIM"},
        ]
    }
    builder.add_tim_context(tim_ctx, dbot_scores=[])

    final_context = builder.build()
    final_indicator = final_context["Test.Path(val.Value && val.Value == obj.Value)"][0]

    assert final_indicator.get("TIMScore", 0) == 5


# --- 2) MaxScore/MaxVerdict enrichment over all results ---
@pytest.mark.parametrize(
    "results, expected_max, expected_verdict",
    [
        ([{"Score": 1, "Brand": "X"}, {"Score": 3, "Brand": "Y"}, {"Score": 2, "Brand": "TIM"}], 3, "Malicious"),
        ([{"Score": 2, "Brand": "X"}, {"Score": 2, "Brand": "TIM"}], 2, "Suspicious"),
        ([{"Score": 2, "Brand": "TIM"}], 2, "Suspicious"),
    ],
)
def test_build_enriches_final_indicators_correctly(results, expected_max, expected_verdict):
    """
    Given:
        - A set of indicator results.
    When:
        - The build() method is called.
    Then:
        - The final output is enriched with the correct MaxScore and MaxVerdict.
    """
    builder = ContextBuilder(indicator=default_indicator, final_context_path="Test.Path")

    tim_ctx = {"indicator1": results}
    builder.add_tim_context(tim_ctx, dbot_scores=[])

    final_context = builder.build()
    final_indicator = final_context["Test.Path(val.Value && val.Value == obj.Value)"][0]

    assert final_indicator["MaxScore"] == expected_max
    assert final_indicator["MaxVerdict"] == expected_verdict


def test_build_without_tim_context_carries_dbot_and_other():
    """
    Given:
        - No TIM context.
        - Only DBot and Other results present.
    When:
        - build() is called.
    Then:
        - Final context contains DBot + Other but no TIM key.
    """
    builder = ContextBuilder(indicator=default_indicator, final_context_path="Final.Path")
    builder.add_tim_context({}, dbot_scores=[make_dbot("ind1", "V", 1)])
    builder.add_other_commands_results({"K1": {"v": 2}})

    final_ctx = builder.build()
    assert "Final.Path(val.Value && val.Value == obj.Value)" not in final_ctx
    assert Common.DBotScore.CONTEXT_PATH in final_ctx
    assert final_ctx["K1"]["v"] == 2


def test_build_assembles_all_context_types():
    """
    Given:
        - Data for TIM results, DBot scores, and other commands.
    When:
        - The build() method is called.
    Then:
        - The final context should contain all three types of data in the correct paths.
    """
    builder = ContextBuilder(indicator=default_indicator, final_context_path="Test.Path")

    # Add all types of context
    builder.add_tim_context(
        tim_ctx={"indicator1": [{"Score": 3, "Brand": "TIM"}]},
        dbot_scores=[make_dbot("indicator1", "TIM", 3)],
    )
    builder.add_other_commands_results({"Command1": {"data": "value1"}})

    final_context = builder.build()

    # Assert all parts are present
    assert "Test.Path(val.Value && val.Value == obj.Value)" in final_context
    assert final_context["Test.Path(val.Value && val.Value == obj.Value)"][0]["Value"] == "indicator1"
    assert Common.DBotScore.CONTEXT_PATH in final_context
    assert final_context[Common.DBotScore.CONTEXT_PATH][0]["Vendor"] == "TIM"
    assert "Command1" in final_context
    assert final_context["Command1"]["data"] == "value1"


# -------------------------------------------------------------------------------------------------
# -- Level 4: Core Class Units (BrandManager)
# -------------------------------------------------------------------------------------------------


def test_brand_manager_to_run_empty_means_all(mocker):
    """
    Given:
        - Active brands present.
        - No brands requested.
    When:
        - brand_manager.to_run is accessed.
    Then:
        - Returns [] to signal “all brands”.
    """
    stub_modules(mocker, [{"brand": "A", "state": "active"}, {"brand": "B", "state": "active"}])
    module = DummyModule(args={}, brands=[], verbose=False, commands=[])
    assert module.brand_manager.to_run == []


def test_enabled_brands_filters_only_active_brands(mocker):
    """
    Given:
        - demisto.getModules returns some active and inactive brands.
    When:
        - Accessing the enabled_brands property.
    Then:
        - Only the 'active' brands are returned, and a debug message logs the count.
    """
    stub_modules(
        mocker,
        [
            {"brand": "A", "state": "active"},
            {"brand": "B", "state": "inactive"},
            {"brand": "C", "state": "active"},
            {"brand": "D", "state": "unknown"},
        ],
    )
    module = DummyModule(args={}, brands=[], verbose=False, commands=[])
    result = module.brand_manager.enabled
    assert set(result) == {"A", "C"}


@pytest.mark.parametrize(
    "modules, input_brands, expected, exception",
    [
        # empty brand list → returns []
        (
            [{"brand": "X", "state": "active"}],
            [],
            [],
            None,
        ),
        # no overlap → raises DemistoException
        (
            [{"brand": "A", "state": "active"}],
            ["X", "Y"],
            None,
            DemistoException,
        ),
        # partial overlap → only A
        (
            [
                {"brand": "A", "state": "active"},
                {"brand": "B", "state": "active"},
            ],
            ["A", "C", "D"],
            ["A"],
            None,
        ),
    ],
)
def test_brands_to_run_various(mocker, modules, input_brands, expected, exception):
    """
    Given:
        - Some active brand.
        - A set of user-provided brands.
    When:
        - Accessing brands_to_run.
    Then:
        - Returns the expected list or raises the expected exception based on the intersection between both.
    """
    stub_modules(mocker, modules)
    module = DummyModule(args={}, brands=input_brands, verbose=False, commands=[])

    if exception:
        with pytest.raises(exception):
            _ = module.brand_manager.to_run
    else:
        result = module.brand_manager.to_run
        assert set(result) == set(expected)


@pytest.mark.parametrize(
    "modules, input_brands, expected_missing",
    [
        # no brands provided → always empty
        ([{"brand": "A", "state": "active"}], [], []),
        # one enabled, three requested → missing are the two not enabled
        ([{"brand": "A", "state": "active"}], ["A", "B", "C"], ["B", "C"]),
        # both A and B enabled, both requested → missing is empty
        (
            [
                {"brand": "A", "state": "active"},
                {"brand": "B", "state": "active"},
            ],
            ["A", "B"],
            [],
        ),
        # no modules enabled → all requested are missing
        ([], ["X", "Y"], ["X", "Y"]),
    ],
)
def test_missing_brands_various(mocker, modules, input_brands, expected_missing):
    """
    Given:
        - demisto.getModules returns a mixture of active/inactive brands.
        - A set of user-provided brands.
    When:
        - Accessing missing_brands.
    Then:
        - Returns the expected list of brands that are not enabled.
    """
    stub_modules(mocker, modules)
    module = DummyModule(args={}, brands=input_brands, verbose=False, commands=[])
    result = module.brand_manager.missing
    # order is not guaranteed, so compare as sets
    assert set(result) == set(expected_missing)


# -------------------------------------------------------------------------------------------------
# -- Level 5: AggregatedCommand
# -------------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "enabled_brands, brands, commands_info, expected_unsupported_enrichment_brands",
    [
        # no brands → empty result
        ([], [], [], []),
        # one external command not enabled → one missing
        (
            ["A", "B"],
            ["A", "B", "C"],
            [("A", CommandType.INTERNAL), ("B", CommandType.INTERNAL), ("C", CommandType.EXTERNAL)],
            ["C"],
        ),
    ],
)
def test_unsupported_enrichment_brands_various(
    module_factory, enabled_brands, brands, commands_info, expected_unsupported_enrichment_brands
):
    """
    Given:
        - enabled_brands is mocked directly on the module.
        - module.brands and module.commands are overridden.
    When:
        - Accessing unsupported_enrichment_brands.
    Then:
        - Returns the expected list of external missing brands.
    """
    # instantiate with defaults
    module = module_factory(brands=brands)
    module.brand_manager.enabled = enabled_brands  # directly inject the enabled_brands list

    # override inputs
    module.commands = [
        [Command(name=f"cmd{i}", args={}, brand=brand, command_type=ctype) for i, (brand, ctype) in enumerate(commands_info)]
    ]

    result = module.unsupported_enrichment_brands
    assert set(result) == set(expected_unsupported_enrichment_brands)


# -------------------------------------------------------------------------------------------------
# -- Level 6: ReputationAggregatedCommand
# -------------------------------------------------------------------------------------------------


# --- Prepare Commands Tests ---
@pytest.mark.parametrize(
    "requested_brands, external_enrichment, expected_names",
    [
        ([], False, {"intA", "intB"}),  # no brands, no external → INTERNAL only
        ([], True, {"intA", "intB", "enrichIndicators"}),  # no brands, external → INTERNAL + EXTERNAL
        (["A"], False, {"intA", "enrichIndicators"}),  # brand A, no external → INTERNAL(A)
        (["B"], True, {"intB", "enrichIndicators"}),  # brand B, no external → INTERNAL(B)
        (["X"], False, {"enrichIndicators"}),  # brand not matching INTERNAL → EXTERNAL only
        (["A", "B"], False, {"intA", "intB", "enrichIndicators"}),  # both INTERNAL brands
    ],
)
def test_prepare_commands_various(module_factory, requested_brands, external_enrichment, expected_names):
    """
    Given:
        - A boolean flag indicating whether external enrichment is enabled.
        - Different commands for different brands.
    When:
        - Calling `prepare_commands`.
    Then:
        - If no brands are requested all internal commands are returned.
        - If no brands and external_enrichment=true all commands return.
        - If brands are requested, only the requested internal commands are returned + external commands (e.g., enrichIndicators).
    """
    indicator = Indicator(type="url", value_field="Data", context_path_prefix="URL(", context_output_mapping={})
    cmd_intA = Command(name="intA", args={}, brand="A", command_type=CommandType.INTERNAL)
    cmd_intB = Command(name="intB", args={}, brand="B", command_type=CommandType.INTERNAL)
    cmd_ext = Command(name="enrichIndicators", args={"indicatorsValues": "example.com"}, command_type=CommandType.EXTERNAL)

    all_commands = [cmd_intA, cmd_intB, cmd_ext]
    module = module_factory(brands=requested_brands, indicator=indicator, commands=[all_commands])

    batches = module.prepare_commands_batches(external_enrichment=external_enrichment)
    flattened = [c for batch in batches for c in batch]

    assert {c.name for c in flattened} == expected_names


def test_prepare_commands_includes_builtin(module_factory):
    """
    Given:
        - A builtin command.
    When:
        - Calling `prepare_commands_batches`.
    Then:
        - The builtin command is included in the first batch.
    """
    cmd_bi = Command(name="createNewIndicator", command_type=CommandType.BUILTIN)
    module = module_factory(commands=[[cmd_bi]], brands=["Whatever"], indicator=Indicator("url", "Data", "URL(", {}))
    batches = module.prepare_commands_batches(external_enrichment=False)
    assert any(c.name == "createNewIndicator" for c in batches[0])


@pytest.mark.parametrize(
    "result_tuple, mock_mapped_context_return, expected_entry_status, expected_entry_msg",
    [
        (  # Success
            (
                {"EntryContext": {"DBotScore": [make_dbot("a.com", "VendorA", 2)], "URL": {"Data": "a.com"}}},
                "Human Readable for success",
                "",
            ),
            {"URL": "a.com"},
            Status.SUCCESS,
            "",
        ),
        (  # Success without context
            ({}, "", ""),
            {},
            Status.SUCCESS,
            "No matching indicators found.",
        ),
        (  # Failure with partial context
            (
                {"EntryContext": {"DBotScore": [make_dbot("b.com", "VendorB", 3)]}},
                "Human Readable for error",
                "Command failed",
            ),
            {"Partial": "Data"},
            Status.FAILURE,
            "Command failed",
        ),
        (  # Failure without context
            ({}, "", "error"),
            {},
            Status.FAILURE,
            "error",
        ),
    ],
)
def test_process_single_command_result(
    mocker,
    module_factory,
    result_tuple,
    mock_mapped_context_return,
    expected_entry_status,
    expected_entry_msg,
):
    """
    Given:
        - A result tuple (raw_result, hr_output, error) and a Command object.
    When:
        - Calling _process_single_command_result.
    Then:
        - Ensure the returned tuple of (entry, mapped_context, verbose_output) is correct.
        - The EntryResult status and message should reflect the error state and presence of context.
        - The mapped_context should be correctly extracted from the raw result.
        - The verbose_output should depend on the 'verbose' instance flag.
    """
    module = module_factory()
    mocker.patch.object(module, "map_command_context", return_value=mock_mapped_context_return)
    raw_result, _, _ = result_tuple

    command_obj = Command(name="test-cmd", brand="TestBrand", args={})
    entry, mapped_ctx, verbose_out = module._process_single_command_result(result_tuple, command_obj)

    # Assert
    # --- Assert EntryResult ---
    assert isinstance(entry, EntryResult)
    assert entry.status == expected_entry_status
    assert entry.message == expected_entry_msg
    assert entry.command_name == command_obj.name
    assert entry.brand == command_obj.brand

    # --- Assert Other Return Values ---
    if raw_result.get("EntryContext"):
        assert mapped_ctx == mock_mapped_context_return
    else:
        assert mapped_ctx == {}


# -- TIM Logic --
@pytest.mark.parametrize(
    "iocs,status,message",
    [
        (None, Status.FAILURE, "boom"),
        ([], Status.SUCCESS, "no results"),
        ([], Status.FAILURE, "empty failure"),
        ([{"value": "x"}], Status.FAILURE, "failed despite hits"),
    ],
)
def test_get_indicators_from_tim_early_return(module_factory, mocker, iocs, status, message):
    """
    Given:
        - Different IOCs and status from search_indicators_in_tim.
    When:
        - Calling get_indicators_from_tim.
    Then:
        - Should not process on FAILURE or empty IOCs.
    """
    mod = module_factory(indicator=default_indicator)
    mocker.patch.object(mod, "search_indicators_in_tim", return_value=(iocs, status, message))
    proc = mocker.patch.object(mod, "process_tim_results")

    ctx, entries = mod.get_indicators_from_tim()

    # Shouldn't process on FAILURE or empty IOCs
    proc.assert_not_called()
    assert ctx == {}
    assert isinstance(entries, list)
    assert len(entries) == 1

    entry = entries[0]
    assert entry.command_name == "search-indicators-in-tim"
    assert entry.args == ",".join(mod.data)  # preserves order & comma-join
    assert entry.brand == "TIM"
    # Status on the entry mirrors the status returned by search_indicators_in_tim
    assert entry.status == status
    assert entry.message == message


def test_get_indicators_from_tim_success_passthrough(module_factory, mocker):
    """
    Given:
        - IndicatorsSearcher returns IOCs and Status.SUCCESS.
    When:
        - Calling get_indicators_from_tim.
    Then:
        - Returns IOCs and Status.SUCCESS.
    """
    iocs = [{"value": "https://a.com"}]

    mod = module_factory(indicator=default_indicator)

    mocker.patch.object(mod, "search_indicators_in_tim", return_value=(iocs, Status.SUCCESS, "ok"))

    expected_ctx = {"TIM": {"some": "context"}}
    expected_entries = [object()]  # sentinel list we can identity-check

    proc = mocker.patch.object(
        mod,
        "process_tim_results",
        return_value=(expected_ctx, expected_entries),
    )

    ctx, entries = mod.get_indicators_from_tim()

    proc.assert_called_once_with(iocs)
    assert ctx == expected_ctx
    # Ensure exact passthrough of the entries list
    assert entries is expected_entries


@pytest.mark.parametrize(
    "ioc_input, mock_tim_indicator_return, mock_parse_indicator_side_effect, expected_indicators, expected_entry_msg",
    [
        (
            build_ioc(
                value="ioc.example.com",
                score=2,
                scores={
                    "BrandA": {"score": 2, "context": {"data": "A"}, "Releiability": "High"},
                    "BrandB": {"score": 3, "context": {"data": "B"}, "Releiability": "Medium"},
                },
            ),
            {"Brand": "TIM", "Score": 2},
            {
                "BrandA": ([{"Value": "from_brand_a"}]),
                "BrandB": ([{"Value": "from_brand_b"}]),
            },
            [
                {"Brand": "TIM", "Score": 2},
                {"Value": "from_brand_a"},
                {"Value": "from_brand_b"},
            ],
            "Found indicator from brands: BrandA, BrandB.",
        ),
        (
            build_ioc(value="1.1.1.1", score=1, scores={}),
            {"Brand": "TIM", "Score": 1},
            {},
            [{"Brand": "TIM", "Score": 1}],
            "No matching indicators found.",
        ),
    ],
)
def test_process_single_tim_ioc(
    mocker,
    module_factory,
    ioc_input,
    mock_tim_indicator_return,
    mock_parse_indicator_side_effect,
    expected_indicators,
    expected_entry_msg,
):
    """
    Given:
        - An IOC dictionary representing a result from a TIM search.
    When:
        - Calling _process_single_tim_ioc with the IOC.
    Then:
        - Ensure the returned tuple of (parsed_indicators, entry_result) is correct.
        - The indicators list should include results from both the main TIM object and brand-specific contexts.
        - The EntryResult message should reflect which brands were processed.
    """
    # Arrange
    module = module_factory()
    mocker.patch.object(module, "create_tim_indicator", return_value=mock_tim_indicator_return)

    def side_effect(entry_context, brand, reliability, score):
        # The tuple return is based on the original code's signature for parse_indicator
        return mock_parse_indicator_side_effect.get(brand, [])

    mocker.patch.object(module, "parse_indicator", side_effect=side_effect)

    # Act
    indicators, entry = module._process_single_tim_ioc(ioc_input)

    # Assert
    assert indicators == expected_indicators
    assert isinstance(entry, EntryResult)
    assert entry.command_name == "search-indicators-in-tim"
    assert entry.brand == "TIM"
    assert entry.status == Status.SUCCESS
    assert entry.args == ioc_input.get("value")
    assert entry.message == expected_entry_msg


def test_search_indicators_in_tim_exception_path(module_factory, mocker):
    """
    Given:
        - IndicatorsSearcher raises an exception during construction/iteration.
    When:
        - Calling search_indicators_in_tim.
    Then:
        - Returns empty IOCs, a FAILURE status, and the exception message.
    """
    mod = module_factory()
    mod.data = ["example.com"]

    # Make IndicatorsSearcher blow up
    mocker.patch(
        "AggregatedCommandApiModule.IndicatorsSearcher",
        side_effect=Exception("Failed to search TIM"),
    )

    iocs, status, msg = mod.search_indicators_in_tim()

    assert iocs == []
    assert status == Status.FAILURE
    assert msg == "Failed to search TIM"


@pytest.mark.parametrize(
    "data, pages, expected_iocs, expected_msg",
    [
        # Scenario 1: Search succeeds but finds no matching indicators
        (
            ["a.com", "b.com"],
            [{"iocs": []}],  # iterable yields one page with no iocs
            [],
            "No matching indicators found.",
        ),
        # Scenario 2: Search succeeds and finds indicators (across multiple pages)
        (
            ["a.com", "b.com"],
            [{"iocs": [{"value": "a.com"}]}, {"iocs": [{"value": "b.com"}]}],
            [{"value": "a.com"}, {"value": "b.com"}],
            "",
        ),
    ],
)
def test_search_indicators_in_tim_success(module_factory, mocker, data, pages, expected_iocs, expected_msg):
    """
    Given:
        - A list of indicator values to search for.
    When:
        - Calling the search_indicators_in_tim method.
    Then:
        - It constructs IndicatorsSearcher with the correct query/size.
        - It flattens 'iocs' from pages and returns expected results/message.
    """
    mod = module_factory()
    mod.data = data
    mod.indicator.type = "URL"

    captured = {}

    def _searcher_ctor(*args, **kwargs):
        captured["query"] = kwargs.get("query")

        class _Searcher:
            def __iter__(self):
                return iter(pages)

        return _Searcher()

    searcher_mock = mocker.patch(
        "AggregatedCommandApiModule.IndicatorsSearcher",
        side_effect=_searcher_ctor,
    )
    iocs, status, msg = mod.search_indicators_in_tim()

    assert searcher_mock.call_count == 1

    q = captured.get("query", "")
    assert f"type:{mod.indicator.type}" in q
    for val in data:
        assert f"value:{val}" in q

    assert iocs == expected_iocs
    assert status == Status.SUCCESS
    assert msg == expected_msg


def test_create_tim_indicator_uses_score_and_status(module_factory, mocker):
    """
    Given:
        - A TIM IOC dict that includes an overall 'score'.
        - get_indicator_status_from_ioc returns IndicatorStatus.FRESH.
    When:
        - Calling create_tim_indicator.
    Then:
        - Returns a dict with Brand='TIM', the provided Score, and Status from get_indicator_status_from_ioc.
    """
    mod = module_factory()
    ioc = {"score": 2, "value": "indicator1"}

    status_mock = mocker.patch.object(mod, "get_indicator_status_from_ioc", return_value=IndicatorStatus.FRESH.value)

    res = mod.create_tim_indicator(ioc)

    status_mock.assert_called_once_with(ioc)
    assert res["Status"] == IndicatorStatus.FRESH.value
    assert res["Brand"] == "TIM"
    assert res["Score"] == 2
    assert res["Data"] == "indicator1"
    assert res["ModifiedTime"] is None


@pytest.mark.parametrize(
    "has_manual, modified_mode, expected_status",
    [
        # Manual overrides anything (even recent modification)
        (True, "fresh", IndicatorStatus.MANUAL.value),
        # Fresh if modified within STATUS_FRESHNESS_WINDOW
        (False, "fresh", IndicatorStatus.FRESH.value),
        # Stale if modified long ago
        (False, "stale", IndicatorStatus.STALE.value),
        # Invalid timestamp string → None
        (False, "invalid", None),
        # No modifiedTime and not manual → None
        (False, "none", None),
    ],
)
def test_get_indicator_status_from_ioc_various(module_factory, has_manual, modified_mode, expected_status):
    """
    Given:
        - Various combinations of 'manuallyEditedFields' and 'modifiedTime'.
    When:
        - Calling get_indicator_status_from_ioc.
    Then:
        - Returns MANUAL if 'Score' in manuallyEditedFields.
        - Else FRESH if modifiedTime within freshness window.
        - Else STALE (including invalid/no modifiedTime).
    """
    mod = module_factory()
    now = datetime.now(UTC)

    def iso(dt: datetime) -> str:
        # Code under test accepts 'Z' or '+00:00'; it replaces Z → +00:00, so we emit 'Z' here.
        return dt.isoformat().replace("+00:00", "Z")

    ioc = {}
    if has_manual:
        ioc["manuallyEditedFields"] = {"Score": True}

    if modified_mode == "fresh":
        ioc["modifiedTime"] = iso(now - timedelta(days=1))  # well within 1 week
    elif modified_mode == "stale":
        ioc["modifiedTime"] = iso(now - timedelta(days=30))  # far beyond 1 week
    elif modified_mode == "invalid":
        ioc["modifiedTime"] = "not-a-time"
    elif modified_mode == "none":
        # leave modifiedTime absent
        pass

    status = mod.get_indicator_status_from_ioc(ioc)
    assert status == expected_status


def test_get_indicator_status_from_ioc_boundary_freshness_window(module_factory):
    """
    Given:
        - modifiedTime just inside the STATUS_FRESHNESS_WINDOW.
    When:
        - Calling get_indicator_status_from_ioc.
    Then:
        - Returns FRESH at the boundary (minus 1 second).
    """
    mod = module_factory()
    now = datetime.now(UTC)
    boundary_time = now - STATUS_FRESHNESS_WINDOW + timedelta(hours=1)

    ioc = {"modifiedTime": boundary_time.isoformat().replace("+00:00", "Z")}
    assert mod.get_indicator_status_from_ioc(ioc) == IndicatorStatus.FRESH.value


def test_get_indicator_status_from_ioc_boundary_stale(module_factory):
    """
    Given:
        - modifiedTime just outside the STATUS_FRESHNESS_WINDOW.
    When:
        - Calling get_indicator_status_from_ioc.
    Then:
        - Returns STALE at the boundary (plus 1 second).
    """
    mod = module_factory()
    now = datetime.now(UTC)
    boundary_time = now - STATUS_FRESHNESS_WINDOW - timedelta(seconds=1)

    ioc = {"modifiedTime": boundary_time.isoformat().replace("+00:00", "Z")}
    assert mod.get_indicator_status_from_ioc(ioc) == IndicatorStatus.STALE.value


# --- Summarize Command Results Tests ---
@pytest.mark.parametrize(
    "entries, expect_error",
    [
        # all failed -> error
        ([make_entry_result("c1", "A", Status.FAILURE, "Error"), make_entry_result("c2", "B", Status.FAILURE, "Error")], True),
        # mix of failures + 'No matching...' -> still error (no actual success)
        (
            [
                make_entry_result("c1", "A", Status.FAILURE, "Error"),
                make_entry_result("c2", "B", Status.SUCCESS, "No matching indicators found."),
            ],
            True,
        ),
        # at least one real success (status=Success, empty message) -> success
        ([make_entry_result("c1", "A", Status.SUCCESS, ""), make_entry_result("c2", "B", Status.FAILURE, "Error")], False),
        # single real success -> success
        ([make_entry_result("c1", "A", Status.SUCCESS, "")], False),
        # Only no matching indicators -> success
        (
            [
                make_entry_result("c1", "A", Status.SUCCESS, "No matching indicators found."),
                make_entry_result("c2", "B", Status.SUCCESS, "No matching indicators found."),
            ],
            False,
        ),
    ],
)
def test_summarize_command_results_error_condition(module_factory, mocker, entries, expect_error):
    """
    Given:
        - A list of entries with different statuses and messages.
    When:
        - Calling summarize_command_results.
    Then:
        - Returns an error entry if all commands failed or no indicators were found.
        - Returns a success entry if at least one command was successful.
    """
    mod = module_factory()
    mocker.patch("AggregatedCommandApiModule.tableToMarkdown", return_value="TBL")

    res = mod.summarize_command_results(entries, verbose_outputs=[], final_context={"ctx": 1})

    assert (res.entry_type == entryTypes["error"]) == expect_error


def test_summarize_command_results_appends_unsupported_enrichment_row(module_factory, mocker):
    """
    Given:
        - Unsupported enrichment brands exist ('X','Y').
    When:
        - summarize_command_results is called.
    Then:
        - The HR table includes a row for the unsupported brands.
    """
    mod = module_factory(brands=["X", "Y"])
    # Make the property return our list
    mod.brand_manager.unsupported_external = lambda _commands: ["X", "Y"]

    tbl = mocker.patch("AggregatedCommandApiModule.tableToMarkdown", return_value="TBL")

    entries = [make_entry_result("c1", "A", Status.SUCCESS, "")]
    res = mod.summarize_command_results(entries, verbose_outputs=[], final_context={"ctx": 1})
    assert res.readable_output == "TBL"

    # Inspect the table rows passed to tableToMarkdown
    args, kwargs = tbl.call_args
    table_rows = kwargs.get("t", args[1] if len(args) > 1 else None)
    assert any(
        row.get("Brand") == "X,Y"
        and row.get("Status") == Status.FAILURE.value
        and "Unsupported Command" in (row.get("Message") or "")
        for row in table_rows
    )


# -- Context Mapping --
@pytest.mark.parametrize(
    "mapping, entry, expected",
    [
        # Empty entry
        ({"a..b": "x..y"}, {}, {}),
        # empty mapping
        ({}, {"a": {"b": 10}}, {"a": {"b": 10}}),
        # simple nested mapping
        ({"a..b": "x..y"}, {"a": {"b": 10}}, {"x": {"y": 10}}),
        # mapping to list via '[]'
        ({"a..b": "x..y[]"}, {"a": {"b": 5}}, {"x": {"y": [5]}}),
        # multiple mappings
        ({"a..b": "out..b", "c": "out..c"}, {"a": {"b": 1}, "c": 2}, {"out": {"b": 1, "c": 2}}),
        # mapping is None
        (None, {"a": {"b": 10}}, {}),
    ],
)
def test_map_command_context_basic(module_factory, mapping, entry, expected):
    """
    Given:
        - Various mappings and entry contexts.
    When:
        - Calling map_command_context.
    Then:
        - Returns a dict matching the expected mapped_context.
    """
    module = module_factory()
    # Copy entry so the original in test is not mutated
    entry_copy = {k: (v.copy() if isinstance(v, dict) else v) for k, v in entry.items()}
    result = module.map_command_context(entry_copy, mapping, is_indicator=False)
    assert result == expected


@pytest.mark.parametrize("val", [0, 0.0, "", False])
def test_map_command_context_preserves_falsy_values(module_factory, val):
    module = module_factory(additional_fields=False)
    mapping = {"a..b": "x..y"}
    entry = {"a": {"b": val}}
    out = module.map_command_context(entry, mapping, is_indicator=True)
    assert out == {"x": {"y": val}}


@pytest.mark.parametrize(
    "mapping, entry, is_indicator, additional_fields, expected",
    [
        # is_indicator False even if additional_fields True → no AdditionalFields
        ({"x": "y"}, {"x": 1, "z": 2}, False, True, {"y": 1}),
        # is_indicator True even if additional_fields False → no AdditionalFields
        ({"x": "y"}, {"x": 1, "z": 2}, True, False, {"y": 1}),
        # is_indicator True and additional_fields True → AdditionalFields full
        ({"x": "y"}, {"x": 1, "z": 2}, True, True, {"y": 1, "AdditionalFields": {"z": 2}}),
        # mapping consumes all keys → AdditionalFields empty dict
        ({"m": "n"}, {"m": 5}, True, True, {"n": 5}),
    ],
)
def test_map_command_context_indicator_flag(module_factory, mapping, entry, is_indicator, additional_fields, expected):
    """
    Given:
        - Mapping and entry that may or may not leave leftovers.
        - Flags is_indicator and additional_fields combinations.
    When:
        - Calling map_command_context.
    Then:
        - AdditionalFields only appears when both flags are True.
    """
    module = module_factory(additional_fields=additional_fields)
    entry_copy = {k: (v.copy() if isinstance(v, dict) else v) for k, v in entry.items()}
    result = module.map_command_context(entry_copy, mapping, is_indicator=is_indicator)

    for k, v in expected.items():
        assert result.get(k) == v

    if "AdditionalFields" in expected:
        assert "AdditionalFields" in result
        assert result["AdditionalFields"] == expected["AdditionalFields"]
    else:
        assert "AdditionalFields" not in result
