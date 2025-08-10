import pytest
import demistomock as demisto
from AggregatedCommandApiModule import *

indicator = Indicator(type="indicator", value_field="Value", context_path_prefix="Indicator(", mapping={})

def make_module(additional_fields=False, indicator=indicator):
    """
    Helper to construct a ReputationAggregatedCommand with minimal required args.
    """
    return ReputationAggregatedCommand(
        args={},
        brands=[],
        indicator=indicator,
        data=[],
        final_context_path="ctx",
        external_enrichment=False,
        additional_fields=additional_fields,
        verbose=False,
        commands=[],
    )

def make_entry(indicators, dbots):
    return {
        "Indicator(val.Data && val.Data == obj.Data)": indicators,
        "DBotScore(val.Indicator == obj.Indicator && val.Vendor == obj.Vendor)": dbots,
    }

entryTypes = {
    'note': 1,
    'downloadAgent': 2,
    'file': 3,
    'error': 4,
    'pinned': 5,
    'userManagement': 6,
    'image': 7,
    'playgroundError': 8,
    'entryInfoFile': 9,
    'warning': 11,
    'map': 15,
    'debug': 16,
    'widget': 17
}
### -------------- Helper Functions --------------

# --- Tests for merge_nested_dicts_in_place --------------------------------
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
def test_merge_nested_dicts_in_place(dict1, dict2, expected):
    """
    Given:
        - Two dictionaries to merge.
    When:
        - Calling merge_nested_dicts_in_place.
    Then:
        - The first dictionary is merged with the second dictionary.
    """
    merge_nested_dicts_in_place(dict1, dict2)
    assert dict1 == expected


# --- Tests for flatten_list ------------------------------------------------
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


# --- Tests for set_dict_value ---------------------------------------------
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


# --- Tests for get_and_remove_dict_value -----------------------------------
@pytest.mark.parametrize(
    "initial, path, expected_value, expected_remaining",
    [
        ({"A": 1}, "A", 1, {}),
        ({"A": {"B": 2}}, "A..B", 2, {"A": {}}),
        ({"X": 1}, "A..B", None, {"X": 1}),
        ({"A": {"C": 3}}, "A..B", None, {"A": {"C": 3}}),
    ],
)
def test_get_and_remove_dict_value(initial, path, expected_value, expected_remaining):
    """
    Given:
        - A dictionary to modify.
        - A path to get the value at.
    When:
        - Calling get_and_remove_dict_value.
    Then:
        - The dictionary is modified.
    """
    result = get_and_remove_dict_value(initial, path)
    assert result == expected_value
    assert initial == expected_remaining


# --- Tests for is_debug ----------------------------------------------------
@pytest.mark.parametrize(
    "input_val, expected",
    [
        (None, False),
        ([], False),
        ([{"Type": entryTypes['note']}], False),
        ([{"Type": entryTypes['debug']}], True),
        ({"Type": entryTypes['debug']}, True),
    ],
)
def test_is_debug_various(input_val, expected):
    assert is_debug(input_val) is expected



### -------------- Tests for Command class --------------
# ─────── Tests for Command class ────────────────────────────────────────────────
@pytest.mark.parametrize(
    "brands_to_run,expected_result",
    [
        (["brand1", "brand2"], {"test-command": {"arg1": "value1", "using-brand": "brand1,brand2"}}),
        ([], {"test-command": {"arg1": "value1"}}),
    ],
)
def test_to_batch_item_with_brands(brands_to_run, expected_result):
    """
    Given:
        - A Command instance with name and args
        - A list of brands to run (may be empty)
    When:
        - Calling to_batch_item method with brands
    Then:
        - Returns a dictionary with the command name as key and args as value
        - The using-brand parameter is added only when brands are provided
    """
    cmd = Command(name="test-command", args={"arg1": "value1"})
    batch_item = cmd.to_batch_item(brands_to_run)
    
    assert batch_item == expected_result


### -------------- Tests for AggregatedCommandAPIModule class --------------
# --- A tiny concrete subclass so we can instantiate ---
class DummyModule(AggregatedCommandAPIModule):
    def process_batch_results(self, execution_results):
        pass

    def aggregated_command_main_loop(self):
        pass


# --- Helper to stub demisto.getModules() ---
def stub_modules(mocker, modules_list):
    """
    modules_list: list of dicts with 'brand' and 'state'
    demisto.getModules() will return a dict mapping keys to those dicts.
    """
    fake = {f"m{i}": m for i, m in enumerate(modules_list)}
    mocker.patch.object(demisto, "getModules", return_value=fake)


# --- enabled_brands tests -------------------------------------------
def test_enabled_brands_filters_only_active_brands(mocker):
    """
    Given:
        - demisto.getModules returns some active and inactive brands.
    When:
        - Accessing the enabled_brands property.
    Then:
        - Only the 'active' brands are returned, and a debug message logs the count.
    """
    stub_modules(mocker, [
        {"brand": "A", "state": "active"},
        {"brand": "B", "state": "inactive"},
        {"brand": "C", "state": "active"},
    ])
    m = DummyModule(args={}, brands=[], verbose=False, commands=[])
    result = m.enabled_brands
    assert set(result) == {"A", "C"}


# --- brands_to_run tests -------------------------------------------
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
        - demisto.getModules returns various active/inactive brands.
        - A set of user-provided brands.
    When:
        - Accessing brands_to_run.
    Then:
        - Returns the expected list or raises the expected exception.
    """
    stub_modules(mocker, modules)
    module = DummyModule(args={}, brands=input_brands, verbose=False, commands=[])

    if exception:
        with pytest.raises(exception):
            _ = module.brands_to_run
    else:
        result = module.brands_to_run
        assert result == expected or set(result) == set(expected)
        
# --- missing_brands tests -------------------------------------------
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
    result = module.missing_brands
    # order is not guaranteed, so compare as sets
    assert set(result) == set(expected_missing)

# --- external_missing_brands tests -------------------------------------------
@pytest.mark.parametrize(
    "enabled_brands, brands, commands_info, expected_external_missing",
    [
        # no brands → empty result
        ([], [], [], []),
        (
            ["A", "B"],
            ["A", "B", "C"],
            [("A", CommandType.INTERNAL), ("B", CommandType.INTERNAL), ("C", CommandType.EXTERNAL)],
            ["C"],
        ),
    ],
)
def test_external_missing_brands_various(mocker, enabled_brands, brands, commands_info, expected_external_missing):
    """
    Given:
        - enabled_brands is mocked directly on the module.
        - module.brands and module.commands are overridden.
    When:
        - Accessing external_missing_brands.
    Then:
        - Returns the expected list of external missing brands.
    """
    # instantiate with defaults
    module = DummyModule(args={}, brands=brands, verbose=False, commands=[])
    module.enabled_brands = enabled_brands  # directly inject the enabled_brands list

    # override inputs
    module.brands = brands
    module.commands = [
        Command(name=f"cmd{i}", args={}, brand=brand, command_type=ctype)
        for i, (brand, ctype) in enumerate(commands_info)
    ]

    result = module.external_missing_brands
    assert set(result) == set(expected_external_missing)

### -------------- Tests for ReputationAggregatedCommand class --------------
@pytest.mark.parametrize(
    "requested_brands, external_enrichment, expected_names",
    [
        ([], False, ["intA", "intB"]),                 # no brands, no external → INTERNAL only
        ([], True,  ["intA", "intB", "url"]),          # no brands, external → INTERNAL + EXTERNAL
        (["A"], False, ["intA", "url"]),               # brand A, no external → INTERNAL(A)
        (["B"], True, ["intB", "url"]),               # brand B, no external → INTERNAL(B)
        (["X"], False, ["url"]),                       # brand not matching INTERNAL → EXTERNAL only
        (["A","B"], False, ["intA","intB", "url"]),     # both INTERNAL brands
    ],
)
def test_prepare_commands_various(requested_brands, external_enrichment, expected_names):
    """
    Given:
        - A ReputationAggregatedCommand instance.
        - A set of requested brands.
        - A boolean flag indicating whether external enrichment is enabled.
    When:
        - Calling `prepare_commands`.
    Then:
        - If no brands are requested all internal commands are returned.
        - If no brands and external_enrichment=true all commands return
        - If brands are requested, only the requested internal commands are returned + reputation commands.
    """
    indicator = Indicator(type="url", value_field="Data", context_path_prefix="URL(", mapping={})
    cmd_intA = Command(name="intA", args={}, brand="A", command_type=CommandType.INTERNAL)
    cmd_intB = Command(name="intB", args={}, brand="B", command_type=CommandType.INTERNAL)
    cmd_ext  = ReputationCommand(indicator=indicator, data="example.com")  # name == "url"
    all_commands = [cmd_intA, cmd_intB, cmd_ext]

    module = ReputationAggregatedCommand(
        args={},
        brands=requested_brands,
        indicator=indicator,
        data=[],
        final_context_path="ctx",
        external_enrichment=external_enrichment,   # prepare_commands takes the flag explicitly
        additional_fields=False,
        verbose=False,
        commands=all_commands,
        validate_input_function=lambda _: None,
    )

    result = module.prepare_commands(external_enrichment=external_enrichment)
    assert {c.name for c in result} == set(expected_names)

# --- map_command_context tests -------------------------------------------
@pytest.mark.parametrize(
    "mapping, entry, expected",
    [
        # Empty entry
        (
            {"a..b": "x..y"},
            {},
            {},
        ),
        # empty mapping
        (
            {},
            {"a": {"b": 10}},
            {"a": {"b": 10}},
        ),
        # simple nested mapping
        (
            {"a..b": "x..y"},
            {"a": {"b": 10}},
            {"x": {"y": 10}},
        ),
        # mapping to list via '[]'
        (
            {"a..b": "x..y[]"},
            {"a": {"b": 5}},
            {"x": {"y": [5]}},
        ),
        # multiple mappings
        (
            {"a..b": "out..b", "c": "out..c"},
            {"a": {"b": 1}, "c": 2},
            {"out": {"b": 1, "c": 2}},
        ),
    ],
)
def test_map_command_context_basic(mapping, entry, expected):
    """
    Given:
        - Various mappings and entry contexts.
    When:
        - Calling map_command_context.
    Then:
        - Returns a dict matching the expected mapped_context.
    """
    module = make_module()
    # Copy entry so the original in test is not mutated
    entry_copy = {k: (v.copy() if isinstance(v, dict) else v) for k, v in entry.items()}
    result = module.map_command_context(entry_copy, mapping, is_indicator=False)
    assert result == expected

@pytest.mark.parametrize(
    "mapping, entry, is_indicator, additional_fields, expected",
    [
        # is_indicator False even if additional_fields True → no AdditionalFields
        (
            {"x": "y"}, {"x": 1, "z": 2},
            False, True,
            {"y": 1},
        ),
        # is_indicator True even if additional_fields False → no AdditionalFields
        (
            {"x": "y"}, {"x": 1, "z": 2},
            True, False,
            {"y": 1},
        ),
        # is_indicator True and additional_fields True → AdditionalFields full
        (
            {"x": "y"}, {"x": 1, "z": 2},
            True, True,
            {"y": 1, "AdditionalFields": {"z": 2}},
        ),
        # mapping consumes all keys → AdditionalFields empty dict
        (
            {"m": "n"}, {"m": 5},
            True, True,
            {"n": 5, "AdditionalFields": {}},
        ),
    ],
)
def test_map_command_context_indicator_flag(mapping, entry, is_indicator, additional_fields, expected):
    """
    Given:
        - Mapping and entry that may or may not leave leftovers.
        - Flags is_indicator and additional_fields combinations.
    When:
        - Calling map_command_context.
    Then:
        - AdditionalFields only appears when both flags are True.
    """
    module = make_module(additional_fields=additional_fields)
    entry_copy = {k: (v.copy() if isinstance(v, dict) else v) for k, v in entry.items()}
    result = module.map_command_context(entry_copy, mapping, is_indicator=is_indicator)

    # Build expected merged structure
    # result may include AdditionalFields if both flags True
    for k, v in expected.items():
        assert result.get(k) == v
    # Check AdditionalFields absence when is_indicator False or additional_fields False
    if not (is_indicator and additional_fields):
        assert "AdditionalFields" not in result
    else:
        assert "AdditionalFields" in result
        
# --- parse_indicator tests ------------------------------------------------------
# --- parse_indicator_dbot_extraction ------------------------------------------
@pytest.mark.parametrize(
    "dbot_list, expected_scores",
    [
        (
            [
                {"Indicator": "https://a.example/", "Vendor": "VendorA", "Score": 2},
                {"Indicator": "https://a.example/", "Vendor": "VendorB", "Score": 3},
            ],
            [2, 3],
        ),
        (
            [{"Indicator": "https://b.example/", "Vendor": "VendorC", "Score": 0}],
            [0],
        ),
        (
            [],
            [],
        ),
    ],
)
def test_parse_indicator_dbot_extraction(dbot_list, expected_scores):
    """
    Given:
        - A list of DBotScore entries.
    When:
        - Calling parse_indicator_dbot_extraction.
    Then:
        - Returns a list of DBotScore entries with the expected scores.
    """
    mod = make_module()
    entry = {
        "URL(val.Data && val.Data == obj.Data)": [],
        "DBotScore(val.Indicator == obj.Indicator && val.Vendor == obj.Vendor)": dbot_list,
    }

    _, dbots = mod.parse_indicator(entry, brand="AnyBrand", score=1)

    assert len(dbots) == len(expected_scores)
    assert [item["Score"] for item in dbots] == expected_scores

# ---------- score precedence & fallback ----------

@pytest.mark.parametrize(
    "explicit_score, dbot_scores, expected_score",
    [
        (3, [1, 2], 3),        # explicit wins over dbot max
        (0, [1, 3], 3),        # no explicit -> use dbot max
        (0, [], 0),            # no explicit & no dbots -> default 0 (Common.DBotScore.NONE)
    ],
)
def test_parse_indicator_score_precedence(explicit_score, dbot_scores, expected_score):
    """
    Given:
        - A list of DBotScore entries.
        - An explicit score.
    When:
        - Calling parse_indicator.
    Then:
        - Score is from explicit score if given (non-zero).
        - If Score is not given, it is from DBotScore max.
        - If no DBotScore entries, it is from Common.DBotScore.NONE.
    """
    # mapping must include "Score" for enrichment to set it
    indicator = Indicator(type="indicator", value_field="Value", context_path_prefix="Indicator(", mapping={"Value": "Value", "Score": "Score"})
    mod = make_module(indicator=indicator)
    entry = make_entry(
        indicators=[{"Value": "https://example.com","Brand":"BrandX"}],
        dbots=[{"Score": s} for s in dbot_scores],
    )
    indicators_ctx, _ = mod.parse_indicator(entry, brand="BrandX", score=explicit_score)

    out = indicators_ctx["https://example.com"]["BrandX"][0]
    assert out["Value"] == "https://example.com"
    assert out["Score"] == expected_score


@pytest.mark.parametrize("verbose, include_hr", [(True, True), (True, False), (False, True), (False, False)])
def test_parse_result_error_no_entry_context(mocker, verbose, include_hr):
    """
    Given:
        - A command result with an error.
    When:
        - Calling parse_result.
    Then:
        - Returns an entry result with status "Failure".
        - Returns an entry result with message "Error Message".
    """
    mod = make_module()
    mod.verbose = verbose

    cmd = ReputationCommand(indicator=indicator, data="example.com")
    result = {}
    if include_hr:
        result["HumanReadable"] = "hr"

    mocker.patch("AggregatedCommandApiModule.is_error", return_value=True)
    mocker.patch("AggregatedCommandApiModule.get_error", return_value="Error Message")
    mocker.patch.object(mod, "parse_indicator", return_value=({"indicator":"indicator"}, []))

    _, _, hr, entry = mod.parse_result(result, cmd, "BrandX")

    assert entry.command_name == cmd.name
    assert entry.brand == "BrandX"
    assert entry.status == "Failure"
    assert entry.args == json.dumps(cmd.args)
    assert entry.message == "Error Message"
    
    if verbose:
        assert "Error Message" in hr
        if include_hr:
            assert "hr" in hr
        else:
            assert "hr" not in hr
    else:
        assert hr == ""

@pytest.mark.parametrize("is_error, command_context",
                         [(True, {}),
                          (False, {}),
                          (True, {"indicator": "indicator"}),
                          (False, {"indicator": "indicator"})])
def test_parse_result_no_matching_indicator(mocker, is_error, command_context):
    """
    Given:
        - A command result with no matching indicator.
    When:
        - Calling parse_result.
    Then:
        - Returns an entry result with status "Success".
        - Returns an entry result with message "No matching indicator found.".
    """
    mod = make_module()
    cmd = ReputationCommand(indicator=indicator, data="example.com")
    mocker.patch("AggregatedCommandApiModule.is_error", return_value=is_error)
    mocker.patch.object(mod, "parse_indicator", return_value=(command_context, []))
    
    _, _, hr, entry = mod.parse_result(result, cmd, "BrandX")
    
    if is_error:
        assert entry.status == "Failure"
        assert entry.message != "No matching indicator found."
    else:
        assert entry.status == "Success"
        if command_context:
            assert entry.message == "No matching indicator found."
        else:
            assert entry.message != "No matching indicator found."
        
