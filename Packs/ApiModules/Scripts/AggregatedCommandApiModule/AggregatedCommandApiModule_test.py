import json
import pytest
import demistomock as demisto
from CommonServerPython import DemistoException, entryTypes
from AggregatedCommandApiModule import *

# =================================================================================================
# == Test Helper Functions
# =================================================================================================
class DummyModule(AggregatedCommand):
    def process_batch_results(self, execution_results):
        pass

    def aggregated_command_main_loop(self):
        pass


def stub_modules(mocker, modules_list):
    """
    modules_list: list of dicts with 'brand' and 'state'
    demisto.getModules() will return a dict mapping keys to those dicts.
    """
    fake = {f"m{i}": m for i, m in enumerate(modules_list)}
    mocker.patch.object(demisto, "getModules", return_value=fake)


def make_entry(indicators: list[ContextResult]=[], dbots: list[ContextResult]=[]):
    """The expected entry result under the context from each command result."""
    return {
        "Indicator(val.Data && val.Data == obj.Data)": indicators,
        "DBotScore(val.Indicator == obj.Indicator && val.Vendor == obj.Vendor)": dbots,
    }


def build_ioc(scores: dict) -> dict:
    """The expected ioc result from TIM."""
    return {"insightCache": {"scores": scores}}


def as_map(merged_list, value_key):
    """Turn the merged list into {value: results} for easy assertions."""
    return {item[value_key]: item["results"] for item in merged_list}


def make_entry_result(name, brand, status, msg):
    """Creates an entry result."""
    return EntryResult(command_name=name, args="", brand=brand, status=status, message=msg)

def make_dbot(indicator, vendor, score):
    """A helper to create DBotScore dicts for tests."""
    return {"Indicator": indicator, "Vendor": vendor, "Score": score}

# =================================================================================================
# == Global Mocks & Fixtures
# =================================================================================================
default_indicator = Indicator(type="indicator", value_field="Value", context_path_prefix="Indicator(", context_output_mapping={})

@pytest.fixture
def module_factory():
    """
    Pytest fixture that returns a factory function for creating
    ReputationAggregatedCommand instances with default or custom arguments.
    """

    def _factory(**kwargs):
        """The actual factory function."""
        factory_defaults = {
            "args": {}, "brands": [], "indicator": default_indicator, "data": [],
            "final_context_path": "ctx", "external_enrichment": False,
            "additional_fields": False, "verbose": False, "commands": [],
            "validate_input_function": lambda args: None,
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

@pytest.mark.parametrize(
    "dict1, dict2, expected",
    [
        # non-overlapping keys → dict1 extended with dict2
        ({"a": {"X": [1]}}, {"b": {"Y": [2, 3]}}, {"a": {"X": [1]}, "b": {"Y": [2, 3]}},),
        # overlapping key with nested dict → lists extended
        ({"a": {"X": [1], "Z": [9]}}, {"a": {"X": [2, 3]}}, {"a": {"X": [1, 2, 3], "Z": [9]}},),
        # overlapping key where dict2 value is not dict → extend at top level
        ({"a": [1]}, {"a": [2, 3]}, {"a": [1, 2, 3]},),
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
    result = pop_dict_value(initial, path)
    assert result == expected_value
    assert initial == expected_remaining


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
    """
    Given:
        - A list of entries.
    When:
        - Calling is_debug.
    Then:
        - The list is flattened.
    """
    assert is_debug_entry(input_val) is expected

# -------------------------------------------------------------------------------------------------
# -- Level 2: Core Class Units (Command)
# -------------------------------------------------------------------------------------------------

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
        - A Command instance with name and args.
        - A list of brands to run (may be empty).
    When:
        - Calling to_batch_item method with brands.
    Then:
        - Returns a dictionary with the command name as key and args as value.
        - The using-brand parameter is added only when brands are provided.
    """
    cmd = Command(name="test-command", args={"arg1": "value1"})
    batch_item = cmd.to_batch_item(brands_to_run)

    assert batch_item == expected_result

def test_batch_executor_init_raises_on_empty_commands():
    """
    Given:
        - An empty list of commands.
    When:
        - BatchExecutor is initialized.
    Then:
        - A ValueError is raised.
    """
    with pytest.raises(ValueError, match="called with no commands"):
        BatchExecutor(commands=[])
# -------------------------------------------------------------------------------------------------
# -- Level 3: Core Class Units (ContextBuilder)
# -------------------------------------------------------------------------------------------------

def test_add_reputation_context():
    """
    Given:
        - A ContextBuilder instance.
    When:
        - add_reputation_context is called with reputation and DBot score data.
    Then:
        - The internal state should be updated with the provided data and priority.
    """
    builder = ContextBuilder(indicator=default_indicator, final_context_path="Test.Path")
    rep_ctx = {"indicator1": {"brandA": [{"data": "value"}]}}
    dbot_list = [make_dbot("indicator1", "brandA", 2)]

    builder.add_reputation_context(rep_ctx, dbot_list, priority=10)

    assert len(builder.reputation_context) == 1
    assert builder.reputation_context[0] == (10, rep_ctx)
    assert len(builder.dbot_context) == 1
    assert builder.dbot_context[0] == (10, dbot_list)


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

    assert builder.other_context == {
        "Command1": {"data": "value1"},
        "Command2": {"data": "value2"}
    }
# --- Tests for the build() method and its helpers ---

@pytest.mark.parametrize("batch_map, tim_map, expected_results", [
    # Case 1: Batch only
    (
        {"indicator1": {"brandA": [{"batch": "data"}]}},
        {},
        [{"Value": "indicator1", "max_score": 0, "max_verdict": "Unknown", "results": [{"batch": "data"}]}]
    ),
    # Case 2: TIM only
    (
        {},
        {"indicator1": {"brandA": [{"tim": "data"}]}},
        [{"Value": "indicator1", "max_score": 0, "max_verdict": "Unknown", "results": [{"tim": "data"}]}]
    ),
    # Case 3: Batch overrides TIM for the same brand, but keeps other TIM brands
    (
        {"indicator1": {"brandA": [{"batch": "data"}]}},
        {"indicator1": {"brandA": [{"tim": "ignored"}], "brandB": [{"tim": "kept"}]}},
        [{"Value": "indicator1", "max_score": 0, "max_verdict": "Unknown", "results": [{"batch": "data"}, {"tim": "kept"}]}]
    ),
])
def test_build_merges_indicators_correctly(batch_map, tim_map, expected_results):
    """
    Given:
        - Reputation context from TIM and a batch source with different priorities.
    When:
        - The build() method is called.
    Then:
        - The final context correctly merges indicator results, prioritizing batch data.
    """
    builder = ContextBuilder(indicator=default_indicator, final_context_path="Test.Path")

    builder.add_reputation_context(reputation_ctx=tim_map, dbot_scores=[], priority=10)
    builder.add_reputation_context(reputation_ctx=batch_map, dbot_scores=[], priority=20)

    final_context = builder.build()
    
    assert final_context["Test.Path"] == expected_results


@pytest.mark.parametrize("batch_dbot, tim_dbot, expected_output", [
    # Batch overrides TIM
    (
        [make_dbot("a.com", "brand1", 3)],
        [make_dbot("a.com", "brand1", 1), make_dbot("b.com", "brand2", 2)],
        [make_dbot("a.com", "brand1", 3), make_dbot("b.com", "brand2", 2)]
    ),
    # No overlap
    (
        [make_dbot("a.com", "brand1", 3)],
        [make_dbot("b.com", "brand2", 2)],
        [make_dbot("a.com", "brand1", 3), make_dbot("b.com", "brand2", 2)]
    ),
])
def test_build_merges_dbot_scores_correctly(batch_dbot, tim_dbot, expected_output):
    """
    Given:
        - DBotScore lists from TIM and a batch source with different priorities.
    When:
        - The build() method is called.
    Then:
        - The final DBotScore list is correctly merged and de-duplicated, with batch scores taking priority.
    """
    builder = ContextBuilder(indicator=default_indicator, final_context_path="Test.Path")

    builder.add_reputation_context(reputation_ctx={}, dbot_scores=tim_dbot, priority=10)
    builder.add_reputation_context(reputation_ctx={}, dbot_scores=batch_dbot, priority=20)

    final_context = builder.build()
    
    sort_key = lambda item: (item.get("Indicator"), item.get("Vendor"))
    assert sorted(final_context[Common.DBotScore.CONTEXT_PATH], key=sort_key) == sorted(expected_output, key=sort_key)


@pytest.mark.parametrize("results, expected_max, expected_verdict", [
    ([{"Score": 1}, {"Score": 3}], 3, "Malicious"),
    ([{"Score": 2}], 2, "Suspicious"),
    ([], 0, "Unknown"),
])
def test_build_enriches_final_indicators_correctly(results, expected_max, expected_verdict):
    """
    Given:
        - A set of indicator results.
    When:
        - The build() method is called.
    Then:
        - The final output is enriched with the correct max_score and max_verdict.
    """
    builder = ContextBuilder(indicator=default_indicator, final_context_path="Test.Path")
    batch_context = {"indicator1": {"brandA": results}}
    builder.add_reputation_context(reputation_ctx=batch_context, dbot_scores=[], priority=20)

    final_context = builder.build()

    final_indicator = final_context["Test.Path"][0]
    assert final_indicator["max_score"] == expected_max
    assert final_indicator["max_verdict"] == expected_verdict


def test_build_assembles_all_context_types():
    """
    Given:
        - Data for reputation, DBot scores, and other commands.
    When:
        - The build() method is called.
    Then:
        - The final context should contain all three types of data in the correct paths.
    """
    builder = ContextBuilder(indicator=default_indicator, final_context_path="Test.Path")

    # Add all types of context
    builder.add_reputation_context(
        reputation_ctx={"indicator1": {"brandA": [{"Score": 3}]}},
        dbot_scores=[make_dbot("indicator1", "brandA", 3)],
        priority=10
    )
    builder.add_other_commands_results({"Command1": {"data": "value1"}})

    final_context = builder.build()

    # Assert all parts are present
    assert "Test.Path" in final_context
    assert final_context["Test.Path"][0]["Value"] == "indicator1"
    assert Common.DBotScore.CONTEXT_PATH in final_context
    assert final_context[Common.DBotScore.CONTEXT_PATH][0]["Vendor"] == "brandA"
    assert "Command1" in final_context
    assert final_context["Command1"]["data"] == "value1"
    
    
# -------------------------------------------------------------------------------------------------
# -- Level 4: Base Module Logic (AggregatedCommandAPIModule)
# -------------------------------------------------------------------------------------------------

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
    module = DummyModule(args={}, brands=[], verbose=False, commands=[])
    result = module.enabled_brands
    assert set(result) == {"A", "C"}


@pytest.mark.parametrize(
    "modules, input_brands, expected, exception",
    [
        # empty brand list → returns []
        ([{"brand": "X", "state": "active"}],
            [],
            [],
            None,),
        # no overlap → raises DemistoException
        ([{"brand": "A", "state": "active"}],
            ["X", "Y"],
            None,
            DemistoException,),
        # partial overlap → only A
        ([{"brand": "A", "state": "active"},
            {"brand": "B", "state": "active"},
            ],
            ["A", "C", "D"],
            ["A"],
            None,),
    ],
)
def test_brands_to_run_various(mocker, modules, input_brands, expected, exception):
    """
    Given:
        - demisto.getModules returns various active brands.
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
    result = module.missing_brands
    # order is not guaranteed, so compare as sets
    assert set(result) == set(expected_missing)


# -------------------------------------------------------------------------------------------------
# -- Level 5: ReputationAggregatedCommand Logic (Bottom-Up)
# -------------------------------------------------------------------------------------------------

@pytest.mark.parametrize(
    "enabled_brands, brands, commands_info, expected_external_missing",
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
def test_external_missing_brands_various(module_factory, enabled_brands, brands, commands_info, expected_external_missing):
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
    module = module_factory(brands=brands)
    module.enabled_brands = enabled_brands  # directly inject the enabled_brands list

    # override inputs
    module.commands = [
        Command(name=f"cmd{i}", args={}, brand=brand, command_type=ctype)
        for i, (brand, ctype) in enumerate(commands_info)
    ]

    result = module.external_missing_brands
    assert set(result) == set(expected_external_missing)


@pytest.mark.parametrize(
    "requested_brands, external_enrichment, expected_names",
    [
        ([], False, ["intA", "intB"]),                 # no brands, no external → INTERNAL only
        ([], True, ["intA", "intB", "url"]),          # no brands, external → INTERNAL + EXTERNAL
        (["A"], False, ["intA", "url"]),               # brand A, no external → INTERNAL(A)
        (["B"], True, ["intB", "url"]),               # brand B, no external → INTERNAL(B)
        (["X"], False, ["url"]),                       # brand not matching INTERNAL → EXTERNAL only
        (["A", "B"], False, ["intA", "intB", "url"]),     # both INTERNAL brands
    ],
)
def test_prepare_commands_various(module_factory, requested_brands, external_enrichment, expected_names):
    """
    Given:
        - A ReputationAggregatedCommand instance.
        - A set of requested brands.
        - A boolean flag indicating whether external enrichment is enabled.
    When:
        - Calling `prepare_commands`.
    Then:
        - If no brands are requested all internal commands are returned.
        - If no brands and external_enrichment=true all commands return.
        - If brands are requested, only the requested internal commands are returned + reputation commands.
    """
    indicator = Indicator(type="url", value_field="Data", context_path_prefix="URL(", context_output_mapping={})
    cmd_intA = Command(name="intA", args={}, brand="A", command_type=CommandType.INTERNAL)
    cmd_intB = Command(name="intB", args={}, brand="B", command_type=CommandType.INTERNAL)
    cmd_ext = ReputationCommand(indicator=indicator, data="example.com")  # name == "url"
    all_commands = [cmd_intA, cmd_intB, cmd_ext]

    module = module_factory(
        brands=requested_brands,
        indicator=indicator,
        commands=all_commands
    )

    result = module.prepare_commands(external_enrichment=external_enrichment)
    assert {c.name for c in result} == set(expected_names)

# -- Context Mapping --
@pytest.mark.parametrize(
    "mapping, entry, expected",
    [
        # Empty entry
        ({"a..b": "x..y"},  {},  {}),
        # empty mapping
        ({},  {"a": {"b": 10}},  {"a": {"b": 10}}),
        # simple nested mapping
        ({"a..b": "x..y"},  {"a": {"b": 10}},  {"x": {"y": 10}}),
        # mapping to list via '[]'
        ({"a..b": "x..y[]"},  {"a": {"b": 5}},  {"x": {"y": [5]}}),
        # multiple mappings
        ({"a..b": "out..b", "c": "out..c"},  {"a": {"b": 1}, "c": 2},  {"out": {"b": 1, "c": 2}}),
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
        ({"m": "n"}, {"m": 5}, True, True, {"n": 5, "AdditionalFields": {}}),
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

    if not (is_indicator and additional_fields):
        assert "AdditionalFields" not in result
    else:
        assert "AdditionalFields" in result


# -- Result Parsing --
@pytest.mark.parametrize(
    "entry, expected_scores",
    [
        # single DBotScore entry
        (make_entry(dbots=[{"Indicator": "https://b.example/", "Vendor": "VendorC", "Score": 0}]),
         [0]),
        # no DBotScore entries
        (make_entry(),[])
    ])
def test_parse_indicator_dbot_extraction(module_factory, entry, expected_scores):
    """
    Given:
        - A list of DBotScore entries.
    When:
        - Calling parse_indicator.
    Then:
        - Returns a list of DBotScore entries with the expected scores.
    """
    mod = module_factory()

    _, dbots = mod.parse_indicator(entry, brand="AnyBrand", score=1)

    assert len(dbots) == len(expected_scores)
    assert [item["Score"] for item in dbots] == expected_scores




@pytest.mark.parametrize("verbose, include_hr", [(True, True), (True, False), (False, True), (False, False)])
def test_parse_result_with_error(module_factory, mocker, verbose, include_hr):
    """
    Given:
        - A command result with an error.
        - Verbose is True or False.
        - HumanReadable exists or not.
    When:
        - Calling parse_result.
    Then:
        - Returns an entry result with status "Failure".
        - Returns an entry result with message "Error Message".
    """
    mod = module_factory(verbose=verbose)

    cmd = ReputationCommand(indicator=default_indicator, data="example.com")
    result = {"HumanReadable": "hr_text"} if include_hr else {}

    mocker.patch("AggregatedCommandApiModule.is_error", return_value=True)
    mocker.patch("AggregatedCommandApiModule.get_error", return_value="Error Message")
    mocker.patch.object(mod, "parse_indicator", return_value=({"indicator": "indicator"}, []))

    _, _, hr, entry = mod.parse_result(result, cmd, "BrandX")

    assert entry.command_name == cmd.name
    assert entry.brand == "BrandX"
    assert entry.status == Status.FAILURE
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


@pytest.mark.parametrize("is_error, command_context, expected_status, expected_message",
                         [(True, {}, Status.FAILURE, "Error Message"), # error
                          (False, {}, Status.SUCCESS, "No matching indicators found."), # no matching indicator
                          (False, {"indicator": "indicator"}, Status.SUCCESS, "")]) # success
def test_parse_result_no_matching_indicator(module_factory, mocker, is_error, command_context, expected_status, expected_message):
    """
    Given:
        - Result error or no matching indicator.
    When:
        - Calling parse_result.
    Then:
        - If is error status is fail and appropriate message.
        - If not error and no matching indicator status is success and appropriate message.
    """
    mod = module_factory()
    cmd = ReputationCommand(indicator=default_indicator, data="example.com")
    mocker.patch("AggregatedCommandApiModule.is_error", return_value=is_error)
    mocker.patch("AggregatedCommandApiModule.get_error", return_value="Error Message")
    mocker.patch.object(mod, "parse_indicator", return_value=(command_context, []))

    _, _, _, entry = mod.parse_result({"EntryContext": command_context}, cmd, "BrandX")

    assert entry.status == expected_status
    assert entry.message == expected_message


# -- TIM Logic --
def test_search_indicators_in_tim_exception_path(module_factory, mocker):
    """
    Given:
        - IndicatorsSearcher raises an exception.
    When:
        - Calling search_indicators_in_tim.
    Then:
        - Returns an empty list of IOCs and an entry result with status "Failure" and the exception message.
    """
    mod = module_factory()
    mod.data = ["example.com"]
    mocker.patch(
        "AggregatedCommandApiModule.IndicatorsSearcher",
        side_effect=Exception("Error")
    )
    mocker.patch("AggregatedCommandApiModule.traceback", autospec=True)

    iocs, entry = mod.search_indicators_in_tim()

    assert iocs == []
    assert entry.status == Status.FAILURE
    assert entry.message == "Error"


@pytest.mark.parametrize(
    "data, search_pages, expected_msg",
    [
        # No IOCs → message "No matching indicators found."
        (["a.com", "b.com"],
         [{"iocs": []}],
         "No matching indicators found."),
        # Some IOCs across multiple pages → flattened
        (["a.com", "b.com"],
         [{"iocs": [{"id": 1}]}, {"iocs": [{"id": 2}, {"id": 3}]}],
         ""),
    ],
)
def test_search_indicators_in_tim_success(module_factory, mocker, data, search_pages, expected_msg):
    """
    Given:
        - data list of indicators to search and type.
        - search_pages list of pages of IOCs or empty.
    When:
        - Calling search_indicators_in_tim.
    Then:
        - Construct the query and call IndicatorsSearcher.
        - Return the IOCs and an entry result with status "Success" and the expected message.
    """
    mod = module_factory(data=data)

    ind_mock = mocker.patch(
        "AggregatedCommandApiModule.IndicatorsSearcher",
        return_value=search_pages
    )

    _, entry = mod.search_indicators_in_tim()

    # Called with the right size and query containing type + each value
    assert ind_mock.call_count == 1
    kwargs = ind_mock.call_args.kwargs
    assert kwargs["size"] == len(data)
    q = kwargs["query"]
    assert "type:indicator" in q
    assert "value: a.com" in q
    assert "value: b.com" in q
    # Flattening behavior and entry fields
    assert entry.command_name == "search-indicators-in-tim"
    assert entry.brand == "TIM"
    assert entry.status == Status.SUCCESS
    assert entry.message == expected_msg



@pytest.mark.parametrize(
    "iocs_input, side_effect_returns, expected_ctx, expected_dbots",
    [
        # One IOC, two brands → two calls, merged under the same indicator key
        ([build_ioc({"BrandA": {"score": 1, "context": {"ctx": "A"}},
                    "BrandB": {"score": 3, "context": {"ctx": "B"}}})
          ],
            [({"ind1": {"BrandA": [{"k": "A"}]}}, [{"Score": 7}]),
             ({"ind1": {"BrandB": [{"k": "B"}]}}, [{"Score": 8}])
             ],
            {"ind1": {"BrandA": [{"k": "A"}], "BrandB": [{"k": "B"}]}},
            [{"Score": 7}, {"Score": 8}],
        ),
        # Two IOCs, same brand/key → lists should extend/append
        ([build_ioc({"BrandX": {"score": 2, "context": {"a": 1}}}),
          build_ioc({"BrandX": {"score": 4, "context": {"a": 2}}})
          ],
            [({"indX": {"BrandX": [{"a": 1}]}}, [{"Score": 2}]),
             ({"indX": {"BrandX": [{"a": 2}]}}, [{"Score": 4}])
             ],
            {"indX": {"BrandX": [{"a": 1}, {"a": 2}]}},
            [{"Score": 2}, {"Score": 4}],
        ),
        # IOC missing scores → nothing parsed
        (
            [{"insightCache": {}}],  # no 'scores' key
            [],
            {},
            [],
        ),
        # No IOCs → returns empty ctx/dbots and still returns the single EntryResult from search
        (
            [],
            [],
            {},
            [],
        ),
    ],
)
def test_process_tim_results_merging_and_calls(module_factory, mocker, iocs_input, side_effect_returns, expected_ctx, expected_dbots):
    """
    Given:
        - A list of IOCs with scores and contexts.
        - Expected Context structure as above.
    When:
        - Calling process_tim_results.
    Then:
        - Returns the merged context and accumulated DBotScores.
        - parse_indicator is called with the right arguments.
    """
    mod = module_factory()
    mocker.patch.object(demisto, "debug", autospec=True)
    mocker.patch.object(mod, "parse_indicator", side_effect=side_effect_returns)

    ctx, dbots = mod.process_tim_results(iocs_input)

    assert ctx == expected_ctx
    assert dbots == expected_dbots


@pytest.mark.parametrize(
    "iocs, proc_return, expected_ctx, expected_dbots",
    [
        # No IOCs → returns empty ctx/dbots and still returns the single EntryResult from search
        ([], ({"IGNORED": 1}, [{"Score": 9}]), {}, []),
        # IOCs found → returns whatever process_tim_results returns
        ([{"id": 1}, {"id": 2}], ({"ctx": {"k": "v"}}, [{"Score": 2}]), {"ctx": {"k": "v"}}, [{"Score": 2}]),
    ],
)
def test_get_indicators_from_tim_various(module_factory, mocker, iocs, proc_return, expected_ctx, expected_dbots):
    """
    Given:
        - search_indicators_in_tim returns either no IOCs or some IOCs plus an EntryResult.
    When:
        - Calling get_indicators_from_tim.
    Then:
        - With no IOCs -> {}, [], [entry]
        - With IOCs    -> process_tim_results is called and its return is passed through.
        - Always returns a single-entry list with the same EntryResult (fields compared).
    """
    mod = module_factory()

    search_entry = EntryResult(
        command_name="search-indicators-in-tim",
        args={"query": "type:indicator and (value: x)"},
        brand="TIM",
        status=Status.SUCCESS,
        message="",
    )

    # Patch instance methods called by get_indicators_from_tim
    mocker.patch.object(mod, "search_indicators_in_tim", return_value=(iocs, search_entry))
    mocker.patch.object(mod, "process_tim_results", return_value=proc_return)

    ctx, dbots, entries = mod.get_indicators_from_tim()
    assert ctx == expected_ctx
    assert dbots == expected_dbots

    assert isinstance(entries, list)
    assert len(entries) == 1
    entry = entries[0]
    assert entry.command_name == search_entry.command_name
    assert entry.brand == search_entry.brand
    assert entry.status == search_entry.status
    assert entry.message == search_entry.message
    assert entry.args == search_entry.args



@pytest.mark.parametrize(
    "entries, expect_error",
    [
        # all failed -> error
        ([make_entry_result("c1", "A", Status.FAILURE, "Error"), make_entry_result("c2", "B", Status.FAILURE, "Error")], True),
        # mix of failures + 'No matching...' -> still error (no actual success)
        ([make_entry_result("c1", "A", Status.FAILURE, "Error"), make_entry_result(
            "c2", "B", Status.SUCCESS, "No matching indicators found.")], True),
        # at least one real success (status=Success, empty message) -> success
        ([make_entry_result("c1", "A", Status.SUCCESS, ""), make_entry_result("c2", "B", Status.FAILURE, "Error")], False),
        # single real success -> success
        ([make_entry_result("c1", "A", Status.SUCCESS, "")], False),
        # Mix of failure and no matching indicators -> error
        ([make_entry_result("c1", "A", Status.FAILURE, "Error"),
          make_entry_result("c2", "B", Status.SUCCESS, "No matching indicators found.")], True),
        # Only no matching indicators -> success
        ([make_entry_result("c1", "A", Status.SUCCESS, "No matching indicators found."),
          make_entry_result("c2", "B", Status.SUCCESS, "No matching indicators found.")], False),
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
    mocker.patch.object(mod, "raise_non_enabled_brands_error")
    mocker.patch("AggregatedCommandApiModule.tableToMarkdown", return_value="TBL")

    res = mod.summarize_command_results(entries, verbose_outputs=[], final_context={"ctx": 1})

    assert (res.entry_type == entryTypes['error']) == expect_error

# === Test raise_non_enabled_brands_error ===
def test_raise_non_enabled_brands_error_raises_when_all_unsupported(module_factory):
    """
    Given:
        - A list of entries where all non-TIM commands failed due to being an unsupported brand.
    When:
        - raise_non_enabled_brands_error is called.
    Then:
        - A DemistoException is raised with the specific message.
    """
    module = module_factory()
    entries = [
        make_entry_result("cmd1", "BrandA", "Failure", "Unsupported Command : ..."),
        make_entry_result("cmd2", "BrandB", "Failure", "Unsupported Command : ..."),
    ]

    with pytest.raises(DemistoException, match="None of the commands correspond to an enabled integration instance"):
        module.raise_non_enabled_brands_error(entries)


def test_raise_non_enabled_brands_error_does_not_raise_on_other_failures(module_factory):
    """
    Given:
        - A list of entries with a mix of failures (not all 'Unsupported Command').
    When:
        - raise_non_enabled_brands_error is called.
    Then:
        - No exception is raised.
    """
    module = module_factory()
    entries = [
        make_entry_result("cmd1", "BrandA", "Failure", "Unsupported Command : ..."),
        make_entry_result("cmd2", "BrandB", "Failure", "A different API error"),  # A different error
    ]

    try:
        module.raise_non_enabled_brands_error(entries)
    except DemistoException:
        pytest.fail("raise_non_enabled_brands_error raised an exception unexpectedly.")
