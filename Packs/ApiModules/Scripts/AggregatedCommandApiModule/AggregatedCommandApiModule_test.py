import pytest
import demistomock as demisto
from AggregatedCommandApiModule import *

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
    
@pytest.mark.parametrize(
    "brands, ext_flag, expected_names",
    [
        # no brands, no external enrichment → only internal
        ([], False, ["intA", "intB"]),
        # no brands, external enrichment → both internal & external
        ([], True, ["intA", "intB", "extC", "extD"]),
        # only A requested, no external enrichment → internal A + all external (because brands non‐empty)
        (["A"], False, ["intA", "extC", "extD"]),
        # brands do not match any internal, no external enrichment → only external
        (["X"], False, ["extC", "extD"]),
        # A & B requested, no external enrichment → all commands
        (["A", "B"], False, ["intA", "intB", "extC", "extD"]),
    ],
)

### -------------- Tests for AggregatedCommandAPIModule class --------------
def test_prepare_commands_various(brands, ext_flag, expected_names):
    """
    Given:
        - A mix of INTERNAL and EXTERNAL commands.
        - Various user-provided `brands` lists and an `external_enrichment` flag.
    When:
        - Calling `prepare_commands(external_enrichment=ext_flag)`.
    Then:
        - Returns exactly the commands matching the internal/external policies.
    """
    # Define a fixed set of commands
    cmd_intA = Command(name="intA", args={}, brand="A", command_type=CommandType.INTERNAL)
    cmd_intB = Command(name="intB", args={}, brand="B", command_type=CommandType.INTERNAL)
    cmd_extC = Command(name="extC", args={}, brand="C", command_type=CommandType.EXTERNAL)
    cmd_extD = Command(name="extD", args={}, brand="D", command_type=CommandType.EXTERNAL)
    all_commands = [cmd_intA, cmd_intB, cmd_extC, cmd_extD]

    # Instantiate with dummy indicator/data/context (not used by prepare_commands)
    module = ReputationAggregatedCommand(
        args={},
        brands=brands,
        indicator=None,
        data=[],
        final_context_path="ctx",
        external_enrichment=False,
        additional_fields=False,
        verbose=False,
        commands=all_commands,
    )

    # Exercise prepare_commands
    result = module.prepare_commands(external_enrichment=ext_flag)
    result_names = [cmd.name for cmd in result]

    # Order isn't important—just the exact set
    assert set(result_names) == set(expected_names)


### -------------- Tests for ReputationAggregatedCommand class --------------
def test_reputation_aggregated_command():
    """
    Given:
        - A ReputationAggregatedCommand instance.
    When:
        - Calling `execute_command`.
    Then:
        - Returns the expected result.
    """
    # Define a fixed set of commands
    cmd_intA = Command(name="intA", args={}, brand="A", command_type=CommandType.INTERNAL)
    cmd_intB = Command(name="intB", args={}, brand="B", command_type=CommandType.INTERNAL)
    cmd_extC = Command(name="extC", args={}, brand="C", command_type=CommandType.EXTERNAL)
    cmd_extD = Command(name="extD", args={}, brand="D", command_type=CommandType.EXTERNAL)
    all_commands = [cmd_intA, cmd_intB, cmd_extC, cmd_extD]

    # Instantiate with dummy indicator/data/context (not used by prepare_commands)
    module = ReputationAggregatedCommand(
        args={},
        brands=[],
        indicator=None,
        data=[],
        final_context_path="ctx",
        external_enrichment=False,
        additional_fields=False,
        verbose=False,
        commands=all_commands,
    )

    # Exercise prepare_commands
    result = module.prepare_commands(external_enrichment=False)
    result_names = {cmd.name for cmd in result}

    # Order isn't important—just the exact set
    assert result_names == {"intA", "intB"}
    
class DummyIndicator:
    def __init__(self, type_):
        self.type = type_

def make_module(additional_fields=False):
    """
    Helper to construct a ReputationAggregatedCommand with minimal required args.
    """
    return ReputationAggregatedCommand(
        args={},
        brands=[],
        indicator=DummyIndicator(type_="T"),
        data=[],
        final_context_path="ctx",
        external_enrichment=False,
        additional_fields=additional_fields,
        verbose=False,
        commands=[],
    )

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
        
# --- parse_indicator tests -------------------------------------------
def test_parse_indicator_dbotscore_extraction_only():
    """
    Given:
        - entry_context containing only DBotScore entries and no indicators.
    When:
        - parse_indicator is called.
    Then:
        - dbot_list contains all flattened DBotScore entries.
        - no indicators are parsed (indicators_context empty).
    """
    entry_context = {
        "DBotScore1": [{"Score": 1}, {"Score": 3}],
        "Indicator": [],
    }
    indicator = DummyIndicator(mapping={"Value": "Value"})
    module = ReputationAggregatedCommand(
        args={}, brands=[], indicator=indicator, data=[], final_context_path="", 
        external_enrichment=False, additional_fields=False, verbose=False, commands=[]
    )
    # Call with score_param=0 (treated as False)
    ctx_copy = {k: v.copy() for k, v in entry_context.items()}
    indicators_context, dbot_list = module.parse_indicator(ctx_copy, brand="X", score=0)

    # dbot_list should include both entries
    assert dbot_list == [{"Score": 1}, {"Score": 3}]


