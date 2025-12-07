import pytest
import demistomock as demisto
from CommonServerPython import DemistoException, entryTypes
from AggregatedCommandApiModule import *
from datetime import datetime, timedelta, timezone


# =================================================================================================
# == Test Helper Functions
# =================================================================================================
class DummyModule(AggregatedCommand):
    def process_batch_results(self, execution_results):
        pass

    def run(self):
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


# =================================================================================================
# == Global Mocks & Fixtures
# =================================================================================================
default_indicator = IndicatorSchema(
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
            "indicator_schema": default_indicator,
            "indicator_instances": [],
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
    "values, mapping, expected",
    [
        # Match first value
        (["md5", "sha256"], {"MD5": "md5"}, "md5"),
        # Match second value
        (["md5", "sha256"], {"SHA256": "sha256"}, "sha256"),
        # Case-insensitive match
        (["AaA"], {"MD5": "aAa"}, "AaA"),
    ],
)
def test_map_back_to_input_basic(values, mapping, expected):
    """
    Given:
        - A list of original values and a mapping of hash field -> value.
    When:
        - Calling map_back_to_input.
    Then:
        - Returns the first original value that matches one of the mapping values (case-insensitive),
          or empty string if none match.
    """
    assert map_back_to_input(values, mapping) == expected


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
    instances, _ = create_and_extract_indicators(data, indicator_type)
    assert {instance.extracted_value for instance in instances} == expected_set


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

    with pytest.raises(ValueError, match="No valid indicators found in the input data."):
        data, _ = create_and_extract_indicators(data, indicator_type)


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

    with pytest.raises(ValueError, match="No valid indicators found in the input data."):
        create_and_extract_indicators(["https://a.com"], "url")


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


@pytest.mark.parametrize(
    "input_val, expected",
    [
        ("d41d8cd98f00b204e9800998ecf8427e", {"MD5": "d41d8cd98f00b204e9800998ecf8427e"}),
        ("da39a3ee5e6b4b0d3255bfef95601890afd80709", {"SHA1": "da39a3ee5e6b4b0d3255bfef95601890afd80709"}),
        (None, {}),
        ("", {}),
    ],
)
def test_build_hash_dict(input_val, expected):
    """
    Given:
        - A hash string (MD5 or SHA1) or empty.
    When:
        - build_hash_dict is called.
    Then:
        - Returns a dict with the correct hash type key (upper case).
    """
    # Note: 'get_hash_type' comes from CommonServerPython.
    # If mocking is needed, patch it. Usually it's available in unit tests via import.
    assert build_hash_dict(input_val) == expected


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
    indicator_schema = IndicatorSchema(
        type="url",
        value_field="Data",
        context_path_prefix="URL(",
        context_output_mapping={"Score": "Score", "CVSS": "CVSS"},
    )
    builder = ContextBuilder(indicator_schema=indicator_schema, final_context_path="X")
    tim = {"Brand": "TIM", "Score": 2, "CVSS": {"Score": 7.1}, "Status": "Fresh", "ModifiedTime": "2025-09-01T00:00:00Z"}
    brand_a = {"Brand": "A", "Score": 3, "Data": "a.com"}
    brand_b = {"Brand": "B", "Score": 1, "Data": "b.com"}
    instance = IndicatorInstance(
        raw_input="indicator1", extracted_value="indicator1", created=True, enriched=True, tim_context=[tim, brand_a, brand_b]
    )
    builder.add_indicator_instances([instance])
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


def test_create_indicator_file_type_adds_hashes_from_tim():
    """
    Given:
        - A ContextBuilder for a file indicator with multiple hash fields.
        - TIM context with a TIM entry that has MD5, SHA1, and SHA256.
    When:
        - create_indicator() is called.
    Then:
        - The resulting item has:
            - Value set to the tim_context key.
            - A 'Hashes' dict with all available hash values.
            - Status and ModifiedTime lifted to the top level.
    """
    file_indicator = IndicatorSchema(
        type="file",
        value_field=["MD5", "SHA1", "SHA256"],
        context_path_prefix="File(",
        context_output_mapping={"Score": "Score"},
    )
    builder = ContextBuilder(
        indicator_schema=file_indicator,
        final_context_path="FileEnrichmentV2(val.Value && val.Value == obj.Value)",
    )

    tim_entry = {
        "Brand": "TIM",
        "MD5": "md5-value",
        "SHA1": "sha1-value",
        "SHA256": "sha256-value",
        "Score": 2,
        "Status": "Fresh",
        "ModifiedTime": "2025-09-01T00:00:00Z",
    }
    file_instance = IndicatorInstance(
        raw_input="file-indicator-key", extracted_value="file-indicator-key", enriched=True, created=True, tim_context=[tim_entry]
    )

    builder.add_indicator_instances([file_instance])

    out = builder.create_indicator()
    assert len(out) == 1
    item = out[0]

    # Top-level value should be the key from tim_context
    assert item["Value"] == "file-indicator-key"

    # Hashes aggregated from the TIM entry
    assert item["Hashes"] == {
        "MD5": "md5-value",
        "SHA1": "sha1-value",
        "SHA256": "sha256-value",
    }

    # Status / ModifiedTime lifted
    assert item["Status"] == "Fresh"
    assert item["ModifiedTime"] == "2025-09-01T00:00:00Z"


def test_add_other_commands_results():
    """
    Given:
        - A ContextBuilder instance.
    When:
        - add_other_commands_results is called multiple times.
    Then:
        - The internal other_context dictionary should be correctly updated.
    """
    builder = ContextBuilder(indicator_schema=default_indicator, final_context_path="Test.Path")

    builder.add_other_commands_results({"Command1": {"data": "value1"}})
    builder.add_other_commands_results({"Command2": {"data": "value2"}})

    assert builder.other_context == {"Command1": {"data": "value1"}, "Command2": {"data": "value2"}}


def test_build_preserves_exception_keys_when_empty():
    indicator = IndicatorSchema(
        type="url", value_field="Data", context_path_prefix="URL(", context_output_mapping={"Score": "Score", "CVSS": "CVSS"}
    )
    builder = ContextBuilder(indicator_schema=indicator, final_context_path="Test.Path")

    # TIM entry where TIM has no CVSS and explicit None ModifiedTime
    instance = IndicatorInstance(
        raw_input="v1",
        extracted_value="v1",
        enriched=True,
        created=True,
        tim_context=[{"Brand": "TIM", "Score": 2, "ModifiedTime": None, "CVSS": None, "Status": None}],
    )
    builder.add_indicator_instances([instance])

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


def test_create_indicator_success_happy_path():
    """
    Given:
        - A Valid input (valid=True).
        - Successfully Enriched (enriched=True).
        - Found in TIM (found=True).
    When:
        - ContextBuilder.create_indicator() is called.
    Then:
        - The result should NOT be an Error.
        - The Status should be lifted from the TIM context (e.g., 'Fresh').
        - The Value should match the extracted value.
    """
    # 1. Setup Instance
    # "found=True" means tim_context is not None/Empty
    tim_data = {"Brand": "TIM", "Status": "Fresh", "Score": 2, "Value": "8.8.8.8"}

    instance = IndicatorInstance(
        raw_input="8.8.8.8",
        extracted_value="8.8.8.8",
        created=True,  # or False, doesn't matter if found+enriched
        enriched=True,
        tim_context=[tim_data],
    )

    # 2. Setup Builder
    # Schema doesn't matter much for the logic flow, just need defaults
    schema = IndicatorSchema("ip", "Address", "IP(", {})
    builder = ContextBuilder(schema, "IPEnrichment")
    builder.add_indicator_instances([instance])

    # 3. Execute
    results = builder.create_indicator()

    # 4. Assertions
    assert len(results) == 1
    res = results[0]

    assert res.get("Status") == "Fresh"  # Came from TIM object
    assert res.get("Value") == "8.8.8.8"
    assert res.get("Message") is None  # No error message on success


@pytest.mark.parametrize(
    "valid, created, enriched, found, expected_msg_part",
    [
        # --- Case 1: Invalid Input ---
        # Logic: if not valid -> Error
        # (Other flags don't matter)
        (False, False, False, False, "Invalid"),
        # --- Case 2: Creation Failed ---
        # Logic: not created and not enriched and not found -> probably not created
        (True, False, False, False, "Failed To Create"),
        # --- Case 3: Enrichment Failed (But Found) ---
        # Logic: not created and not enriched and found
        # (Means it existed in TIM, but the enrichment command failed/wasn't run)
        (True, False, False, True, "Failed to Enrich"),
        # --- Case 4: Enrichment Failed (Created) ---
        # Logic: created and not enriched
        # (Means we created it, but enrichment failed)
        (True, True, False, False, "Failed to Enrich"),
        (True, True, False, True, "Failed to Enrich"),  # Found doesn't matter if didn't enriched
        # --- Case 5: Extraction Failed ---
        # Logic: enriched and not found
        # (Means enrichment command said 'Success', but TIM search returned nothing)
        (True, True, True, False, "Failed to extract"),
        (True, False, True, False, "Failed to extract"),
    ],
)
def test_create_indicator_failure_scenarios(valid, created, enriched, found, expected_msg_part):
    """
    Given:
        - Various combinations of flags resulting in failure.
    When:
        - ContextBuilder.create_indicator() is called.
    Then:
        - The result Status should always be 'Error'.
        - The result Message should match the specific logic branch taken.
    """
    # 1. Setup Data
    extracted = "1.1.1.1" if valid else None
    tim_ctx = [{"Brand": "TIM", "Status": "Fresh"}] if found else None

    instance = IndicatorInstance(
        raw_input="raw_input", extracted_value=extracted, created=created, enriched=enriched, tim_context=tim_ctx, hr_message=""
    )
    # 2. Setup Builder
    schema = IndicatorSchema("ip", "Address", "IP(", {})
    builder = ContextBuilder(schema, "IPEnrichment")
    builder.add_indicator_instances([instance])

    # 3. Execute
    results = builder.create_indicator()

    # 4. Assertions
    assert len(results) == 1
    res = results[0]

    # All these cases must result in Error
    assert res.get("Status") == "Error"

    # Check that the specific error logic path was taken
    actual_msg = res.get("Message", "")
    assert expected_msg_part in actual_msg


# --- Tests for the build() method and its helpers ---
def test_build_extract_tim_score():
    """
    Given:
        - A list of indicator results from various brands.
    When:
        - The build() method is called.
    Then:
        - TIMScore is computed only from entries where Brand == "TIM", ignoring others.
    """
    indicator_with_score = IndicatorSchema(
        type="test",
        value_field="ID",
        context_path_prefix="Test(",
        context_output_mapping={"Score": "Score"},
    )
    builder = ContextBuilder(indicator_schema=indicator_with_score, final_context_path="Test.Path")
    instance = IndicatorInstance(
        raw_input="indicator1",
        extracted_value="indicator1",
        enriched=True,
        created=True,
        tim_context=[
            {"Score": 5, "Brand": "TIM"},
            {"Score": 8, "Brand": "brandA"},  # should be ignored for TIMScore
        ],
    )

    builder.add_indicator_instances([instance])
    # Only the TIM scores (5 and 3) should be considered => max is 5
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
    builder = ContextBuilder(indicator_schema=default_indicator, final_context_path="Test.Path")
    instance = IndicatorInstance(
        raw_input="indicator1", extracted_value="indicator1", enriched=True, created=True, tim_context=results
    )

    builder.add_indicator_instances([instance])

    final_context = builder.build()
    final_indicator = final_context["Test.Path(val.Value && val.Value == obj.Value)"][0]

    assert final_indicator["MaxScore"] == expected_max
    assert final_indicator["MaxVerdict"] == expected_verdict


def test_build_without_tim_context_carries_other():
    """
    Given:
        - No TIM context.
    When:
        - build() is called.
    Then:
        - Final context contains Other but no TIM key.
    """
    builder = ContextBuilder(indicator_schema=default_indicator, final_context_path="Final.Path")
    builder.add_other_commands_results({"K1": {"v": 2}})

    final_ctx = builder.build()
    assert "Final.Path(val.Value && val.Value == obj.Value)" not in final_ctx
    assert final_ctx["K1"]["v"] == 2


def test_build_assembles_all_context_types():
    """
    Given:
        - Data for TIM results, and other commands.
    When:
        - The build() method is called.
    Then:
        - The final context should contain all two types of data in the correct paths.
    """
    builder = ContextBuilder(indicator_schema=default_indicator, final_context_path="Test.Path")

    # Add all types of context
    builder.add_indicator_instances(
        [
            IndicatorInstance(
                raw_input="indicator1",
                extracted_value="indicator1",
                created=True,
                enriched=True,
                tim_context=[{"Score": 3, "Brand": "TIM"}],
            )
        ]
    )

    builder.add_other_commands_results({"Command1": {"data": "value1"}})

    final_context = builder.build()

    # Assert all parts are present
    assert "Test.Path(val.Value && val.Value == obj.Value)" in final_context
    assert final_context["Test.Path(val.Value && val.Value == obj.Value)"][0]["Value"] == "indicator1"
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


def test_internal_enrichment_brands_injected_when_no_brands_and_external_false(module_factory, mocker):
    """
    Given:
        - internal_enrichment_brands configured (e.g., WildFire).
        - No brands explicitly requested.
        - external_enrichment is False.
        - BrandManager.enabled_brands includes the internal enrichment brand.
        - There is also an INTERNAL command with its own brand.
    When:
        - Instantiating ReputationAggregatedCommand.
    Then:
        - self.brands should include both the internal_enrichment_brands and the INTERNAL command brands.
        - prepare_commands_batches should include both INTERNAL and EXTERNAL commands.
    """
    # Patch enabled_brands to simulate active integrations
    mocker.patch("AggregatedCommandApiModule.BrandManager.enabled_brands", return_value={"WildFire-v2", "OtherBrand"})

    cmd_internal = Command(
        name="core-get-hash-analytics-prevalence", args={}, brand="Cortex Core - IR", command_type=CommandType.INTERNAL
    )
    cmd_external = Command(name="enrichIndicators", args={}, command_type=CommandType.EXTERNAL)

    module = module_factory(
        brands=[],  # simulate user didn't pass brands
        external_enrichment=False,
        internal_enrichment_brands=["WildFire-v2"],
        indicator_schema=default_indicator,
        commands=[[cmd_internal, cmd_external]],
    )

    # Brands list should now be union of active internal_enrichment_brands and INTERNAL command brands
    assert set(module.brands) == {"WildFire-v2", "Cortex Core - IR"}

    # And prepare_commands_batches should now include both INTERNAL and EXTERNAL commands
    batches = module.prepare_commands_batches(external_enrichment=False)
    flattened = [c for batch in batches for c in batch]
    assert {c.name for c in flattened} == {"core-get-hash-analytics-prevalence", "enrichIndicators"}


def test_internal_enrichment_brands_not_applied_when_brands_given(module_factory, mocker):
    """
    Given:
        - internal_enrichment_brands configured.
        - User explicitly passes brands in the command args.
        - external_enrichment is False.
        - internal_enrichment_brands are enabled.
    When:
        - Instantiating ReputationAggregatedCommand.
    Then:
        - self.brands remains the user-provided brands (no auto-injection).
    """
    mocker.patch("AggregatedCommandApiModule.BrandManager.enabled_brands", return_value={"WildFire-v2"})

    cmd_internal = Command(name="intA", args={}, brand="A", command_type=CommandType.INTERNAL)
    module = module_factory(
        brands=["UserBrand"],
        external_enrichment=False,
        internal_enrichment_brands=["WildFire-v2"],
        indicator_schema=default_indicator,
        commands=[[cmd_internal]],
    )

    assert module.brands == ["UserBrand"]


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
    indicator = IndicatorSchema(type="url", value_field="Data", context_path_prefix="URL(", context_output_mapping={})
    cmd_intA = Command(name="intA", args={}, brand="A", command_type=CommandType.INTERNAL)
    cmd_intB = Command(name="intB", args={}, brand="B", command_type=CommandType.INTERNAL)
    cmd_ext = Command(name="enrichIndicators", args={"indicatorsValues": "example.com"}, command_type=CommandType.EXTERNAL)

    all_commands = [cmd_intA, cmd_intB, cmd_ext]
    module = module_factory(brands=requested_brands, indicator_schema=indicator, commands=[all_commands])

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
    module = module_factory(commands=[[cmd_bi]], brands=["Whatever"], indicator_schema=IndicatorSchema("url", "Data", "URL(", {}))
    batches = module.prepare_commands_batches(external_enrichment=False)
    assert any(c.name == "createNewIndicator" for c in batches[0])


@pytest.mark.parametrize(
    "result_tuple, mock_mapped_context_return, expected_entry_status, expected_entry_msg",
    [
        (  # Success
            (
                {"EntryContext": {"URL": {"Data": "a.com"}}},
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
                {"EntryContext": {}},
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
    "search_return_value",
    [
        ([]),  # Standard case: Search returns empty list
        (None),  # Edge case: Search returns None
    ],
)
def test_get_indicators_from_tim_early_return(module_factory, mocker, search_return_value):
    """
    Given:
        - search_indicators_in_tim returns an empty list or None.
    When:
        - Calling get_indicators_from_tim.
    Then:
        - process_tim_results should NOT be called.
        - The method should return immediately.
    """
    mod = module_factory(indicator_schema=default_indicator)

    mocker.patch.object(mod, "search_indicators_in_tim", return_value=search_return_value)

    proc = mocker.patch.object(mod, "process_tim_results")

    mod.get_indicators_from_tim()
    proc.assert_not_called()


def test_get_indicators_from_tim_success_passthrough(module_factory, mocker):
    """
    Given:
        - search_indicators_in_tim returns a non-empty list of IOCs.
    When:
        - Calling get_indicators_from_tim.
    Then:
        - The IOCs are passed directly to process_tim_results.
    """
    # 1. Setup
    iocs = [{"value": "https://a.com"}]
    mod = module_factory(indicator_schema=default_indicator)

    # NEW: search_indicators_in_tim returns just the list of IOCs now
    mocker.patch.object(mod, "search_indicators_in_tim", return_value=iocs)

    # NEW: process_tim_results is a void method (updates state via side effects)
    # We just need to mock it to assert it was called.
    proc = mocker.patch.object(mod, "process_tim_results")

    # 2. Execution
    mod.get_indicators_from_tim()

    # 3. Assertion
    # Verify the "Happy Path": Data flowed from Search -> Process
    proc.assert_called_once_with(iocs)


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
                {"Brand": "TIM", "Score": 2, "Value": "ioc.example.com"},
                {"Value": "from_brand_a"},
                {"Value": "from_brand_b"},
            ],
            "Found indicator from brands: BrandA, BrandB.",
        ),
        (
            build_ioc(value="1.1.1.1", score=1, scores={}),
            {"Brand": "TIM", "Score": 1},
            {},
            [{"Brand": "TIM", "Score": 1, "Value": "1.1.1.1"}],
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
        - Ensure the returned tuple is (parsed_indicators, value_string, message_string).
        - The indicators list should include results from both the main TIM object and brand-specific contexts.
        - The returned message should reflect which brands were processed.
    """
    # 1. Arrange
    module = module_factory()

    # The new code does: value = tim_indicator.get("Value", "")
    # We must ensure the mock return dict has the 'Value' so the assertion matches the input.
    if "Value" not in mock_tim_indicator_return:
        mock_tim_indicator_return["Value"] = ioc_input.get("value")

    mocker.patch.object(module, "create_tim_indicator", return_value=mock_tim_indicator_return)

    def side_effect(entry_context, brand, reliability, score):
        return mock_parse_indicator_side_effect.get(brand, [])

    mocker.patch.object(module, "parse_indicator", side_effect=side_effect)

    # 2. Act
    # NEW Signature: returns (list[dict], str, str)
    indicators, value, message = module._process_single_tim_ioc(ioc_input)

    # 3. Assert
    assert indicators == expected_indicators
    # Verify values returned directly in the tuple
    assert value == ioc_input.get("value")
    assert message == expected_entry_msg


def test_search_indicators_in_tim_exception_path(module_factory, mocker):
    """
    Given:
        - IndicatorsSearcher raises an exception during construction/iteration.
    When:
        - Calling search_indicators_in_tim.
    Then:
        - Returns an empty list [].
        - Updates the relevant indicator_instances with the error message.
    """
    # 1. Setup
    # We must provide instances so the code has something to update with the error
    instance = IndicatorInstance(raw_input="example.com", extracted_value="example.com")
    mod = module_factory(indicator_instances=[instance])

    # 2. Mock Exception
    mocker.patch(
        "AggregatedCommandApiModule.IndicatorsSearcher",
        side_effect=Exception("Failed to search TIM"),
    )

    # 3. Execution
    iocs = mod.search_indicators_in_tim()

    # 4. Assertions
    # New code returns empty list on exception
    assert iocs == []

    # New code updates the instance state with the error
    assert instance.hr_message is not None
    assert "Failed to search TIM" in instance.hr_message


@pytest.mark.parametrize(
    "data, pages, expected_iocs",
    [
        # Scenario 1: Search succeeds but finds no matching indicators
        (
            ["a.com", "b.com"],
            [{"iocs": []}],  # iterable yields one page with no iocs
            [],
        ),
        # Scenario 2: Search succeeds and finds indicators (across multiple pages)
        (
            ["a.com", "b.com"],
            [{"iocs": [{"value": "a.com"}]}, {"iocs": [{"value": "b.com"}]}],
            [{"value": "a.com"}, {"value": "b.com"}],
        ),
    ],
)
def test_search_indicators_in_tim_success(module_factory, mocker, data, pages, expected_iocs):
    """
    Given:
        - A list of indicator instances to search for.
    When:
        - Calling the search_indicators_in_tim method.
    Then:
        - It constructs IndicatorsSearcher with the correct query.
        - It flattens 'iocs' from pages and returns just the list of IOCs.
    """
    instances = [IndicatorInstance(raw_input=val, extracted_value=val) for val in data]
    schema = IndicatorSchema(type="URL", value_field="Value", context_path_prefix="URL(", context_output_mapping={})

    mod = module_factory(indicator_instances=instances, indicator_schema=schema)

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

    iocs = mod.search_indicators_in_tim()

    assert searcher_mock.call_count == 1

    q = captured.get("query", "")
    assert f"type:{schema.type}" in q
    for val in data:
        assert f"value:{val}" in q

    assert iocs == expected_iocs


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
    assert res[default_indicator.value_field] == "indicator1"
    assert res["ModifiedTime"] is None


def test_create_tim_indicator_file_type_maps_value_using_hashes(module_factory, mocker):
    """
    Given:
        - A ReputationAggregatedCommand configured for type='file' with multiple hash fields.
        - self.valid_inputs contains the original input hash (MD5) derived from indicator_instances.
        - The TIM IOC 'value' is SHA256, and CustomFields include both md5/sha256.
    When:
        - create_tim_indicator is called.
    Then:
        - The resulting TIM indicator:
            - Has Brand='TIM'.
            - Has MD5/SHA256 fields mapped from CustomFields.
            - Has Value equal to the original input hash (MD5), via map_back_to_input logic.
    """
    # 1. Define Schema
    file_indicator = IndicatorSchema(
        type="file",
        value_field=["MD5", "SHA256"],
        context_path_prefix="File(",
        context_output_mapping={
            "MD5": "MD5",
            "SHA256": "SHA256",
            "Score": "Score",
        },
    )

    original_md5 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    sha256_val = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

    # 2. Setup Instance (New Architecture)
    # The module extracts 'valid_inputs' from these instances
    instance = IndicatorInstance(raw_input=original_md5, extracted_value=original_md5)

    # 3. Initialize Module
    mod = module_factory(
        indicator_schema=file_indicator,
        indicator_instances=[instance],
    )

    # 4. Input IOC from TIM (Main value is SHA256)
    ioc = {
        "score": 3,
        "value": sha256_val,
        "modifiedTime": "2025-09-01T00:00:00Z",
        "CustomFields": {
            "md5": original_md5,
            "sha256": sha256_val,
        },
    }

    # 5. Mock Status Helper
    status_mock = mocker.patch.object(
        mod,
        "get_indicator_status_from_ioc",
        return_value=IndicatorStatus.FRESH.value,
    )

    # 6. Execute
    res = mod.create_tim_indicator(ioc)

    # 7. Assertions
    status_mock.assert_called_once_with(ioc)

    assert res["Brand"] == "TIM"
    assert res["Score"] == 3
    assert res["Status"] == IndicatorStatus.FRESH.value
    assert res["ModifiedTime"] == "2025-09-01T00:00:00Z"

    # Hash fields mapped from CustomFields
    assert res["MD5"] == original_md5
    assert res["SHA256"] == sha256_val

    # For file indicators, Value is mapped back to the original input (MD5)
    # instead of the TIM 'value' (SHA256)
    assert res["Value"] == original_md5


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
    now = datetime.now(timezone.utc)

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
    now = datetime.now(timezone.utc)
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
    now = datetime.now(timezone.utc)
    boundary_time = now - STATUS_FRESHNESS_WINDOW - timedelta(seconds=1)

    ioc = {"modifiedTime": boundary_time.isoformat().replace("+00:00", "Z")}
    assert mod.get_indicator_status_from_ioc(ioc) == IndicatorStatus.STALE.value


def test_update_indicator_instances_status_logic(module_factory):
    """
    Given:
        - A module with indicator instances.
        - EntryResults simulating command executions:
            1. CreateNewIndicatorsOnly -> Success
            2. enrichIndicators -> Failure
    When:
        - update_indicator_instances_status is called.
    Then:
        - The instances should be updated:
            - created = True
            - enriched = False
            - error_message should contain the enrichment error.
            - final_status should be FAILURE (because of error).
    """
    # 1. Setup
    instance = IndicatorInstance(raw_input="8.8.8.8", extracted_value="8.8.8.8")
    mod = module_factory(indicator_instances=[instance])

    # Simulate command results already stored in the module
    mod.entry_results = [
        EntryResult(command_name="CreateNewIndicatorsOnly", brand="Builtin", status=Status.SUCCESS, message="Created", args={}),
        EntryResult(command_name="enrichIndicators", brand="External", status=Status.FAILURE, message="Quota exceeded", args={}),
    ]

    # 2. Execute
    mod.update_indicator_instances_status()

    # 3. Assertions
    assert instance.created is True
    assert instance.enriched is False
    assert instance.error_message
    assert "Quota exceeded" in instance.error_message
    assert instance.final_status == Status.FAILURE


def test_create_indicators_entry_results(module_factory):
    """
    Given:
        - IndicatorInstances with specific final statuses.
        - Existing command entry results.
    When:
        - create_indicators_entry_results is called.
    Then:
        - New EntryResult objects (Brand='TIM') are PREPENDED to the list.
    """
    # 1. Setup
    instance = IndicatorInstance(raw_input="1.1.1.1", extracted_value="1.1.1.1", final_status=Status.SUCCESS, hr_message="Found")
    mod = module_factory(indicator_instances=[instance])

    # Existing entry (e.g., from an enrichment command)
    existing_entry = EntryResult("cmd", {}, "brand", Status.SUCCESS, "")
    mod.entry_results = [existing_entry]

    # 2. Execute
    mod.create_indicators_entry_results()

    # 3. Assertions
    assert len(mod.entry_results) == 2

    # The TIM entry should be first
    tim_entry = mod.entry_results[0]
    assert tim_entry.brand == "TIM"
    assert tim_entry.args == "1.1.1.1"
    assert tim_entry.status == Status.SUCCESS
    assert tim_entry.message == "Found"

    # The existing entry remains
    assert mod.entry_results[1] == existing_entry


@pytest.mark.parametrize(
    "entries, expect_error",
    [
        # 1. All failed -> Error
        ([make_entry_result("c1", "A", Status.FAILURE, "Error"), make_entry_result("c2", "B", Status.FAILURE, "Error")], True),
        # 2. Mix of failures + 'No matching...' (soft failure) -> Error (because no actual success occurred)
        (
            [
                make_entry_result("c1", "A", Status.FAILURE, "Error"),
                make_entry_result("c2", "B", Status.SUCCESS, "No matching indicators found."),
            ],
            True,
        ),
        # 3. At least one real success (Status.SUCCESS + empty/valid message) -> Success
        ([make_entry_result("c1", "A", Status.SUCCESS, ""), make_entry_result("c2", "B", Status.FAILURE, "Error")], False),
        # 4. Single real success -> Success
        ([make_entry_result("c1", "A", Status.SUCCESS, "")], False),
        # 5. Only 'No matching indicators found' -> Success (This is a valid state, not a system error)
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
        - Returns an error entry type if all commands failed or no indicators were found (and some failed).
        - Returns a success entry type if at least one command was successful.
    """
    # 1. Setup
    mod = module_factory()

    # Mock table generation to avoid formatting logic errors
    mocker.patch("AggregatedCommandApiModule.tableToMarkdown", return_value="TBL")

    # Mock this internal method to prevent it from modifying 'self.entry_results' or side-loading data
    # We want to test ONLY the logic applied to the 'entries' argument passed in.
    mocker.patch.object(mod, "create_indicators_entry_results")

    # 2. Act
    # REMOVED: verbose_outputs argument (now part of instance state)
    mod.entry_results = entries
    res = mod.summarize_command_results(final_context={"ctx": 1})

    # 3. Assert
    assert (res.entry_type == entryTypes["error"]) == expect_error


def test_summarize_command_results_appends_unsupported_enrichment_row(module_factory, mocker):
    """
    Given:
        - Unsupported enrichment brands exist ('X','Y').
    When:
        - summarize_command_results is called.
    Then:
        - The HR table includes a row for each unsupported brand.
    """
    mod = module_factory(brands=["X", "Y"])
    # Make the property return our list via BrandManager
    mod.brand_manager.unsupported_external = lambda _commands: ["X", "Y"]

    tbl = mocker.patch("AggregatedCommandApiModule.tableToMarkdown", return_value="TBL")

    mod.entry_results = [make_entry_result("c1", "A", Status.SUCCESS, "")]
    res = mod.summarize_command_results(final_context={"ctx": 1})
    assert res.readable_output == "TBL"

    # Inspect the table rows passed to tableToMarkdown
    args, kwargs = tbl.call_args
    table_rows = kwargs.get("t", args[1] if len(args) > 1 else None)

    # There should be separate rows for X and Y, each marked as failure with the unsupported message
    for brand in ("X", "Y"):
        row = next(r for r in table_rows if r.get("Brand") == brand)
        assert row.get("Status") == Status.FAILURE.value
        assert "Unsupported Command" in (row.get("Message") or "")


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
