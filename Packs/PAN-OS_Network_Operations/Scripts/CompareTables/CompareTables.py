import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""
Compares two sets of tabular data to find the differences in keys
"""
from dataclasses import dataclass
from typing import List

# -- This is a way to get around trimming commonserverpython on import
try:
    demisto.args()
except:
    from CommonServerPython import *


@dataclass
class Difference:
    """
    :param key: Key with difference
    :param value: Value difference
    :param description: Human readable description of difference
    :param table_id: ID of table
    """
    table_id: str
    key: str
    value: str = None
    description: str = None


@dataclass
class ScriptResult:
    differences: list[Difference]

    _output_prefix = "CompareTables"
    _title = "Table Comparison Result"

    _result_cls = Difference


def compare_two_dicts(left: dict, right: dict):
    differences: list[tuple] = []
    for left_k, left_v in left.items():
        right_v = right.get(left_k)
        if right.get(left_k) != left_v:
            differences.append((f"{left_k} - {left_v}", right_v))

    return differences


def remove_dict_keys(l: list[dict], ignore_keys: list[str]):
    if not ignore_keys:
        return l

    new_list = [{k: v for k, v in d.items() if k not in ignore_keys} for d in l]

    return new_list


def main(left: list, right: list, index_key: str = "id", ignore_keys: list = None, table_id="compare",
         **kwargs) -> ScriptResult:
    """
    Given two tables, compare by keys to look for difference and return the result.
    :param left: Left table
    :param right: Right table
    :param index_key: Key to use as index
    :param ignore_keys: Keys in table dictionary to ignore in comparison
    :param table_id: The string identifier for the table - appears in output
    :param kwargs: Keyword args !no-auto-argument
    """
    differences = []
    if ignore_keys is str:
        ignore_keys = [ignore_keys]

    left = remove_dict_keys(left, ignore_keys)
    right = remove_dict_keys(right, ignore_keys)
    pairs = zip(left, right)
    # Calculate objects missing in right table
    for left_object in left:
        left_value = left_object.get(index_key)
        right_object = next((item for item in right if item.get(index_key) == left_object.get(index_key)),
                            None)
        if not right_object:
            differences.append(Difference(
                key=index_key,
                value=left_value,
                description=f"{left_value} missing.",
                table_id=table_id
            ))

    # Calculate differences where index_key value exists in both
    dict_differences = [(x, y) for x, y in pairs if x != y and x.get(index_key) == y.get(index_key)]
    for left_dict, right_dict in dict_differences:
        dict_differences = compare_two_dicts(left_dict, right_dict)
        s = ", ".join([f"{x} different to {y}" for (x, y) in dict_differences])
        differences.append(Difference(
            key=index_key,
            value=left_dict.get(index_key),
            description=f"{s}",
            table_id=table_id
        ))

    return ScriptResult(
        differences=differences
    )


if __name__ in ('__main__', '__builtin__', 'builtins'):
    result = main(**demisto.args())

    dict_result = [vars(x) for x in result.differences]
    readable_output = tableToMarkdown(result._title, dict_result)
    outputs = {
        "Result": dict_result
    }

    command_result = CommandResults(
        outputs_prefix=result._output_prefix,
        outputs=outputs,
        readable_output=readable_output
    )
    return_results(command_result)
