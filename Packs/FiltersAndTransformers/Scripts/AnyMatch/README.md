This filter accepts two inputs, left and right, each of which can be either a single element of any type (e.g., string, int, etc.) or a list of elements. The filter iterates over each element in the left input and returns all elements that match based on the specified match direction. The matching process is case-insensitive, meaning it disregards letter case during the comparison.

All inputs are treated either as a string or as a list of strings, if it contains a comma.
A JSON is always treated as a string.

Since the comparison treats all inputs as strings, integers and strings are considered equal during the evaluation.

## Match Direction

The `match_direction` parameter controls how substring matching is performed:
- **"right in left"** (default): Checks if any element from the right side is a substring of the left element.
- **"left in right"**: Checks if the left element is a substring of any element from the right side.

## Script Data

---

| **Name**             | **Description** |
| -------------------- | --------------- |
| Script Type          | python3         |
| Tags                 | filter          |
| Cortex XSOAR Version | 6.9.0           |

## Inputs

---

| **Argument Name** | **Description**                                                                                                    |
| ----------------- | ------------------------------------------------------------------------------------------------------------------ |
| left              | Value to check if it has a substring that is equal to an element in the right side. Can be a single value or a comma-separated list.                   |
| right             | Value to check if it is equal to an element or to a substring of an element from the left. Can be a single value or a comma-separated list. |
| match_direction   | Direction of substring matching. Options: "right in left" (default) - checks if right elements are substrings of left elements; "left in right" - checks if left elements are substrings of right elements. |

## Outputs

---
There are no outputs for this script.

### Table of examples

#### Default behavior (match_direction = "right in left")

| Left            | Right                   | Result                                               | Explanation                                               |
| --------------- | ----------------------- | ----------------------------------------              | --------------------------------------------------------- |
| 1,2,3           | "1"                     | 1           | Integers are treated as strings.        |
| 1,2,250         | 25,10                   | 250         | A part of 250 exists in the right side. |
| 1               | 21                      |None                                                   |
| 5,1,6,9,65,8    | 1,6                     | 1,6,65                                                |
| a               | holla                   | None                                |
| bca              |    A                   | bca                                 | The filter is case-insensitive. |
| {'alert' {'data': 'x'}}              | x  |{'alert' {'data': 'x'}}                              |
| {'a':1},{'b':2} | {'a':1,'c':2}           | None                          |  `{'a':1,'c':2}`     is nat a part of a value from the left.  |
| {'a':1},{'b':2} | {a:1}                   | None                           | `{a:1}` is not a part of any value from the left.  |
| {key1:value1, key2:value2}  | 1 |{key1:value1, key2:value2}|  A json is treated as a single string, even when there is a comma in it.
| '','            | {'a':1,'c':2}           | '                     | `''` is not a part of `{'a':1,'c':2}`, but `'` is.|

#### With match_direction = "left in right"

| Left            | Right                   | Result                                               | Explanation                                               |
| --------------- | ----------------------- | ----------------------------------------              | --------------------------------------------------------- |
| 'File1.json','File2.zip' | '\ProgramData\File1.json','\Temp\File2.txt' | 'File1.json' | 'File1.json' is found as substring in '\ProgramData\File1.json'. |
| test            | testing,tested          | test                                                  | 'test' is a substring of both 'testing' and 'tested'. |
| abc             | xyzabc               | abc                                                   | 'abc' is found within 'xyzabc. |
