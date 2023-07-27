This filter accepts two inputs, `left` and `right`, which can each be either a single value of all types (e.g., string, int, etc) or a list of values. The filter iterates over each value in the `left` input and checks if it exists within the `right` input as a complete match or as a substring. The matching process is case-insensitive, meaning it disregards letter case during the comparison.

Moreover, the comparison treats all inputs as strings. Hence, integers and strings are considered equal during the evaluation.

## Script Data

---

| **Name**             | **Description** |
| -------------------- | --------------- |
| Script Type          | python3         |
| Tags                 | filter          |
| Cortex XSOAR Version | 6.9.0          |

## Inputs

---

| **Argument Name** | **Description**                                                                                                    |
| ----------------- | ------------------------------------------------------------------------------------------------------------------ |
| left              | Value to check if it exists in the right side. can be a single value or a comma-separated list.                    |
| right             | Value to check if it includes string or substrings from the left. can be a single value or a comma-separated list. |


## Outputs

---
There are no outputs for this script.


### Truth table for example

| Left            | Right                   | Result                                   | Explanation                                               |
| --------------- | ----------------------- | ---------------------------------------- | --------------------------------------------------------- |
| 1,2,3           | "1"                     | [True, False, False]                     | Integers are treated as strings.                          |
| 1,2             | 25,10                   | [True, True]                             |
| 1               | 1,2,3                   | [True]                                   |
| 1               | 21                      | [True]                                   |
| 5,1,6,9,65,8    | 1,6                     | [False, True, True, False, False, False] |
| a               | holla                  | [True]                                   |
| 1               | 1                       | [True]                                   |
| A               | bca                     | [True]                                   | The filter is case-insensitive.                           |
| a               | ABC                     | [True]                                   |
| x               | {'alert' {'data': 'x'}} | [True]                                   |
| {'a':1},{'b':2} | {'a':1,'c':2}           | [False, False]                           | `{'a':1}` is not in `{'a':1,'c':2}`                           |
| {'a':1},{'b':2} | {a:1}                   | [False, False]                           | `{'a':1}` is not in `{a:1}   `                                |
| '','            | {'a':1,'c':2}           | [False, True]                            | `''` is not in `{'a':1,'c':2}`, but `'` is in` {'a':1,'c':2}` |
