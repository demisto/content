### A transformer for if-elif-else logic

The **If-Elif** transformer simulates a python *"if elif else"* tree using a JSON provided in the *conditions* argument.
The JSON should be a list of dictionaries where all have the keys "*condition*", which holds a boolean expression, and "*return*", which holds the value to return if "*condition*" is evaluated to be true. To return a default value if all "*condition*"s were false, the last dictionary should have only the key "*default*" holding the valid JSON value. If this is not provided an empty string will be returned as a default.
In order to prevent injections, context values should be retrieved from the value entered in the *value (Get)* of the transformer with the hash-curly brackets `#{...}` syntax. This syntax has the same behavior as the classic XSOAR `${...}` syntax and uses the [Cortex XSOAR Transform Language (DT)](https://xsoar.pan.dev/docs/integrations/dt). To provide the full context to the transformer, use `${.}` as the *value (Get)* argument. **Note:** when used as a "*return*" value, this syntax should *not* be surrounded by quotes.  

#### Supported operators for conditions

**Comparison operators** work like Python operators:

| Operator | Name | Example |
| --- | --- | --- |
| == | Equal | x == y |
| != | Not equal | x != y |
| > | Greater than | x > y |
| < | Less than | x < y |
| >= | Greater than or equal to | x >= y |
| <= | Less than or equal to | x <= y |
| in | In | x in y|
| not in | Not in | x not in y|
**Note:** If a comparison is incomparable by nature (e.g., `'a' < 3`), it will evaluate to false.

**Logical operators** also follow the Python syntax:

| Operator | Description | Example |
| --- | --- | --- |
| and | Returns True if both statements are true | x < 5 and x < 10 |
| or | Returns True if one of the statements is true | x < 5 or x < 4 |
| not | Reverse the result, returns False if the result is true | not(x < 5 and x < 10) |

**Regular expressions** are implemented with the "regex_match" function, in the format: `regex_match('pattern', 'string')`. The behavior of the function is controlled with the *flags* argument.

**Literal strings** should preferably be surrounded by single quotes. Do not use `#{...}` in a string, instead, use the `+` operator. For example: `'first ' + #{second.string} + ' third'` will be equal to the common `"first ${second.string} third"`. (This method can be used for lists too.)
**Note:** If the `+` operator is used on distinct types (e.g., `'a' + None`), it will evaluate to `None` (null).

The following flags can be used in the *flags* argument to control the transformer's behavior:

|Flag|Effect|Example|
|---|---|---|
| case_insensitive | Comparisons between strings and regex matches are case-insensitive. | `'WoRd' == 'wOrD'` |
| list_compare | Comparing an object with a list also compares the object with all values in the list and evaluates to true if *any* comparison is true.<br>Works on operators: `<` `>` `<=` `>=` `in` `not in` `+` | `'word' in ['word1', 'word2']` |
| regex_dot_all | Make the `.` special character match any character at all, including a newline. Without this flag, `.` will match anything *except* a newline. | `regex_match('a.b', 'a\nb')` |
| regex_multiline | The patterns `^` and `$` will match the beginning and end of each line respectively as opposed to the beginning and end of the *string*. | `regex_match('^\d$', '1\n2\n')` |
| regex_full_match | Regex patterns will be compared with the whole string to find a match. | `not regex_match('\d+', 'a12345')` |

### Example

---

##### value (Get)

```
${.}
```

##### conditions

```json
[
  {
    "condition": "'www.' + #{domain.name} + '.com' not in #{approved.sites}",
    "return": #{domain.name} + "/home"
  },
  {
    "condition": "#{number} >= 5 and #{path.to.string} == 'Yes'",
    "return": "valid"
  },
  {
    "condition": "regex_match('\d+', #{some.value})",
    "return": #{value.to.return}
  },
  {
    "default": #{default.value}
  }
]
```

##### flags

```
case_insensitive,regex_dot_all,regex_multiline
```

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | transformer, general |
| Cortex XSOAR Version | 6.9.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| value | The object from which to grab values. For the full context use "$\{.\}". |
| conditions | A JSON formatted list, where all but the last items are dictionaries with the keys "condition" (holding a boolean expression) and "return" (holding the value to return if "condition" is true).<br/>The last dictionary can have the key "default" which can hold any valid JSON object to return if no "condition" was true. |
| flags | Flags to control comparison and regular expression behavior. Possible values are: case_insensitive, list_compare, regex_dot_all, regex_multiline, regex_full_match. |

## Outputs

---
There are no outputs for this script.
