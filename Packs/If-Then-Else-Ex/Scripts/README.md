A transformer to return a value in if-then-else logic.

---
## Script Data

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | transformer, general |

---
## Inputs

| **Argument Name** | **Description** |
| --- | --- |
| value | The value to transform. |
| lhs | The left hand side value to compare with `rhs`. |
| rhs | The right hand side value to compare with `lhs`. |
| operator | The operator to compare `lhs` to `rhs`. |
| then | Return this value if the condition is true. |
| else | Return this value if the condition is not true. |
| transformer_value_key | The special name to return the value given to this transformer. The value given to this transformer is returned if the value come from `then` or `else` matches this value. |


---
## Operators

Available operators

* `===`
* `!==`
* `==`
* `!=`
* `>`
* `>=`
* `<`
* `<=`
* `matches`
* `matches caseless`
* `doesn't match`
* `doesn't match caseless`
* `wildcard: matches`
* `wildcard: matches caseless`
* `wildcard: doesn't match`
* `wildcard: doesn't match caseless`
* `regex: matches`
* `regex: matches caseless`
* `regex: doesn't match`
* `regex: doesn't match caseless`
* `in list`
* `in caseless list`
* `not in list`
* `not in caseless list`
