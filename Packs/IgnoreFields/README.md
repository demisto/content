A transformer to remove selected fields from the JSON object.

##### What does this pack do?
- Transform a JSON object to remove the selected fields/keys.
- Works with multiple comma separated keys and can be to an array of JSON objects

---
## Examples

**Input**

```
    {
       "key1":"This field is needed",
       "Key2":"This field is not needed"
    }
```
**Output**

```
    {
        "key1":"This field is needed"
    }