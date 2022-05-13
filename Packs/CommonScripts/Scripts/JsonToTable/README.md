Accepts a json object and returns a markdown.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | transformer, entirelist, general |
| Cortex XSOAR Version | 5.5.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| value | The json to transform to a markdown table. |
| title | The markdown title. |
| headers | A comma-separated list of table header values. Default will include all available table headers. |
| is_auto_json_transform | Try to auto json transform. |
| json_transform_properties | A json to transform the value to strings. The syntax is: \`\{"header_key": \{"keys": \[&amp;lt;item1&amp;gt;, ...\], "is_nested": true/false\}\}\`  |

## Outputs
---
There are no outputs for this script.


## Script Examples
### Example command
```!JsonToTable value=`[{"name": "name1", "value": "val1"}, {"name": "name2", "value" : "val2"}]````
### Context Example
```json
{}
```

### Human Readable Output

>|name|value|
>|---|---|
>| name1 | val1 |
>| name2 | val2 |


### Example command
```!JsonToTable value=`[{"name": "name1", "value": "val1"}, {"name": "name2", "value" : "val2"}]` headers=name```
### Context Example
```json
{}
```

### Human Readable Output

>|name|
>|---|
>| name1 |
>| name2 |


### Example command
```!JsonToTable value=`[{"name": {"first": "a", "second": "b", "not_important": "no"}, "value": "val1"}, {"name": {"first": "c", "second": "d", "not_important": "no"}, "value": "val2"}]` is_auto_json_transform=true```
### Context Example
```json
{}
```

### Human Readable Output

>|name|value|
>|---|---|
>| <br/>***first***: a<br/>***second***: b<br/>***not_important***: no | val1 |
>| <br/>***first***: c<br/>***second***: d<br/>***not_important***: no | val2 |


### Example command
```!JsonToTable value=`[{"name": {"first": "a", "second": "b", "not_important": "no"}, "value": "val1"}, {"name": {"first": "c", "second": "d", "not_important": "no"}, "value": "val2"}]` json_transform_properties=`{"name": {"keys": ["first", "second"]}}````
### Context Example
```json
{}
```

### Human Readable Output

>|name|value|
>|---|---|
>| <br/>***first***: a<br/>***second***: b | val1 |
>| <br/>***first***: c<br/>***second***: d | val2 |


### Example command
```!JsonToTable value=`[{"name": {"first": {"a": "val"}, "second": "b", "not_important": "no"}, "value": "val1"}, {"name": {"first": {"a": "val2"}, "second": "d", "not_important": "no"}, "value": "val2"}]` json_transform_properties=`{"name": {"keys": ["a", "second"], "is_nested": "true"}}````
### Context Example
```json
{}
```

### Human Readable Output

>|name|value|
>|---|---|
>| **first**:<br/>	***a***: val<br/><br/>***second***: b | val1 |
>| **first**:<br/>	***a***: val2<br/><br/>***second***: d | val2 |

