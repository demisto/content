Returns the content of the List with the given Name as a string or JSON object, depending on the selected `type`.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | transformer |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| value | The name of the List to open |
| type | The format to return the list content in, such as 'json' or 'string'. The Type does not have to match the format configured in the list, but controls how the content of the list is handled |

## Outputs

---
There are no outputs for this script.

## Script Examples

### Example command

```!GetListContent value="list_name"```

### Context Example

```json
{}
```

### Human Readable Output

>None

### Example command

```!GetListContent value="list_name" type=json```

### Context Example

```json
{}
```

### Human Readable Output

>None

### Example command

```!GetListContent value="list_name" type=string```

### Context Example

```json
{}
```

### Human Readable Output

>None
