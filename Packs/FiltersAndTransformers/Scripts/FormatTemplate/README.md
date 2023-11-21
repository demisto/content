Build text from a template that can include DT expressions.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | transformer, general |
| Cortex XSOAR Version | 6.5.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| value | The context to refer a value with $\{.xxx\} if \`template\` is not empty, otherwise the template text. |
| template | The template text |
| template_type | The template type |
| ctx_data | Context Data: Input . \(single dot\) on \`From previous tasks\` to enable to extract the context data. |
| ctx_inputs | \`inputs\` context: Input 'inputs' \(no quotation\) on \`From previous tasks\` to enable $\{inputs.\} expression in DT. |
| ctx_inc | \`demisto\` context: Input 'incident' \(no quotation\) on \`From previous tasks\` to enable $\{incident.\} expression in DT. |
| variable_markers | The pair of start and end markers to bracket a variable name. |
| keep_symbol_to_null | Set to true not to replace a value if the variable is null, otherwise false. |

## Outputs
---
There are no outputs for this script.


## Getting Started
---
The transformer builds a text from a template text which includes variables just like:
This is a test message for ${user_name}.

The template will be formatted to `This is a test message for John Doe.` by replacing the variable parameters.

By default, a variable name starts with `${` and ends with `}` . You can change the start marker and end marker by specifying the `variable_markers` parameter.

## Examples
---

### Replace variables in a text based on the context data.

#### Parameters
| **Argument Name** | **Value** | **Note** |
| --- | --- | --- |
| value | | Any value |
| template | My name is ${first_name} ${last_name}. | |
| template_type | | |
| ctx_data | . | Make sure that **From previous tasks** is selected |
| ctx_inputs | | |
| ctx_inc | | |
| variable_markers | | |
| keep_symbol_to_null | | |

#### Context Data
```
{
  "first_name": "John",
  "last_name": "Doe"
}
```

#### Output
```
My name is John Doe.
```

---

### Replace variables in a text based on the value.

#### Parameters
| **Argument Name** | **Value** | **Note** |
| --- | --- | --- |
| value | *See the value* | |
| template | My name is ${.first_name} ${.last_name}. | |
| template_type | | |
| ctx_data | | |
| ctx_inputs | | |
| ctx_inc | | |
| variable_markers | | |
| keep_symbol_to_null | | |

#### value (structured)
```
{
  "first_name": "John",
  "last_name": "Doe"
}
```

#### Output
```
My name is John Doe.
```

---

### Format the template given to the value.

#### Parameters
| **Argument Name** | **Value** | **Note** |
| --- | --- | --- |
| value | My name is ${first_name} ${last_name}. | |
| template | | |
| template_type | | |
| ctx_data | . | Make sure that **From previous tasks** is selected |
| ctx_inputs | | |
| ctx_inc | | |
| variable_markers | | |
| keep_symbol_to_null | | |

#### Context Data
```
{
  "first_name": "John",
  "last_name": "Doe"
}
```

#### Output
```
My name is John Doe.
```

---

### Change the variable start and end marker to the windows command shell style such as %name%.

#### Parameters
| **Argument Name** | **Value** | **Note** |
| --- | --- | --- |
| value | | Any value |
| template | My name is %first_name% %last_name%. | |
| template_type | | |
| ctx_data | . | Make sure that **From previous tasks** is selected |
| ctx_inputs | | |
| ctx_inc | | |
| variable_markers | %,% | |
| keep_symbol_to_null | | |

#### Context Data
```
{
  "first_name": "John",
  "last_name": "Doe"
}
```

#### Output
```
My name is John Doe.
```

---

### Change the variable start and end marker to the UNIX shell style such as $name.

#### Parameters
| **Argument Name** | **Value** | **Note** |
| --- | --- | --- |
| value | | Any value |
| template | My name is $first_name $last_name. | |
| template_type | | |
| ctx_data | . | Make sure that **From previous tasks** is selected |
| ctx_inputs | | |
| ctx_inc | | |
| variable_markers | $ | |
| keep_symbol_to_null | | |

#### Context Data
```
{
  "first_name": "John",
  "last_name": "Doe"
}
```

#### Output
```
My name is John Doe.
```

---

### Keep variable names if they are missing in the context.

#### Parameters
| **Argument Name** | **Value** | **Note** |
| --- | --- | --- |
| value | | Any value |
| template | My name is ${first_name} ${last_name}. | |
| template_type | | |
| ctx_data | . | Make sure that **From previous tasks** is selected |
| ctx_inputs | | |
| ctx_inc | | |
| variable_markers | | |
| keep_symbol_to_null | true | |

#### Context Data
```
{
  "first_name": "John"
}
```

#### Output
```
My name is John ${last_name}
```

---

### Use DTs to build variables.

#### Parameters
| **Argument Name** | **Value** | **Note** |
| --- | --- | --- |
| value | | Any value |
| template | My name is ${first_name=val.toUpperCase()} ${last_name=val.toUpperCase()}. | |
| template_type | | |
| ctx_data | . | Make sure that **From previous tasks** is selected |
| ctx_inputs | | |
| ctx_inc | | |
| variable_markers | | |
| keep_symbol_to_null | | |

#### Context Data
```
{
  "first_name": "John",
  "last_name": "Doe"
}
```

#### Output
```
My name is JOHN DOE.
```

---

### Convert all the values in a structured data

#### Parameters
| **Argument Name** | **Value** | **Note** |
| --- | --- | --- |
| value | | Any value |
| template | *See the template* | |
| template_type | | |
| ctx_data | . | Make sure that **From previous tasks** is selected |
| ctx_inputs | | |
| ctx_inc | | |
| variable_markers | | |
| keep_symbol_to_null | | |

#### template (structured)
```
{
  "1": "First name is ${first_name}",
  "2": "Last name is ${last_name}",
  "3": [
    "First name is ${first_name}",
    "Last name is ${last_name}"
  ]
}
```

#### Context Data
```
{
  "first_name": "John",
  "last_name": "Doe"
}
```

#### Output
```
{
  "1": "First name is John",
  "2": "Last name is Doe",
  "3": [
    "First name is John",
    "Last name is Doe"
  ]
}
```

---

### Convert all the values in a JSON text

#### Parameters
| **Argument Name** | **Value** | **Note** |
| --- | --- | --- |
| value | | Any value |
| template | *See the template* | |
| template_type | json | |
| ctx_data | . | Make sure that **From previous tasks** is selected |
| ctx_inputs | | |
| ctx_inc | | |
| variable_markers | | |
| keep_symbol_to_null | | |

#### template
```
{
  "1": "First name is ${first_name}",
  "2": "Last name is ${last_name}",
  "3": [
    "First name is ${first_name}",
    "Last name is ${last_name}"
  ]
}
```

#### Context Data
```
{
  "first_name": "John",
  "last_name": "Doe"
}
```

#### Output
```
{
  "1": "First name is John",
  "2": "Last name is Doe",
  "3": [
    "First name is John",
    "Last name is Doe"
  ]
}
```
