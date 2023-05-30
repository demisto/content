Set a value built by a template in context under the key you entered.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |
| Cortex XSOAR Version | 6.5.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| key | The key to set. Can be a full path such as "Key.ID". If using append=true can also use a DT selector such as "Data\(val.ID == obj.ID\)". |
| template | The template text which can include DT expressions such as $\{value\}. |
| template_type | The template type. |
| append | If false, the context key will be overwritten. If set to true, the script will be appended to the existing context key. |
| stringify | Whether to save the argument as a string. The default value is "noop". |
| force | Whether to force the creation of the context. The default value is "false". |
| context | The context data which overwrites the Demisto context. |
| variable_markers | The pair of start and end markers to bracket a variable name. |
| keep_symbol_to_null | Set to true to not replace a value if the variable is null, otherwise false. |

## Outputs
---
There are no outputs for this script.

## Getting Started
---
The script builds a text from a template text which includes variables such as:
 - This is a test message for ${user_name}.

The template will be formatted to `This is a test message for John Doe.` by replacing variable parameters.

By default, a variable name starts with `${` and ends with `}` . You can change the start marker and end marker by specifying the `variable_markers` parameter.

## Examples
---

### Replace variables in a text based on the context data.

#### Command
```
!SetWithTemplate key=out template=${lists.Template}
```

#### Lists Library
Template:
```
My name is ${first_name} ${last_name}.
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
  "out": "My name is John Doe."
}
```

---

### Change the variable start and end marker to the windows command shell style such as %name%.

#### Command
```
!SetWithTemplate key=out template=${lists.Template} variable_markers=%,%
```

#### Lists Library
Template:
```
My name is %first_name% %last_name%.
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
  "out": "My name is John Doe."
}
```

---

### Change the variable start and end marker to the UNIX shell style such as $name.

#### Command
```
!SetWithTemplate key=out template=${lists.Template} variable_markers=$
```

#### Lists Library
Template:
```
My name is $first_name $last_name.
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
  "out": "My name is John Doe."
}
```

---

### Keep variable names if they are missing in the context.

#### Command
```
!SetWithTemplate key=out template=${lists.Template} keep_symbol_to_null=true
```

#### Lists Library
Template:
```
My name is ${first_name} ${last_name}.
```

#### Context Data
```
{
  "first_name": "John"
}
```

#### Output
```
{
  "out": "My name is John ${last_name}."
}
```

---

### Use DTs to build variables.

#### Command
```
!SetWithTemplate key=out template=${lists.Template}
```

#### Lists Library
Template:
```
My name is ${first_name=val.toUpperCase()} ${last_name=val.toUpperCase()}.
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
  "out": "My name is JOHN DOE."
}
```
