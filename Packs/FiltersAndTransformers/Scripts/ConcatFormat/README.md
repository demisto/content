Returns a string concatenated with given prefix & suffix which supports DT expressions.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | transformer, general, string |
| Cortex XSOAR Version | 6.5.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| value | The text to be concatenated with prefix &amp;amp; suffix  |
| prefix | A prefix to concat to the start of the argument |
| suffix | A prefix to concat to the end of the argument |
| ctx_data | Context Data: Input . \(single dot\) on \`From previous tasks\` to enable to extract the context data. |
| ctx_inputs | \`inputs\` context: Input 'inputs' \(no quotation\) on \`From previous tasks\` to enable $\{inputs.\} expression in DT. |
| ctx_inc | \`demisto\` context: Input 'incident' \(no quotation\) on \`From previous tasks\` to enable $\{incident.\} expression in DT. |
| variable_markers | The pair of start and end markers to bracket a variable name |
| keep_symbol_to_null | Set to true not to replace a value if the variable is null, otherwise false. |

## Outputs
---
There are no outputs for this script.

## Getting Started
---
The transformer concatenates prefix and suffix which supports DT expressions to the string.

## Examples
---

### Build an email address from a user ID by appending a domain

#### Parameters
| **Argument Name** | **Value** | **Note** |
| --- | --- | --- |
| value | jdoe | |
| prefix | | |
| suffix | @${domain} | |
| ctx_data | . | Make sure that **From previous tasks** is selected |
| ctx_inputs | | |
| ctx_inc | | |
| variable_markers | | |
| keep_symbol_to_null | | |

#### Context Data
```
{
  "domain": "paloaltonetworks.com"
}
```

#### Output
```
jdoe@paloaltonetworks.com
```

---

### Build an email address by adding a user ID to the domain

#### Parameters
| **Argument Name** | **Value** | **Note** |
| --- | --- | --- |
| value | paloaltonetworks.com | |
| prefix | ${userid}@| |
| suffix | | |
| ctx_data | . | Make sure that **From previous tasks** is selected |
| ctx_inputs | | |
| ctx_inc | | |
| variable_markers | | |
| keep_symbol_to_null | | |

#### Context Data
```
{
  "userid": "jdoe"
}
```

#### Output
```
jdoe@paloaltonetworks.com
```

---

### Change the variable start and end marker to the windows command shell style such as %name%.

#### Parameters
| **Argument Name** | **Value** | **Note** |
| --- | --- | --- |
| value | paloaltonetworks.com | |
| prefix | %userid%@| |
| suffix | | |
| ctx_data | . | Make sure that **From previous tasks** is selected |
| ctx_inputs | | |
| ctx_inc | | |
| variable_markers | %,% | |
| keep_symbol_to_null | | |

#### Context Data
```
{
  "userid": "jdoe"
}
```

#### Output
```
jdoe@paloaltonetworks.com
```

---

### Change the variable start and end marker to the UNIX shell style such as $name.

#### Parameters
| **Argument Name** | **Value** | **Note** |
| --- | --- | --- |
| value | paloaltonetworks.com | |
| prefix | $userid@| |
| suffix | | |
| ctx_data | . | Make sure that **From previous tasks** is selected |
| ctx_inputs | | |
| ctx_inc | | |
| variable_markers | $ | |
| keep_symbol_to_null | | |

#### Context Data
```
{
  "userid": "jdoe"
}
```

#### Output
```
jdoe@paloaltonetworks.com
```

---

### Keep variable names if they are missing in the context.

#### Parameters
| **Argument Name** | **Value** | **Note** |
| --- | --- | --- |
| value | paloaltonetworks.com | |
| prefix | ${userid}@| |
| suffix | | |
| ctx_data | . | Make sure that **From previous tasks** is selected |
| ctx_inputs | | |
| ctx_inc | | |
| variable_markers | | |
| keep_symbol_to_null | true | |

#### Context Data
```
{
}
```

#### Output
```
${userid}@paloaltonetworks.com
```

---

### Use DTs to build variables.

#### Parameters
| **Argument Name** | **Value** | **Note** |
| --- | --- | --- |
| value | paloaltonetworks.com | |
| prefix | ${userid=val.toUpperCase()}@ | |
| suffix | | |
| ctx_data | . | Make sure that **From previous tasks** is selected |
| ctx_inputs | | |
| ctx_inc | | |
| variable_markers | | |
| keep_symbol_to_null | | |

#### Context Data
```
{
  "userid": "jdoe"
}
```

#### Output
```
JDOE@paloaltonetworks.com
```

---

### Use nested DTs to build variables.

#### Parameters
| **Argument Name** | **Value** | **Note** |
| --- | --- | --- |
| value | John Doe | |
| prefix | Hello, | |
| suffix | . ${message-${messageID}} | |
| ctx_data | . | Make sure that **From previous tasks** is selected |
| ctx_inputs | | |
| ctx_inc | | |
| variable_markers | | |
| keep_symbol_to_null | | |

#### Context Data
```
{
  "message-1": "This is a test message.",
  "messageID": 1
}
```

#### Output
```
Hello, John Doe. This is a test message.
```

