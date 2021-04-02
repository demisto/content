This transformer will take in a value and transform it based on multiple condition expressions (wildcard, regex, etc) defined in a JSON dictionary structure. The key:value pair of the JSON dictionary should be:

"condition expression": "desired outcome"

For example:

{
    ".*match 1.*": "Dest Val1",
    ".*match 2.*": "Dest Val2",
    ".*match 3(.*)": "\\1",
    "*match 4*": {
        "algorithm": "wildcard",
        "output": "Dest Val4"
    }
}

The transformer will return the value matched to a pattern following to the priority.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | transformer, string |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| value | The value to modify. |
| mappings | A JSON dictionary or list of it that contains key:value pairs that represent the "Condition":"Outcome". |
| algorithm | The default algorithm for pattern match. Available algorithm: `literalP`, `wildcard`, `regex` and `regmatch`. |
| caseless | Set to true for caseless comparison, false otherwise. |
| priority | The option to choose which value matched to return. Available options: `first_match` (default) and `last_match`. |
| context | \`demisto\` context: Input . \(single dot\) on \`From previous tasks\` to enable to extract the context data. |

## Outputs
---
There are no outputs for this script.


---
## Syntax for `mappings`
    
    mappings ::= mapping | List[mapping]
    
    mapping ::= Dict[pattern, repl]
    
    pattern ::= str   # The pattern string which depends on the algorithm given to match with the value.
    
    repl ::= output-str | config
    
    output-str ::= str  # The data to replace to the value.
                        # - Backslash substitution on the template string is available in `regex`
                        # - DT syntax (${}) is available when `context` is enabled.
    
    output-any ::= output-str | Any  # The data to replace to the value.
                                     # `null` is the special value to identify the input value given in this transformer.
    
    algorithm ::= "literal" | "wildcard" | "regex" | "regmatch"
    
    config ::= Dict[str, Any]
              
           The structure is:
              {
                  "algorithm": algorithm,               # (Optional) The algorithm to pattern matching.
                  "output": output-any,                 # (Optional) The data to replace to the value by the pattern.
                  "exclude": pattern | List[pattern],   # (Optional) The patterns to exclude in the pattern matching.
                  "next": mappings                      # (Optional) The subsequent condition to do the pattern matching with the value taken from the output.
              }

