Filter values with complex conditions.<br/>
You can make filters with comlex and combination conditions for the context data at any level of the tree.

---
## Script Data

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | transformer, entirelist, general |


---
## Inputs

| **Argument Name** | **Description** |
| --- | --- |
| value | The value to filter/transform. |
| operator | The operation name to filter/transform. |
| filter | The filter. |
| ctx_demisto | Enable to access the context data |
| ctx_inputs | Enable to access the input parameters to sub playbooks and use `${inputs.}` |
| ctx_lists | Enable to access the `list` data and use `${list.}` |
| ctx_incident | Enable to access the incident context and use `${incident.}` |


---
## Filter Syntax for `expressions`, `conditions` and `transformers`

    primitive-expression ::= <operator> : <value>
    
    dict-expression ::= SET OF primitive-expression
    
    array-expression ::= ARRAY OF ( dict-expression | array-expression | "not" expressions | "or" expressions | "and" expressions )
    
    expressions ::= dict-expression | array-expression
    
    primitive-condition ::= <path> : expressions
    
    condition ::= SET OF primitive-condition
    
    array-condition ::= ARRAY OF condition
    
    conditions ::= condition | array-condition
    
    transformers ::= dict-expression | ARRAY OF dict-expression

    
#### dict-expression
  
  `and` logical operator for each expression.
  
  e.g.
  
  `(<value> ends with ".exe") && (<value> starts with "x")`
    
    {
      "ends with" : ".exe",
      "starts with": "x"
    }
    
    
#### array-expression
  
  Logical operations for each expression. `and` by default.
  
  e.g.
  
  
  `(<value> ends with ".exe") && (<value> starts with "x")`
    
    [
      {"ends with" : ".exe"},
      "and",
      {"starts with": "x"}
    ]
  
  or
  
    [
      {"ends with" : ".exe"},
      {"starts with": "x"}
    ]
  
  
  `(<value> ends with ".exe") || (<value> starts with "x")`
    
    [
      {"ends with" : ".exe"},
      "or",
      {"starts with": "x"}
    ]
    
    
  `not (<value> ends with ".exe")`
    
    [
      "not",
      {"ends with" : ".exe"}
    ]


  `((<value> ends with ".exe") || (<value> ends with ".pdf")) and (<value> starts with "x")`
    
    [
      [
        {"ends with" : ".exe"},
        "or",
        {"ends with" : ".pdf"}
      ],
      "and",
      {"starts with": "x"}
    ]

    
#### condition
  
  Evaluates child nodes of each dictionary element.
  
  e.g.
  
  `<value>.Domain ends with ".com"`
    
    {
      "Domain": {
        "ends with" : ".com"
      }
    }
  

  `(<value>.Domain ends with ".com") && (<value>.IP starts with "192.168.")`
  
    {
      "Domain": {
        "ends with" : ".com"
      },
      "IP": {
        "starts with" : "192.168."
      }
    }
    
#### array-condition
  
  Logical operations for each condition. `and` by default.
  
  e.g.
  
  `(<value>.Domain ends with ".com") || (<value>.IP starts with "192.168.")`
  
    [
      {
        "Domain": {
          "ends with" : ".com"
        }
      }
      "or",
      {
        "IP": {
          "starts with" : "192.168."
        }
      }
    ]


  `not ((<value>.Domain ends with ".com") || (<value>.IP starts with "192.168."))`
  
    [
      "not",
      [
        {
          "Domain": {
            "ends with" : ".com"
          }
        }
        "or",
        {
          "IP": {
            "starts with" : "192.168."
          }
        }
      ]
    ]


#### transformers
  
  Run each transformer in order.
  
  e.g.
  
  `base64: encode -> digest`
  
    [
      {"base64: encode": {}},
      {"digest": {"algorithm": "sha1"}}
    ]
  

  `base64: encode -> digest` (Python 3.7 or above)
  
    {
      "base64: encode": {},
      "digest": {"algorithm": "sha1"}
    }
  
  **Note:**
  The order depends on python runtime in a `dict-expression`. Python 3.6 or less doesn't guarantee dictionary keys order.


---
## DT (Demisto Transform Language)

  In filters written in JSON like `expressions`, `conditions`, `transformers` or `<value>`, you can set values with DT expressions for keys and values.
  When you use DT, you must set `ctx_demisto`, `ctx_inputs`, `ctx_lists` and `ctx_incident` of the parameters for the data to which DT accesses.
  
| *Parameter* | *Data Source* | *Value* | *Description* |
| - | - | - | - |
| ctx_demisto | From Previous Tasks | . | Enable to access the context data |
| ctx_inputs | From Previous Tasks | inputs | Enable to access the input parameters to sub playbooks and use `${inputs.}` |
| ctx_lists | From Previous Tasks | list | Enable to access the `list` data and use `${list.}` |
| ctx_incident | From Previous Tasks | incident | Enable to access the incident context and use `${incident.}` |

   *NOTE:* `${list.}` doesn't work in XSOAR 6.0 in transformer. 
   
  Also, `local` prefix (`${local.}`) can be available for referring to the root value of the target. No parameters set is required for using `${local.}`.


#### Example 1
    {
      "ends with": "${Extension}"
    }

#### Example 2
    {
      "${KeyName}": {
        "ends with": "${Extension}"
      }
    }

#### Example 3
    {
      "ends with": "${Name}.exe"
    }

#### Example 4
    {
      "ends with": "${.=val.Extension}"
    }

#### Example 5
    {
      "ends with": "${incident.name}"
    }

#### Example 6
    {
      "ends with": "${local.Extension}"
    }

---
## Operators

Available operators

* `is transformed with`
* `is filtered with`
* `value is filtered with`
* `keeps`
* `doesn't keep`
* `is`
* `isn't`
* `===`
* `!==`
* `equals`
* `==`
* `doesn't equal`
* `!=`
* `greater or equal`
* `>=`
* `greater than`
* `>`
* `less or equal`
* `<=`
* `less than`
* `in range`
* `starts with`
* `starts with caseless`
* `doesn't start with`
* `doesn't start with caseless`
* `ends with`
* `ends with caseless`
* `doesn't end with`
* `doesn't end with caseless`
* `includes`
* `includes caseless`
* `doesn't include`
* `doesn't include caseless`
* `finds`
* `finds caseless`
* `doesn't find`
* `doesn't find caseless`
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
* `contains`
* `contains caseless`
* `doesn't contain`
* `doesn't contain caseless`
* `wildcard: contains`
* `wildcard: contains caseless`
* `wildcard: doesn't contain`
* `wildcard: doesn't contain caseless`
* `regex: contains`
* `regex: contains caseless`
* `regex: doesn't contain`
* `regex: doesn't contain caseless`
* `matches any line of`
* `matches any caseless line of`
* `doesn't match any line of`
* `doesn't match any caseless line of`
* `matches any string of`
* `matches any caseless string of`
* `doesn't match any string of`
* `doesn't match any caseless string of`
* `wildcard: matches any string of`
* `wildcard: matches any caseless string of`
* `wildcard: doesn't match any string of`
* `wildcard: doesn't match any caseless string of`
* `regex: matches any string of`
* `regex: matches any caseless string of`
* `regex: doesn't match any string of`
* `regex: doesn't match any caseless string of`
* `contains any line of`
* `contains any caseless line of`
* `doesn't contain any line of`
* `doesn't contain any caseless line of`
* `contains any string of`
* `contains any caseless line of`
* `doesn't contain any string of`
* `doesn't contain any caseless line of`
* `wildcard: contains any string of`
* `wildcard: contains any caseless line of`
* `wildcard: doesn't contain any string of`
* `wildcard: doesn't contain any caseless line of`
* `regex: contains any string of`
* `regex: contains any caseless line of`
* `regex: doesn't contain any string of`
* `regex: doesn't contain any caseless line of`
* `matches expressions of`
* `matches conditions of`
* `value matches expressions of`
* `value matches conditions of`
* `json: encode array`
* `json: encode`
* `json: decode`
* `base64: encode`
* `base64: decode`
* `digest`
* `is replaced with`
* `is updated with`
* `appends`
* `if-then-else`
* `switch-case`
* `collects values`
* `collects keys`
* `flattens with values`
* `flattens with keys`
* `abort`


----
### Operator: `is transformed with`
<details><summary>
Transform each element with `transformers` given in a filter.
See `Filter Syntax` for the details of `transformers`.
</summary><p/>

> **Filter Format**: `transformers`

#### Example 1
##### Input
    [
      {
        "Name": "a.dat",
        "Size": 100
      },
      {
        "Name": "b.exe",
        "Size": 200
      },
      {
        "Name": "c.txt",
        "Size": 300
      }
    ]

##### Filter
> **Operator**: is transformed with

> **Path**: 

> **Filter**:

    {
      "json: encode": {},
      "base64: encode": {}
    }

##### Output
    [
      "eyJOYW1lIjogImEuZGF0IiwgIlNpemUiOiAxMDB9",
      "eyJOYW1lIjogImIuZXhlIiwgIlNpemUiOiAyMDB9",
      "eyJOYW1lIjogImMudHh0IiwgIlNpemUiOiAzMDB9"
    ]


#### Example 2
##### Input
    {
      "File": [
        {
          "Name": "a.dat",
          "Size": 100
        },
        {
          "Name": "b.exe",
          "Size": 200
        }
      ],
      "IP": [
        "1.1.1.1",
        "2.2.2.2"
      ]
    }

##### Filter
> **Operator**: is transformed with

> **Path**: File

> **Filter**:

    {
      "is filtered with": {
        "Name": {
        "ends with": ".exe"
      },
      "json: encode": {},
      "base64: encode": {}
    }

##### Output
    {
      "File": [
        "eyJOYW1lIjogImIuZXhlIiwgIlNpemUiOiAyMDB9"
      ],
      "IP": [
        "1.1.1.1",
        "2.2.2.2"
      ]
    }


</details>


----
### Operator: `is filtered with`
<details><summary>
Evaluates each element of an array with given conditions and returns a set of the elements matched.
The value is handled as an array which has only one element when its data type is `dictionary`.
See `Filter Syntax` for the details of `conditions`.
</summary><p/>

> **Filter Format**: `conditions`

#### Example 1
##### Input
    [
      {
        "Name": "a.dat",
        "Size": 100
      },
      {
        "Name": "b.exe",
        "Size": 200
      },
      {
        "Name": "c.txt",
        "Size": 300
      }
    ]

##### Filter
> **Operator**: is filtered with

> **Path**: Name

> **Filter**:

    {
      "Name": {
        "ends with": ".exe"
      }
    }

##### Output
    [
      {
        "Name": "b.exe",
        "Size": 200
      }
    ]
</details>

----
### Operator: `value is filtered with`
<details><summary>
Evaluates each value of dictionary elements or each element for values whose data type is not `dictionary`, and returns a set of the elements matched to expressions given in a filter.
See `Filter Syntax` for the details of `expressions`.
</summary><p/>

> **Filter Format**: `expressions`

#### Example 1
##### Input
    [
      "192.168.1.1",
      "1.1.1.1",
      "192.168.1.2"
    ]

##### Filter
> **Operator**: value is filtered with

> **Path**: 

> **Filter**:

    {
      "starts with": "192.168."
    }

##### Output
    [
      "192.168.1.1",
      "192.168.1.2"
    ]


#### Example 2
##### Input

    {
      "Host1": {
        "User": "JDOE",
        "IP": "192.168.1.1",
        "Score": 30
      },
      "Host2": {
        "User": "TYAMADA",
        "IP": "192.168.1.2",
        "Score": 10
      },
      "Host3": {
        "User": "MBLACK",
        "IP": "3.3.3.3",
        "Score": 40
      }
    }

##### Filter
> **Operator**: value is filtered with

> **Path**: Score

> **Filter**:

    {
      ">=": 20
    }

##### Output
    {
      "Host1": {
        "User": "JDOE",
        "IP": "192.168.1.1",
        "Score": 30
      },
      "Host3": {
        "User": "MBLACK",
        "IP": "3.3.3.3",
        "Score": 40
      }
    }


</details>

----
### Operator: `keeps`
<details><summary>
Evaluates each element of an array with keys given and returns a set of the elements which only retains the keys given and corresponding values.
The value is handled as an array which has only one element when its data type is `dictionary`.
</summary><p/>

> **Filter Format**: `expressions`

#### Example 1
##### Input
    [
      {
        "Host": "JDOE",
        "IP": "1.1.1.1"
      },
      {
        "User": "John Doe",
        "First Name": "John",
        "Last Name": "Doe"
      },
      {
        "Host": "YTARO",
        "User": "Taro Yamada"
      }
    ]

##### Filter
> **Operator**: keeps

> **Path**:

> **Filter**:
    
    [
      "Host",
      "User"
    ]

##### Output
    [
      {
        "Host": "JDOE"
      },
      {
        "User": "John Doe"
      },
      {
        "Host": "YTARO",
        "User": "Taro Yamada"
      }
    ]

</details>

----
### Operator: `doesn't keeps`
<details><summary>
Evaluates each element of an array with keys given and returns a set of the elements which are excluded the keys given.
The value is handled as an array which has only one element when its data type is `dictionary`.
</summary><p/>

> **Filter Format**: `expressions`


#### Example 1
##### Input
    [
      {
        "Host": "JDOE",
        "IP": "1.1.1.1"
      },
      {
        "User": "John Doe",
        "First Name": "John",
        "Last Name": "Doe"
      },
      {
        "Host": "YTARO",
        "User": "Taro Yamada"
      }
    ]

##### Filter
> **Operator**: doesn't keeps

> **Path**:

> **Filter**:
    
    [
      "Host",
      "User"
    ]

##### Output
    [
      {
        "IP": "1.1.1.1"
      },
      {
        "First Name": "John",
        "Last Name": "Doe"
      },
      },
      {
      }
    ]

</details>

----
### Operator: `is`
<details><summary>
This operator works with a sub operator specified as filter.
</summary><p/>

----
#### Sub Operator: empty
<details><summary>
Returns a set of elements which is empty.
</summary><p/>


#### Example 1
##### Input
    10

##### Filter
> **Operator**: is

> **Path**:

> **Filter**:
    
    empty

##### Output
    null

#### Example 2
##### Input
    [
      10,
      {
      },
      null,
      "xxx"
    ]

##### Filter
> **Operator**: is

> **Path**:

> **Filter**:
    
    empty

##### Output
    [
      {
      },
      null
    ]

</details>

----
#### Sub Operator: null
<details><summary>
Returns a set of elements which is `null`.
</summary><p/>


#### Example 1
##### Input
    10

##### Filter
> **Operator**: is

> **Path**:

> **Filter**:
    
    null

##### Output
    null

#### Example 2
##### Input
    [
      10,
      {
      },
      null,
      "xxx"
    ]

##### Filter
> **Operator**: is

> **Path**:

> **Filter**:
    
    null

##### Output
    [
      null
    ]

</details>

----
#### Sub Operator: string
<details><summary>
Returns a set of elements whose data type is `string`.
</summary><p/>


#### Example 1
##### Input
    10

##### Filter
> **Operator**: is

> **Path**:

> **Filter**:
    
    string

##### Output
    null

#### Example 2
##### Input
    [
      10,
      {
      },
      null,
      "xxx"
    ]

##### Filter
> **Operator**: is

> **Path**:

> **Filter**:
    
    string

##### Output
    [
      "xxx"
    ]


</details>

----
#### Sub Operator: integer
<details><summary>
Returns a set of elements whose data type is `integer`.
</summary><p/>


#### Example 1
##### Input
    10

##### Filter
> **Operator**: is

> **Path**:

> **Filter**:
    
    integer

##### Output
    10

#### Example 2
##### Input
    [
      10,
      "123"
    ]

##### Filter
> **Operator**: is

> **Path**:

> **Filter**:
    
    integer

##### Output
    [
      10
    ]

</details>

----
#### Sub Operator: integer string
<details><summary>
Returns a set of elements whose data type is `string` and whose value is integer.
The value that includes decimal point is evaluated as not integer.
</summary><p/>


#### Example 1
##### Input
    [
      10,
      "123"
    ]

##### Filter
> **Operator**: is

> **Path**:

> **Filter**:
    
    integer string

##### Output
    [
      "123"
    ]

</details>

----
#### Sub Operator: any integer
<details><summary>
Returns a set of elements matched with `string` or `integer string` operator.
</summary><p/>


#### Example 1
##### Input
    [
      10,
      "123",
      "xxx"
    ]

##### Filter
> **Operator**: is

> **Path**:

> **Filter**:

    any integer

##### Output
    [
      10,
      "123"
    ]


</details>

----
#### Sub Operator: existing key
<details><summary>
Evaluates each dictionary element of an array, then returns a set of the elements which has a key given in `path`.
</summary><p/>


#### Example 1
##### Input
    [
      {
        "Host": "JDOE",
        "IP": "1.1.1.1"
      },
      {
        "User": "John Doe",
        "Email": "jdoe@domain.com"
      }
    ]

##### Filter
> **Operator**: is

> **Path**: Host

> **Filter**:
    
    existing key

##### Output
    [
      {
        "Host": "JDOE",
        "IP": "1.1.1.1"
      }
    ]


#### Example 2
##### Input
    [
      {
        "Host": {
          "IP": "1.1.1.1",
          "Score": 50,
          "User": "JDOE"
        },
        "User": {
          "ID": 1000,
          "Name": "John Doe"
        }
      },
      {
        "Host": {
          "IP": "2.2.2.2",
          "Score": 30
        }
      }
    ]

##### Filter
> **Operator**: is

> **Path**: Host.User

> **Filter**:
    
    existing key

##### Output
    [
      {
        "Host": {
          "IP": "1.1.1.1",
          "Score": 50,
          "User": "JDOE"
        },
        "User": {
          "ID": 1000,
          "Name": "John Doe"
        }
      }
    ]

</details>
</details>

----
### Operator: `isn't`
<details><summary>
This operator works with a sub operator specified as filter.
</summary><p/>

----
#### Sub Operator: empty
<details><summary>
Returns a set of elements which is not empty.
</summary><p/>


#### Example 1
##### Input
    10

##### Filter
> **Operator**: isn't

> **Path**:

> **Filter**:
    
    empty

##### Output
    10

#### Example 2
##### Input
    [
      10,
      {
      },
      null,
      "xxx"
    ]

##### Filter
> **Operator**: isn't

> **Path**:

> **Filter**:
    
    empty


##### Output
    [
      10,
      "xxx"
    ]

</details>

----
#### Sub Operator: null
<details><summary>
Returns a set of elements which is not `null`.
</summary><p/>


#### Example 1
##### Input
    10

##### Filter
> **Operator**: isn't

> **Path**:

> **Filter**:
    
    10

##### Output
    null

#### Example 2
##### Input
    [
      10,
      {
      },
      null,
      "xxx"
    ]

##### Filter
> **Operator**: isn't

> **Path**:

> **Filter**:
    
    null

##### Output
    [
      10,
      {
      },
      "xxx"
    ]

</details>

----
#### Sub Operator: string
<details><summary>
Returns a set of elements whose data type is not `string`.
</summary><p/>


#### Example 1
##### Input
    10

##### Filter
> **Operator**: isn't

> **Path**:

> **Filter**:
    
    string

##### Output
    10

#### Example 2
##### Input
    [
      10,
      {
      },
      null,
      "xxx"
    ]

##### Filter
> **Operator**: isn't

> **Path**:

> **Filter**:
    
    string

##### Output
    [
      10,
      {
      },
      null
    ]


</details>

----
#### Sub Operator: integer
<details><summary>
Returns a set of elements whose date type is not `integer`.
</summary><p/>


#### Example 1
##### Input
    10

##### Filter
> **Operator**: isn't

> **Path**:

> **Filter**:
    
    integer

##### Output
    null

#### Example 2
##### Input
    [
      10,
      "123"
    ]

##### Filter
> **Operator**: isn't

> **Path**:

> **Filter**:
    
    integer

##### Output
    [
      "123"
    ]

</details>

----
#### Sub Operator: integer string
<details><summary>
Returns a set of elements whose data type is not `string` or whose value is not integer.
The value that includes decimal point is evaluated as not integer.
</summary><p/>


#### Example 1
##### Input
    [
      10,
      "123",
      "123.0"
    ]

##### Filter
> **Operator**: isn't

> **Path**:

> **Filter**:
    
    integer string

##### Output
    [
      10,
      "123.0"
    ]

</details>

----
#### Sub Operator: any integer
<details><summary>
Returns a set of elements which are neither `string` or `integer string`.
</summary><p/>


#### Example 1
##### Input
    [
      10,
      "123",
      "xxx"
    ]

##### Filter
> **Operator**: isn't

> **Path**:

> **Filter**:

    any integer

##### Output
    [
      "xxx"
    ]


</details>

----
#### Sub Operator: existing key
<details><summary>
Evaluates each dictionary element of an array, then returns a set of the elements which doesn't have a key given in `path`.
</summary><p/>


#### Example 1
##### Input
    [
      {
        "Host": "JDOE",
        "IP": "1.1.1.1"
      },
      {
        "User": "John Doe",
        "Email": "jdoe@domain.com"
      }
    ]

##### Filter
> **Operator**: isn't

> **Path**: Host

> **Filter**:
    
    existing key

##### Output
    [
      {
        "User": "John Doe",
        "Email": "jdoe@domain.com"
      }
    ]


#### Example 2
##### Input
    [
      {
        "Host": {
          "IP": "1.1.1.1",
          "Score": 50,
          "User": "JDOE"
        },
        "User": {
          "ID": 1000,
          "Name": "John Doe"
        }
      },
      {
        "Host": {
          "IP": "2.2.2.2",
          "Score": 30
        }
      }
    ]

##### Filter
> **Operator**: isn't

> **Path**: Host.User

> **Filter**:
    
    existing key

##### Output
    [
      {
        "Host": {
          "IP": "2.2.2.2",
          "Score": 30
        }
      }
    ]

</details>
</details>

----
### Operator: `===`
<details><summary>
Returns a set of elements which exactly matches to a value given in a filter. It doesn't match when the data types are different.
</summary><p/>

> **Filter Format**: `<value>`

#### Example 1
##### Input
    [
      10,
      "10",
      123
    ]

##### Filter
> **Operator**: ===

> **Path**: 

> **Filter**:

    10

##### Output
    [
      10
    ]


#### Example 2
##### Input
    [
      10,
      "10",
      123
    ]

##### Filter
> **Operator**: ===

> **Path**: 

> **Filter**:

    "10"

##### Output
    [
      "10"
    ]
 

</details>


----
### Operator: `!==`
<details><summary>
Returns a set of elements which doesn't match the data type or the value of a value given in a filter.
</summary><p/>

> **Filter Format**: `<value>`

#### Example 1
##### Input
    [
      10,
      "10",
      123
    ]

##### Filter
> **Operator**: !==

> **Path**: 

> **Filter**:

    10

##### Output
    [
      "10",
      123
    ]

</details>


----
### Operator: `equals`, `==`
<details><summary>
Returns a set of elements which is equal to a value given in a filter.
The value is implicitly converted from its data type to another in a comparison between different data types.
`==` is an alias name for `equals`.
</summary><p/>

> **Filter Format**: `<value>`

#### Example 1
##### Input
    [
      10,
      "10",
      123
    ]

##### Filter
> **Operator**: equals

> **Path**: 

> **Filter**:

    10

##### Output
    [
      10,
      "10"
    ]
 
</details>


----
### Operator: `doesn't equal`, `!=`
<details><summary>
Returns a set of elements which is not equal to a value given in a filter.
The value is implicitly converted from its data type to another in a comparison between different data types.
`!=` is an alias name for `doesn't equal`.
</summary><p/>

> **Filter Format**: `<value>`

#### Example 1
##### Input
    [
      10,
      "10",
      123
    ]

##### Filter
> **Operator**: doesn't equal

> **Path**: 

> **Filter**:

    10

##### Output
    [
      123
    ]

</details>


----
### Operator: `greater or equal`, `>=`
<details><summary>
Returns a set of elements which is greater or equal to a value given in a filter.
The value is implicitly converted from its data type to number in a comparison.
This operator evaluates to false for either or both of the data which cannot convert to number.
`>=` is an alias name for `greater or equal`.
</summary><p/>

> **Filter Format**: `<value>`

#### Example 1
##### Input
    [
      1,
      10,
      "10",
      123
    ]

##### Filter
> **Operator**: greater or equal

> **Path**: 

> **Filter**:

    10

##### Output
    [
      10,
      "10",
      123
    ]

</details>

----
### Operator: `greater than`, `>`
<details><summary>
Returns a set of elements which is greater than a value given in a filter.
The value is implicitly converted from its data type to number in a comparison.
This operator evaluates to false for either or both of the data which cannot convert to number.
`>` is an alias name for `greater than`.
</summary><p/>

> **Filter Format**: `<value>`

#### Example 1
##### Input
    [
      1,
      10,
      "10",
      123
    ]

##### Filter
> **Operator**: greater than

> **Path**: 

> **Filter**:

    10

##### Output
    [
      123
    ]

</details>


----
### Operator: `less or equal`, `&lt;=`
<details><summary>
Returns a set of elements which is less or equal to a value given in a filter.
The value is implicitly converted from its data type to number in a comparison.
This operator evaluates to false for either or both of the data which cannot convert to number.
`&lt;=` is an alias name for `less or equal`.
</summary><p/>

> **Filter Format**: `<value>`

#### Example 1
##### Input
    [
      1,
      10,
      "10",
      123
    ]

##### Filter
> **Operator**: less or equal

> **Path**: 

> **Filter**:

    10

##### Output
    [
      1,
      10,
      "10"
    ]

</details>


----
### Operator: `less than`, `<`
<details><summary>
Returns a set of elements which is less than a value given in a filter.
The value is implicitly converted from its data type to number in a comparison.
This operator evaluates to false for either or both of the data which cannot convert to number.
`&lt;` is an alias name for `less than`.
</summary><p/>

> **Filter Format**: `<value>`

#### Example 1
##### Input
    [
      1,
      10,
      "10",
      123
    ]

##### Filter
> **Operator**: less than

> **Path**: 

> **Filter**:

    10

##### Output
    [
      1
    ]

</details>


----
### Operator: `in range`
<details><summary>
Returns a set of elements which is greater or equal to `min` and less or equal to `max` given in a range.
The value is implicitly converted from its data type to number in a comparison.
This operator evaluates to false for either or both of the data which cannot convert to number.
</summary><p/>

> **Filter Format**: `min`,`max`

#### Example 1
##### Input
    [
      1,
      10,
      "10",
      "30",
      123
    ]

##### Filter
> **Operator**: in range

> **Path**: 

> **Filter**:

    10,100

##### Output
    [
      10,
      "10",
      "30"
    ]

</details>


----
### Operator: `starts with`
<details><summary>
Returns a set of elements which starts with a string given in a filter.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    [
      10,
      "xxx.exe",
      "yyy.pdf",
      {
        "xxx": "x"
      }
    ]

##### Filter
> **Operator**: starts with

> **Path**: 

> **Filter**:

    xxx

##### Output
    [
      "xxx.exe"
    ]

</details>


----
### Operator: `starts with caseless`
<details><summary>
Returns a set of elements which starts with a string given in a filter. It performs case-insensitive matching.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    [
      10,
      "xxx.exe",
      "XXX.EXE",
      "yyy.pdf",
      {
        "xxx": "x"
      }
    ]

##### Filter
> **Operator**: starts with caseless

> **Path**: 

> **Filter**:

    xxx

##### Output
    [
      "xxx.exe",
      "XXX.EXE"
    ]

</details>


----
### Operator: `doesn't start with`
<details><summary>
Returns a set of elements which doesn't start with a string given in a filter.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    [
      10,
      "xxx.exe",
      "yyy.pdf",
      {
        "xxx": "x"
      }
    ]

##### Filter
> **Operator**: doesn't start with

> **Path**: 

> **Filter**:

    xxx

##### Output
    [
      10,
      "yyy.pdf",
      {
        "xxx": "x"
      }
    ]

</details>


----
### Operator: `doesn't start with caseless`
<details><summary>
Returns a set of elements which doesn't start with a string given in a filter. It performs case-insensitive matching.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    [
      10,
      "xxx.exe",
      "XXX.EXE",
      "yyy.pdf",
      {
        "xxx": "x"
      }
    ]

##### Filter
> **Operator**: doesn't start with caseless

> **Path**: 

> **Filter**:

    xxx

##### Output
    [
      10,
      "yyy.pdf",
      {
        "xxx": "x"
      }
    ]

</details>


----
### Operator: `ends with`
<details><summary>
Returns a set of elements which ends with a string given in a filter.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    [
      10,
      "xxx.exe",
      "yyy.pdf",
      {
        "xxx": "x"
      }
    ]

##### Filter
> **Operator**: ends with

> **Path**: 

> **Filter**:

    .exe

##### Output
    [
      "xxx.exe"
    ]

</details>


----
### Operator: `ends with caseless`
<details><summary>
Returns a set of elements which ends with a string given in a filter. It performs case-insensitive matching.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    [
      10,
      "xxx.exe",
      "XXX.EXE",
      "yyy.pdf",
      {
        "xxx": "x"
      }
    ]

##### Filter
> **Operator**: ends with caseless

> **Path**: 

> **Filter**:

    .exe

##### Output
    [
      "xxx.exe",
      "XXX.EXE"
    ]

</details>


----
### Operator: `doesn't end with`
<details><summary>
Returns a set of elements which doesn't end with a string given in a filter.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    [
      10,
      "xxx.exe",
      "yyy.pdf",
      {
        "xxx": "x"
      }
    ]

##### Filter
> **Operator**: doesn't end with

> **Path**: 

> **Filter**:

    .exe

##### Output
    [
      10,
      "yyy.pdf",
      {
        "xxx": "x"
      }
    ]

</details>


----
### Operator: `doesn't end with caseless`
<details><summary>
Returns a set of elements which doesn't end with a string given in a filter. It performs case-insensitive matching.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    [
      10,
      "xxx.exe",
      "XXX.EXE",
      "yyy.pdf",
      {
        "xxx": "x"
      }
    ]

##### Filter
> **Operator**: doesn't end with caseless

> **Path**: 

> **Filter**:

    .exe

##### Output
    [
      10,
      "yyy.pdf",
      {
        "xxx": "x"
      }
    ]

</details>


----
### Operator: `includes`
<details><summary>
Returns a set of elements of which a string given in a filter is a substring.
The searching only works for `string` data types.
It evaluates to unmatched for a element that either or both of the data types is not `string`.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    www.paloaltonetworks.com

##### Filter
> **Operator**: includes

> **Path**: 

> **Filter**:

    paloaltonetworks

##### Output
    www.paloaltonetworks.com


#### Example 2
##### Input
    [
      10,
      "www.paloaltonetworks.com",
      "www.paloaltonetworks.co.jp",
      {
        "xxx": "xxx.paloaltonetworks.com"
      }
    ]

##### Filter
> **Operator**: includes

> **Path**: 

> **Filter**:

    paloaltonetworks

##### Output
    [
      "www.paloaltonetworks.com",
      "www.paloaltonetworks.co.jp"
    ]

</details>


----
### Operator: `includes caseless`
<details><summary>
Returns a set of elements of which a string given in a filter is a substring.
It performs case-insensitive seaching, and only works for `string` data types.
It evaluates to unmatched for a element that either or both of the data types is not `string`.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    [
      10,
      "www.paloaltonetworks.com",
      "WWW.PaloAltoNetworks.COM",
      {
        "xxx": "xxx.paloaltonetworks.com"
      }
    ]

##### Filter
> **Operator**: includes caseless

> **Path**: 

> **Filter**:

    paloaltonetworks

##### Output
    [
      "www.paloaltonetworks.com",
      "WWW.PaloAltoNetworks.COM"
    ]

</details>


----
### Operator: `doesn't include`
<details><summary>
Returns a set of elements of which a string given in a filter is not a substring.
The searching only works for `string` data types.
It evaluates to unmatched for a element that either or both of the data types is not `string`.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    [
      10,
      "www.paloaltonetworks.com",
      "www.paloaltonetworks.co.jp",
      {
        "xxx": "xxx.paloaltonetworks.com"
      }
    ]

##### Filter
> **Operator**: doesn't include

> **Path**: 

> **Filter**:

    paloaltonetworks

##### Output
    [
      10,
      {
        "xxx": "xxx.paloaltonetworks.com"
      }
    ]

</details>


----
### Operator: `doesn't include caseless`
<details><summary>
Returns a set of elements of which a string given in a filter is not a substring.
It performs case-insensitive seaching, and only works for `string` data types.
It evaluates to unmatched for a element that either or both of the data types is not `string`.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    [
      10,
      "www.paloaltonetworks.com",
      "WWW.PaloAltoNetworks.COM",
      {
        "xxx": "xxx.paloaltonetworks.com"
      }
    ]

##### Filter
> **Operator**: doesn't include caseless

> **Path**: 

> **Filter**:

    paloaltonetworks

##### Output
    [
      10,
      {
        "xxx": "xxx.paloaltonetworks.com"
      }
    ]

</details>


----
### Operator: `finds`
<details><summary>
Returns the entire target value if a string given in a filter is a substring of any of the elements, `null` otherwise.
The searching is performed for a single `string` element or each `string` element of an array.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    www.paloaltonetworks.com

##### Filter
> **Operator**: finds

> **Path**: 

> **Filter**:

    paloaltonetworks

##### Output
    www.paloaltonetworks.com

#### Example 2
##### Input
    [
      10,
      "www.paloaltonetworks.com",
      "WWW.PaloAltoNetworks.COM",
      {
        "xxx": "xxx.paloaltonetworks.com"
      }
    ]

##### Filter
> **Operator**: finds

> **Path**: 

> **Filter**:

    paloaltonetworks

##### Output
    [
      10,
      "www.paloaltonetworks.com",
      "WWW.PaloAltoNetworks.COM",
      {
        "xxx": "xxx.paloaltonetworks.com"
      }
    ]

#### Example 3
##### Input
    [
      10,
      "www.paloaltonetworks.com",
      "WWW.PaloAltoNetworks.COM",
      {
        "xxx": "xxx.paloaltonetworks.com"
      }
    ]

##### Filter
> **Operator**: finds

> **Path**: 

> **Filter**:

    xxx.paloaltonetworks.com

##### Output
    null

</details>


----
### Operator: `finds caseless`
<details><summary>
Returns the entire target value if a string given in a filter is a substring of any of the elements, `null` otherwise.
The searching is performed for a single `string` element or each `string` element of an array with case-insensitive matching.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    WWW.PaloAltoNetworks.COM

##### Filter
> **Operator**: finds caseless

> **Path**: 

> **Filter**:

    paloaltonetworks

##### Output
    WWW.PaloAltoNetworks.COM

#### Example 2
##### Input
    [
      10,
      "WWW.PaloAltoNetworks.COM",
      {
        "xxx": "xxx.paloaltonetworks.com"
      }
    ]

##### Filter
> **Operator**: finds caseless

> **Path**: 

> **Filter**:

    paloaltonetworks

##### Output
    [
      10,
      "WWW.PaloAltoNetworks.COM",
      {
        "xxx": "xxx.paloaltonetworks.com"
      }
    ]

</details>


----
### Operator: `doesn't find`
<details><summary>
Returns an entire target value if a string given in a filter is not a substring of any of the elements, `null` otherwise.
The searching is performed for a single `string` element or each `string` element of an array.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    www.paloaltonetworks.com

##### Filter
> **Operator**: doesn't find

> **Path**: 

> **Filter**:

    paloaltonetworks

##### Output
    null


#### Example 2
##### Input
    [
      10,
      "www.paloaltonetworks.com",
      "WWW.PaloAltoNetworks.COM",
      {
        "xxx": "xxx.paloaltonetworks.com"
      }
    ]

##### Filter
> **Operator**: doesn't find

> **Path**: 

> **Filter**:

    paloaltonetworks

##### Output
    null


#### Example 3
##### Input
    [
      10,
      "www.paloaltonetworks.com",
      "WWW.PaloAltoNetworks.COM",
      {
        "xxx": "xxx.paloaltonetworks.com"
      }
    ]

##### Filter
> **Operator**: doesn't find

> **Path**: 

> **Filter**:

    xxx.paloaltonetworks

##### Output
    [
      10,
      "www.paloaltonetworks.com",
      "WWW.PaloAltoNetworks.COM",
      {
        "xxx": "xxx.paloaltonetworks.com"
      }
    ]

</details>


----
### Operator: `doesn't find caseless`
<details><summary>
Returns an entire target value if a string given in a filter is not a substring of any of the elements, `null` otherwise.
The searching is performed for a single `string` element or each `string` element of an array with case-insensitive matching.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    WWW.PaloAltoNetworks.COM

##### Filter
> **Operator**: doesn't find caseless

> **Path**: 

> **Filter**:

    PaloAltoNetworks

##### Output
    null


#### Example 2
##### Input
    [
      10,
      "WWW.PaloAltoNetworks.COM",
      {
        "xxx": "xxx.paloaltonetworks.com"
      }
    ]

##### Filter
> **Operator**: doesn't find caseless

> **Path**: 

> **Filter**:

    paloaltonetworks

##### Output
    null


#### Example 3
##### Input
    [
      10,
      "WWW.PaloAltoNetworks.COM",
      {
        "xxx": "xxx.paloaltonetworks.com"
      }
    ]

##### Filter
> **Operator**: doesn't find caseless

> **Path**: 

> **Filter**:

    xxx.paloaltonetworks

##### Output
    [
      10,
      "WWW.PaloAltoNetworks.COM",
      {
        "xxx": "xxx.paloaltonetworks.com"
      }
    ]

</details>


----
### Operator: `matches`
<details><summary>
Returns a set of elements which is equal to a string given in a filter.
The matching is peformed between `string` data types. It doesn't match for a element whose data type is not `string`.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    www.paloaltonetworks.com

##### Filter
> **Operator**: matches

> **Path**: 

> **Filter**:

    www.paloaltonetworks.com

##### Output
    www.paloaltonetworks.com


#### Example 2
##### Input
    www.paloaltonetworks.com

##### Filter
> **Operator**: matches

> **Path**: 

> **Filter**:

    paloaltonetworks

##### Output
    null


#### Example 3
##### Input
    [
      "www.demisto.com",
      "www.paloaltonetworks.com",
      {
        "Host": "www.paloaltonetworks.com"
      }
    ]

##### Filter
> **Operator**: matches

> **Path**: 

> **Filter**:

    www.paloaltonetworks.com

##### Output
    [
      "www.paloaltonetworks.com"
    ]

</details>


----
### Operator: `matches caseless`
<details><summary>
Returns a set of elements which matches a string given in a filter.
The matching is peformed case-insensitively and between `string` data types. It doesn't match for a element whose data type is not `string`.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    WWW.PaloAltoNetworks.COM

##### Filter
> **Operator**: matches caseless

> **Path**: 

> **Filter**:

    www.paloaltonetworks.com

##### Output
    WWW.PaloAltoNetworks.COM


#### Example 2
##### Input
    WWW.PaloAltoNetworks.COM

##### Filter
> **Operator**: matches caseless

> **Path**: 

> **Filter**:

    paloaltonetworks

##### Output
    null


#### Example 3
##### Input
    [
      "www.demisto.com",
      "WWW.PaloAltoNetworks.COM",
      {
        "Host": "www.paloaltonetworks.com"
      }
    ]

##### Filter
> **Operator**: matches caseless

> **Path**: 

> **Filter**:

    www.paloaltonetworks.com

##### Output
    [
      "WWW.PaloAltoNetworks.COM"
    ]

</details>


----
### Operator: `doesn't match`
<details><summary>
Returns a set of elements which is not equal to a string given in a filter.
The matching is peformed between `string` data types. It doesn't match for a element whose data type is not `string`.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    www.paloaltonetworks.com

##### Filter
> **Operator**: doesn't match

> **Path**: 

> **Filter**:

    www.paloaltonetworks.com

##### Output
    null


#### Example 2
##### Input
    www.paloaltonetworks.com

##### Filter
> **Operator**: doesn't match

> **Path**: 

> **Filter**:

    paloaltonetworks

##### Output
    www.paloaltonetworks.com


#### Example 3
##### Input
    [
      "www.demisto.com",
      "www.paloaltonetworks.com",
      {
        "Host": "www.paloaltonetworks.com"
      }
    ]

##### Filter
> **Operator**: doesn't match

> **Path**: 

> **Filter**:

    www.paloaltonetworks.com

##### Output
    [
      "www.demisto.com",
      {
        "Host": "www.paloaltonetworks.com"
      }
    ]

</details>


----
### Operator: `doesn't match caseless`
<details><summary>
Returns a set of elements which doesn't match a string given in a filter.
The matching is peformed case-insensitively and between `string` data types. It doesn't match for a element whose data type is not `string`.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    WWW.PaloAltoNetworks.COM

##### Filter
> **Operator**: doesn't match caseless

> **Path**: 

> **Filter**:

    www.paloaltonetworks.com

##### Output
    null


#### Example 2
##### Input
    WWW.PaloAltoNetworks.COM

##### Filter
> **Operator**: doesn't match caseless

> **Path**: 

> **Filter**:

    paloaltonetworks

##### Output
    WWW.PaloAltoNetworks.COM


#### Example 3
##### Input
    [
      "www.demisto.com",
      "WWW.PaloAltoNetworks.COM",
      {
        "Host": "www.paloaltonetworks.com"
      }
    ]

##### Filter
> **Operator**: doesn't match caseless

> **Path**: 

> **Filter**:

    www.paloaltonetworks.com

##### Output
    [
      "www.demisto.com",
      {
        "Host": "www.paloaltonetworks.com"
      }
    ]

</details>


----
### Operator: `wildcard: matches`
<details><summary>
Returns a set of elements which matches a wildcard pattern given in a filter.
The matching is peformed between `string` data types. It doesn't match for a element whose data type is not `string`.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    www.paloaltonetworks.com

##### Filter
> **Operator**: wildcard: matches

> **Path**: 

> **Filter**:

    ???.paloaltonetworks.*

##### Output
    www.paloaltonetworks.com


#### Example 2
##### Input
    [
      "www.demisto.com",
      "www.paloaltonetworks.com",
      {
        "Host": "www.paloaltonetworks.com"
      }
    ]

##### Filter
> **Operator**: wildcard: matches

> **Path**: 

> **Filter**:

    ???.paloaltonetworks.*

##### Output
    [
      "www.paloaltonetworks.com"
    ]

</details>


----
### Operator: `wildcard: matches caseless`
<details><summary>
Returns a set of elements which matches a wildcard pattern given in a filter.
The matching is peformed case-insensitively and between `string` data types. It doesn't match for a element whose data type is not `string`.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    WWW.PaloAltoNetworks.COM

##### Filter
> **Operator**: wildcard: matches caseless

> **Path**: 

> **Filter**:

    ???.paloaltonetworks.*

##### Output
    WWW.PaloAltoNetworks.COM


#### Example 2
##### Input
    [
      "www.demisto.com",
      "WWW.PaloAltoNetworks.COM",
      {
        "Host": "www.paloaltonetworks.com"
      }
    ]

##### Filter
> **Operator**: wildcard: matches caseless

> **Path**: 

> **Filter**:

    ???.paloaltonetworks.*

##### Output
    [
      "WWW.PaloAltoNetworks.COM"
    ]

</details>


----
### Operator: `wildcard: doesn't match`
<details><summary>
Returns a set of elements which doesn't match a wildcard pattern given in a filter.
The matching is peformed between `string` data types. It doesn't match for a element whose data type is not `string`.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    www.paloaltonetworks.com

##### Filter
> **Operator**: wildcard: doesn't match

> **Path**: 

> **Filter**:

    ???.paloaltonetworks.*

##### Output
    null


#### Example 2
##### Input
    [
      "www.demisto.com",
      "www.paloaltonetworks.com",
      {
        "Host": "www.paloaltonetworks.com"
      }
    ]

##### Filter
> **Operator**: wildcard: doesn't match

> **Path**: 

> **Filter**:

    ???.paloaltonetworks.*

##### Output
    [
      "www.demisto.com",
      {
        "Host": "www.paloaltonetworks.com"
      }
    ]

</details>


----
### Operator: `wildcard: doesn't match caseless`
<details><summary>
Returns a set of elements which doesn't match a wildcard pattern given in a filter.
The matching is peformed case-insensitively and between `string` data types. It doesn't match for a element whose data type is not `string`.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    WWW.PaloAltoNetworks.COM

##### Filter
> **Operator**: wildcard: doesn't match caseless

> **Path**: 

> **Filter**:

    ???.paloaltonetworks.*

##### Output
    null


#### Example 2
##### Input
    [
      "www.demisto.com",
      "WWW.PaloAltoNetworks.COM",
      {
        "Host": "www.paloaltonetworks.com"
      }
    ]

##### Filter
> **Operator**: wildcard: doesn't match caseless

> **Path**: 

> **Filter**:

    ???.paloaltonetworks.*

##### Output
    [
      "www.demisto.com",
      {
        "Host": "www.paloaltonetworks.com"
      }
    ]

</details>


----
### Operator: `regex: matches`
<details><summary>
Returns a set of elements which matches a regular expression pattern given in a filter.
The matching is peformed between `string` data types. It doesn't match for a element whose data type is not `string`.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    www.paloaltonetworks.com

##### Filter
> **Operator**: regex: matches

> **Path**: 

> **Filter**:

    .*paloaltonetworks.*

##### Output
    www.paloaltonetworks.com


#### Example 2
##### Input
    [
      "www.demisto.com",
      "www.paloaltonetworks.com",
      {
        "Host": "www.paloaltonetworks.com"
      }
    ]

##### Filter
> **Operator**: regex: matches

> **Path**: 

> **Filter**:

    .*paloaltonetworks.*

##### Output
    [
      "www.paloaltonetworks.com"
    ]

</details>


----
### Operator: `regex: matches caseless`
<details><summary>
Returns a set of elements which matches a regular expression pattern given in a filter.
The matching is peformed case-insensitively and between `string` data types. It doesn't match for a element whose data type is not `string`.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    WWW.PaloAltoNetworks.COM

##### Filter
> **Operator**: regex: matches caseless

> **Path**: 

> **Filter**:

    .*paloaltonetworks.*

##### Output
    WWW.PaloAltoNetworks.COM


#### Example 2
##### Input
    [
      "www.demisto.com",
      "WWW.PaloAltoNetworks.COM",
      {
        "Host": "www.paloaltonetworks.com"
      }
    ]

##### Filter
> **Operator**: regex: matches caseless

> **Path**: 

> **Filter**:

    .*paloaltonetworks.*

##### Output
    [
      "WWW.PaloAltoNetworks.COM"
    ]

</details>


----
### Operator: `regex: doesn't match`
<details><summary>
Returns a set of elements which doesn't match a regular expression pattern given in a filter.
The matching is peformed between `string` data types. It doesn't match for a element whose data type is not `string`.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    www.paloaltonetworks.com

##### Filter
> **Operator**: regex: doesn't match

> **Path**: 

> **Filter**:

    .*paloaltonetworks.*

##### Output
    null


#### Example 2
##### Input
    [
      "www.demisto.com",
      "www.paloaltonetworks.com",
      {
        "Host": "www.paloaltonetworks.com"
      }
    ]

##### Filter
> **Operator**: regex: doesn't match

> **Path**: 

> **Filter**:

    .*paloaltonetworks.*

##### Output
    [
      "www.demisto.com",
      {
        "Host": "www.paloaltonetworks.com"
      }
    ]

</details>


----
### Operator: `regex: doesn't match caseless`
<details><summary>
Returns a set of elements which doesn't match a regular expression pattern given in a filter.
The matching is peformed case-insensitively and between `string` data types. It doesn't match for a element whose data type is not `string`.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    WWW.PaloAltoNetworks.COM

##### Filter
> **Operator**: regex: doesn't match caseless

> **Path**: 

> **Filter**:

    .*paloaltonetworks.*

##### Output
    null


#### Example 2
##### Input
    [
      "www.demisto.com",
      "WWW.PaloAltoNetworks.COM",
      {
        "Host": "www.paloaltonetworks.com"
      }
    ]

##### Filter
> **Operator**: regex: doesn't match caseless

> **Path**: 

> **Filter**:

    .*paloaltonetworks.*

##### Output
    [
      "www.demisto.com",
      {
        "Host": "www.paloaltonetworks.com"
      }
    ]

</details>


----
### Operator: `in list`
<details><summary>
Returns a set of elements which matches any of strings of a comma separated list.
The matching always evaluates to false for a element whose data type is not `string`.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    banana

##### Filter
> **Operator**: in list

> **Path**: 

> **Filter**:

    apple,banana,cherry

##### Output
    banana


#### Example 2
##### Input
    [
      "apple",
      "melon",
      "banana",
      {
        "fruit": "orange"
      }
    ]

##### Filter
> **Operator**: in list

> **Path**: 

> **Filter**:

    apple,banana,cherry

##### Output
    [
      "apple",
      "banana"
    ]

</details>


----
### Operator: `in caseless list`
<details><summary>
Returns a set of elements which matches any of strings of a comma separated list.
The matching is peformed case-insensitively, and always evaluates to false for a element whose data type is not `string`.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    Banana

##### Filter
> **Operator**: in caseless list

> **Path**: 

> **Filter**:

    apple,banana,cherry

##### Output
    Banana


#### Example 2
##### Input
    [
      "Apple",
      "Melon",
      "Banana",
      {
        "Fruit": "Orange"
      }
    ]

##### Filter
> **Operator**: in caseless list

> **Path**: 

> **Filter**:

    apple,banana,cherry

##### Output
    [
      "Apple",
      "Banana"
    ]

</details>


----
### Operator: `not in list`
<details><summary>
Returns a set of elements which doesn't match any of strings of a comma separated list.
The matching always evaluates to false for a element whose data type is not `string`.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    melon

##### Filter
> **Operator**: not in list

> **Path**: 

> **Filter**:

    apple,banana,cherry

##### Output
    melon


#### Example 2
##### Input
    banana

##### Filter
> **Operator**: not in list

> **Path**: 

> **Filter**:

    apple,banana,cherry

##### Output
    null


#### Example 3
##### Input
    [
      "apple",
      "melon",
      "banana",
      {
        "fruit": "orange"
      }
    ]

##### Filter
> **Operator**: not in list

> **Path**: 

> **Filter**:

    apple,banana,cherry

##### Output
    [
      "melon",
      {
        "fruit": "orange"
      }
    ]

</details>


----
### Operator: `not in caseless list`
<details><summary>
Returns a set of elements which doesn't match any of strings of a comma separated list.
The matching is peformed case-insensitively, and always evaluates to false for a element whose data type is not `string`.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    Melon

##### Filter
> **Operator**: not in caseless list

> **Path**: 

> **Filter**:

    apple,banana,cherry

##### Output
    Melon


#### Example 2
##### Input
    Banana

##### Filter
> **Operator**: not in caseless list

> **Path**: 

> **Filter**:

    apple,banana,cherry

##### Output
    null


#### Example 3
##### Input
    [
      "Apple",
      "Melon",
      "Banana",
      {
        "Fruit": "Orange"
      }
    ]

##### Filter
> **Operator**: not in caseless list

> **Path**: 

> **Filter**:

    apple,banana,cherry

##### Output
    [
      "Melon",
      {
        "Fruit": "Orange"
      }
    ]

</details>


----
### Operator: `contains`
<details><summary>
Returns an entire value if any of the elements matches a string given in a filter, `null` otherwise.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    apple

##### Filter
> **Operator**: contains

> **Path**: 

> **Filter**:

    apple

##### Output
    apple


#### Example 2
##### Input
    banana

##### Filter
> **Operator**: contains

> **Path**: 

> **Filter**:

    apple

##### Output
    null


#### Example 3
##### Input
    [
      "apple",
      "banana",
      "cherry"
    ]

##### Filter
> **Operator**: contains

> **Path**: 

> **Filter**:

    apple

##### Output
    [
      "apple",
      "banana",
      "cherry"
    ]

</details>


----
### Operator: `contains caseless`
<details><summary>
Returns an entire value if any of the elements matches a string given in a filter, `null` otherwise.
The matching is peformed case-insensitively.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    Apple

##### Filter
> **Operator**: contains caseless

> **Path**: 

> **Filter**:

    apple

##### Output
    Apple


#### Example 2
##### Input
    [
      "Apple",
      "Banana",
      "Cherry"
    ]

##### Filter
> **Operator**: contains caseless

> **Path**: 

> **Filter**:

    apple

##### Output
    [
      "Apple",
      "Banana",
      "Cherry"
    ]

</details>


----
### Operator: `doesn't contain`
<details><summary>
Returns an entire value if all of the elements doesn't match a string given in a filter, `null` otherwise.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    apple

##### Filter
> **Operator**: doesn't contain

> **Path**: 

> **Filter**:

    apple

##### Output
    null


#### Example 2
##### Input
    banana

##### Filter
> **Operator**: doesn't contain

> **Path**: 

> **Filter**:

    apple

##### Output
    banana


#### Example 3
##### Input
    [
      "apple",
      "banana",
      "cherry"
    ]

##### Filter
> **Operator**: doesn't contain

> **Path**: 

> **Filter**:

    apple

##### Output
    null

</details>


----
### Operator: `doesn't contain caseless`
<details><summary>
Returns an entire value if all of the elements doesn't match a string given in a filter, `null` otherwise.
The matching is peformed case-insensitively.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    Apple

##### Filter
> **Operator**: doesn't contain caseless

> **Path**: 

> **Filter**:

    apple

##### Output
    null


#### Example 2
##### Input
    banana

##### Filter
> **Operator**: doesn't contain caseless

> **Path**: 

> **Filter**:

    apple

##### Output
    banana


#### Example 3
##### Input
    [
      "Apple",
      "Banana",
      "Cherry"
    ]

##### Filter
> **Operator**: doesn't contain caseless

> **Path**: 

> **Filter**:

    apple

##### Output
    null

</details>


----
### Operator: `wildcard: contains`
<details><summary>
Returns an entire value if any of the elements matches a wildcard pattern given in a filter, `null` otherwise.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    apple

##### Filter
> **Operator**: wildcard: contains

> **Path**: 

> **Filter**:

    *a*

##### Output
    apple


#### Example 2
##### Input
    [
      "apple",
      "banana",
      "cherry"
    ]

##### Filter
> **Operator**: wildcard: contains

> **Path**: 

> **Filter**:

    *a*

##### Output
    [
      "apple",
      "banana",
      "cherry"
    ]

</details>


----
### Operator: `wildcard: contains caseless`
<details><summary>
Returns an entire value if any of the elements matches a wildcard pattern given in a filter, `null` otherwise.
The matching is peformed case-insensitively.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    Apple

##### Filter
> **Operator**: wildcard: contains caseless

> **Path**: 

> **Filter**:

    *a*

##### Output
    Apple


#### Example 2
##### Input
    [
      "Apple",
      "Banana",
      "Cherry"
    ]

##### Filter
> **Operator**: wildcard: contains caseless

> **Path**: 

> **Filter**:

    *a*

##### Output
    [
      "Apple",
      "Banana",
      "Cherry"
    ]

</details>


----
### Operator: `wildcard: doesn't contain`
<details><summary>
Returns an entire value if all of the elements doesn't match a wildcard pattern given in a filter, `null` otherwise.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    apple

##### Filter
> **Operator**: wildcard: doesn't contain

> **Path**: 

> **Filter**:

    *a*

##### Output
    null


#### Example 2
##### Input
    cherry

##### Filter
> **Operator**: wildcard: doesn't contain

> **Path**: 

> **Filter**:

    *a*

##### Output
    cherry


#### Example 3
##### Input
    [
      "cherry",
      "melon"
    ]

##### Filter
> **Operator**: wildcard: doesn't contain

> **Path**: 

> **Filter**:

    *a*

##### Output
    [
      "cherry",
      "melon"
    ]

</details>


----
### Operator: `wildcard: doesn't contain caseless`
<details><summary>
Returns an entire value if all of the elements doesn't match a wildcard pattern given in a filter, `null` otherwise.
The matching is peformed case-insensitively.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    Apple

##### Filter
> **Operator**: wildcard: doesn't contain caseless

> **Path**: 

> **Filter**:

    *a*

##### Output
    null


#### Example 2
##### Input
    cherry

##### Filter
> **Operator**: wildcard: doesn't contain caseless

> **Path**: 

> **Filter**:

    *a*

##### Output
    cherry


#### Example 3
##### Input
    [
      "Cherry",
      "Melon"
    ]

##### Filter
> **Operator**: wildcard: doesn't contain caseless

> **Path**: 

> **Filter**:

    *a*

##### Output
    [
      "Cherry",
      "Melon"
    ]

</details>


----
### Operator: `regex: contains`
<details><summary>
Returns an entire value if any of the elements matches a regular expression given in a filter, `null` otherwise.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    apple

##### Filter
> **Operator**: regex: contains

> **Path**: 

> **Filter**:

    .*a.*

##### Output
    apple


#### Example 2
##### Input
    [
      "apple",
      "banana",
      "cherry"
    ]

##### Filter
> **Operator**: regex: contains

> **Path**: 

> **Filter**:

    .*a.*

##### Output
    [
      "apple",
      "banana",
      "cherry"
    ]

</details>


----
### Operator: `regex: contains caseless`
<details><summary>
Returns an entire value if any of the elements matches a regular expression given in a filter, `null` otherwise.
The matching is peformed case-insensitively.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    Apple

##### Filter
> **Operator**: regex: contains caseless

> **Path**: 

> **Filter**:

    .*a.*

##### Output
    Apple


#### Example 2
##### Input
    [
      "Apple",
      "Banana",
      "Cherry"
    ]

##### Filter
> **Operator**: regex: contains caseless

> **Path**: 

> **Filter**:

    .*a.*

##### Output
    [
      "Apple",
      "Banana",
      "Cherry"
    ]

</details>


----
### Operator: `regex: doesn't contain`
<details><summary>
Returns an entire value if all of the elements doesn't match a regular expression given in a filter, `null` otherwise.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    apple

##### Filter
> **Operator**: regex: doesn't contain

> **Path**: 

> **Filter**:

    .*a.*

##### Output
    null


#### Example 2
##### Input
    cherry

##### Filter
> **Operator**: regex: doesn't contain

> **Path**: 

> **Filter**:

    .*a.*

##### Output
    cherry


#### Example 3
##### Input
    [
      "cherry",
      "melon"
    ]

##### Filter
> **Operator**: regex: doesn't contain

> **Path**: 

> **Filter**:

    .*a.*

##### Output
    [
      "cherry",
      "melon"
    ]

</details>


----
### Operator: `regex: doesn't contain caseless`
<details><summary>
Returns an entire value if all of the elements doesn't match a regular expression given in a filter, `null` otherwise.
The matching is peformed case-insensitively.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    Apple

##### Filter
> **Operator**: regex: doesn't contain caseless

> **Path**: 

> **Filter**:

    .*a.*

##### Output
    null


#### Example 2
##### Input
    cherry

##### Filter
> **Operator**: regex: doesn't contain caseless

> **Path**: 

> **Filter**:

    .*a.*

##### Output
    cherry


#### Example 3
##### Input
    [
      "Cherry",
      "Melon"
    ]

##### Filter
> **Operator**: regex: doesn't contain caseless

> **Path**: 

> **Filter**:

    .*a.*

##### Output
    [
      "Cherry",
      "Melon"
    ]

</details>


----
### Operator: `matches any line of`
<details><summary>
Returns a set of elements which matches any line of a text given in a filter.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    banana

##### Filter
> **Operator**: matches any line of

> **Path**: 

> **Filter**:

    apple
    banana
    cherry

##### Output
    banana


#### Example 2
##### Input
    [
      "apple",
      "banana",
      "cherry"
    ]

##### Filter
> **Operator**: matches any line of

> **Path**: 

> **Filter**:

    orange
    banana
    apple

##### Output
    [
      "apple",
      "banana"
    ]

#### Example 3
##### Input
    [
      "apple",
      "banana",
      "cherry"
    ]

##### Filter
> **Operator**: matches any line of

> **Path**: 

> **Filter**:

    melon
    lemon
    orange

##### Output
    [
    ]

</details>


----
### Operator: `matches any caseless line of`
<details><summary>
Returns a set of elements which matches any line of a text given in a filter.
The matching is peformed case-insensitively.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    Banana

##### Filter
> **Operator**: matches any caseless line of

> **Path**: 

> **Filter**:

    apple
    banana
    cherry

##### Output
    Banana


#### Example 2
##### Input
    [
      "Apple",
      "Banana",
      "Cherry"
    ]

##### Filter
> **Operator**: matches any caseless line of

> **Path**: 

> **Filter**:

    orange
    banana
    apple

##### Output
    [
      "Apple",
      "Banana"
    ]

</details>


----
### Operator: `doesn't match any line of`
<details><summary>
Returns a set of elements which doesn't match any line of a text given in a filter.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    banana

##### Filter
> **Operator**: doesn't match any line of

> **Path**: 

> **Filter**:

    apple
    banana
    cherry

##### Output
    null


#### Example 2
##### Input
    [
      "apple",
      "banana",
      "cherry"
    ]

##### Filter
> **Operator**: doesn't match any line of

> **Path**: 

> **Filter**:

    melon
    orange
    banana

##### Output
    [
      "apple",
      "cherry"
    ]

</details>


----
### Operator: `doesn't match any caseless line of`
<details><summary>
Returns a set of elements which doesn't match any line of a text given in a filter.
The matching is peformed case-insensitively.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    Banana

##### Filter
> **Operator**: doesn't match any caseless line of

> **Path**: 

> **Filter**:

    apple
    banana
    cherry

##### Output
    null


#### Example 2
##### Input
    [
      "Apple",
      "Banana",
      "Cherry"
    ]

##### Filter
> **Operator**: doesn't match any caseless line of

> **Path**: 

> **Filter**:

    melon
    lemon
    orange

##### Output
    [
      "Apple",
      "Banana",
      "Cherry"
    ]


#### Example 3
##### Input
    [
      "Apple",
      "Banana",
      "Cherry"
    ]

##### Filter
> **Operator**: doesn't match any caseless line of

> **Path**: 

> **Filter**:

    melon
    orange
    banana

##### Output
    [
      "Apple",
      "Cherry"
    ]

</details>


----
### Operator: `matches any string of`
<details><summary>
Returns a set of elements which matches any strings given in a filter.
</summary><p/>

> **Filter Format**: `<JSON string> or <JSON array of string>`

#### Example 1
##### Input
    banana

##### Filter
> **Operator**: matches any string of

> **Path**: 

> **Filter**:

    "banana"

##### Output
    banana


#### Example 2
##### Input
    banana

##### Filter
> **Operator**: matches any string of

> **Path**: 

> **Filter**:

    [
      "apple",
      "banana",
      "cherry"
    ]

##### Output
    banana


#### Example 3
##### Input
    [
      "apple",
      "banana",
      "cherry"
    ]

##### Filter
> **Operator**: matches any string of

> **Path**: 

> **Filter**:

    [
      "orange",
      "banana",
      "apple"
    ]

##### Output
    [
      "apple",
      "banana"
    ]

#### Example 4
##### Input
    [
      "apple",
      "banana",
      "cherry"
    ]

##### Filter
> **Operator**: matches any string of

> **Path**: 

> **Filter**:

    [
      "melon",
      "lemon",
      "orange"
    ]

##### Output
    [
    ]

</details>


----
### Operator: `matches any caseless string of`
<details><summary>
Returns a set of elements which matches any strings given in a filter. The matching is peformed case-insensitively.
</summary><p/>

> **Filter Format**: `<JSON string> or <JSON array of string>`

#### Example 1
##### Input
    Banana

##### Filter
> **Operator**: matches any caseless string of

> **Path**: 

> **Filter**:

    [
      "apple",
      "banana",
      "cherry"
    ]

##### Output
    Banana


#### Example 2
##### Input
    [
      "Apple",
      "Banana",
      "Cherry"
    ]

##### Filter
> **Operator**: matches any caseless string of

> **Path**: 

> **Filter**:

    [
      "orange",
      "banana",
      "apple"
    ]

##### Output
    [
      "Apple",
      "Banana"
    ]

</details>


----
### Operator: `doesn't match any string of`
<details><summary>
Returns a set of elements which doesn't match any strings given in a filter.
</summary><p/>

> **Filter Format**: `<JSON string> or <JSON array of string>`

#### Example 1
##### Input
    banana

##### Filter
> **Operator**: doesn't match any string of

> **Path**: 

> **Filter**:

    [
      "apple",
      "banana",
      "cherry"
    ]

##### Output
    null


#### Example 2
##### Input
    [
      "apple",
      "banana",
      "cherry"
    ]

##### Filter
> **Operator**: doesn't match any string of

> **Path**: 

> **Filter**:

    [
      "melon",
      "orange",
      "banana"
    ]

##### Output
    [
      "apple",
      "cherry"
    ]

</details>


----
### Operator: `doesn't match any caseless string of`
<details><summary>
Returns a set of elements which doesn't match any strings given in a filter.
The matching is peformed case-insensitively.
</summary><p/>

> **Filter Format**: `<JSON string> or <JSON array of string>`

#### Example 1
##### Input
    Banana

##### Filter
> **Operator**: doesn't match any caseless string of

> **Path**: 

> **Filter**:

    [
      "apple",
      "banana",
      "cherry"
    ]

##### Output
    null


#### Example 2
##### Input
    [
      "Apple",
      "Banana",
      "Cherry"
    ]

##### Filter
> **Operator**: doesn't match any caseless string of

> **Path**: 

> **Filter**:

    [
      "melon",
      "orange",
      "banana"
    ]

##### Output
    [
      "Apple",
      "Cherry"
    ]

</details>


----
### Operator: `wildcard: matches any string of`
<details><summary>
Returns a set of elements which matches any wildcard patterns given in a filter.
</summary><p/>

> **Filter Format**: `<JSON string> or <JSON array of string>`

#### Example 1
##### Input
    banana

##### Filter
> **Operator**: wildcard: matches any string of

> **Path**: 

> **Filter**:

    "b?????"

##### Output
    banana


#### Example 2
##### Input
    banana

##### Filter
> **Operator**: wildcard: matches any string of

> **Path**: 

> **Filter**:

    [
      "b?????",
      "*c*",
      "*d*"
    ]

##### Output
    banana


#### Example 3
##### Input
    [
      "apple",
      "banana",
      "cherry"
    ]

##### Filter
> **Operator**: wildcard: matches any string of

> **Path**: 

> **Filter**:

    [
      "b?????",
      "*c*",
      "*d*"
    ]

##### Output
    [
      "banana",
      "cherry"
    ]

#### Example 4
##### Input
    [
      "melon",
      "lemon",
      "orange"
    ]

##### Filter
> **Operator**: wildcard: matches any string of

> **Path**: 

> **Filter**:

    [
      "b?????",
      "*c*",
      "*d*"
    ]

##### Output
    [
    ]

</details>


----
### Operator: `wildcard: matches any caseless string of`
<details><summary>
Returns a set of elements which matches any wildcard patterns given in a filter. The matching is peformed case-insensitively.
</summary><p/>

> **Filter Format**: `<JSON string> or <JSON array of string>`

#### Example 1
##### Input
    Banana

##### Filter
> **Operator**: wildcard: matches any caseless string of

> **Path**: 

> **Filter**:

    [
      "b?????",
      "*c*",
      "*d*"
    ]

##### Output
    Banana


#### Example 2
##### Input
    [
      "Apple",
      "Banana",
      "Cherry"
    ]

##### Filter
> **Operator**: wildcard: matches any caseless string of

> **Path**: 

> **Filter**:

    [
      "b?????",
      "*c*",
      "*d*"
    ]

##### Output
    [
      "Banana",
      "Cherry"
    ]

</details>


----
### Operator: `wildcard: doesn't match any string of`
<details><summary>
Returns a set of elements which doesn't match any wildcard patterns given in a filter.
</summary><p/>

> **Filter Format**: `<JSON string> or <JSON array of string>`

#### Example 1
##### Input
    banana

##### Filter
> **Operator**: wildcard: doesn't match any string of

> **Path**: 

> **Filter**:

    [
      "b?????",
      "*c*",
      "*d*"
    ]

##### Output
    null


#### Example 2
##### Input
    [
      "apple",
      "banana",
      "cherry"
    ]

##### Filter
> **Operator**: wildcard: doesn't match any string of

> **Path**: 

> **Filter**:

    [
      "b?????",
      "*c*",
      "*d*"
    ]

##### Output
    [
      "apple"
    ]

</details>


----
### Operator: `wildcard: doesn't match any caseless string of`
<details><summary>
Returns a set of elements which doesn't match any wildcard patterns given in a filter.
The matching is peformed case-insensitively.
</summary><p/>

> **Filter Format**: `<JSON string> or <JSON array of string>`

#### Example 1
##### Input
    Banana

##### Filter
> **Operator**: wildcard: doesn't match any caseless string of

> **Path**: 

> **Filter**:

    [
      "b?????",
      "*c*",
      "*d*"
    ]

##### Output
    null


#### Example 2
##### Input
    [
      "Apple",
      "Banana",
      "Cherry"
    ]

##### Filter
> **Operator**: wildcard: doesn't match any caseless string of

> **Path**: 

> **Filter**:

    [
      "b?????",
      "*c*",
      "*d*"
    ]

##### Output
    [
      "Apple"
    ]

</details>


----
### Operator: `regex: matches any string of`
<details><summary>
Returns a set of elements which matches any regular expression patterns given in a filter.
</summary><p/>

> **Filter Format**: `<JSON string> or <JSON array of string>`

#### Example 1
##### Input
    banana

##### Filter
> **Operator**: regex: matches any string of

> **Path**: 

> **Filter**:

    "b....."

##### Output
    banana


#### Example 2
##### Input
    banana

##### Filter
> **Operator**: regex: matches any string of

> **Path**: 

> **Filter**:

    [
      "b.....",
      ".*c.*",
      ".*d.*"
    ]

##### Output
    banana


#### Example 3
##### Input
    [
      "apple",
      "banana",
      "cherry"
    ]

##### Filter
> **Operator**: regex: matches any string of

> **Path**: 

> **Filter**:

    [
      "b.....",
      ".*c.*",
      ".*d.*"
    ]

##### Output
    [
      "banana",
      "cherry"
    ]

#### Example 4
##### Input
    [
      "melon",
      "lemon",
      "orange"
    ]

##### Filter
> **Operator**: regex: matches any string of

> **Path**: 

> **Filter**:

    [
      "b.....",
      ".*c.*",
      ".*d.*"
    ]

##### Output
    [
    ]

</details>


----
### Operator: `regex: matches any caseless string of`
<details><summary>
Returns a set of elements which matches any regular expression patterns given in a filter. The matching is peformed case-insensitively.
</summary><p/>

> **Filter Format**: `<JSON string> or <JSON array of string>`

#### Example 1
##### Input
    Banana

##### Filter
> **Operator**: regex: matches any caseless string of

> **Path**: 

> **Filter**:

    [
      "b.....",
      ".*c.*",
      ".*d.*"
    ]

##### Output
    Banana


#### Example 2
##### Input
    [
      "Apple",
      "Banana",
      "Cherry"
    ]

##### Filter
> **Operator**: regex: matches any caseless string of

> **Path**: 

> **Filter**:

    [
      "b.....",
      ".*c.*",
      ".*d.*"
    ]

##### Output
    [
      "Banana",
      "Cherry"
    ]

</details>


----
### Operator: `regex: doesn't match any string of`
<details><summary>
Returns a set of elements which doesn't match any regular expression patterns given in a filter.
</summary><p/>

> **Filter Format**: `<JSON string> or <JSON array of string>`

#### Example 1
##### Input
    banana

##### Filter
> **Operator**: regex: doesn't match any string of

> **Path**: 

> **Filter**:

    [
      "b.....",
      ".*c.*",
      ".*d.*"
    ]

##### Output
    null


#### Example 2
##### Input
    [
      "apple",
      "banana",
      "cherry"
    ]

##### Filter
> **Operator**: regex: doesn't match any string of

> **Path**: 

> **Filter**:

    [
      "b.....",
      ".*c.*",
      ".*d.*"
    ]

##### Output
    [
      "apple"
    ]

</details>


----
### Operator: `regex: doesn't match any caseless string of`
<details><summary>
Returns a set of elements which doesn't match any regular expression patterns given in a filter.
The matching is peformed case-insensitively.
</summary><p/>

> **Filter Format**: `<JSON string> or <JSON array of string>`

#### Example 1
##### Input
    Banana

##### Filter
> **Operator**: regex: doesn't match any caseless string of

> **Path**: 

> **Filter**:

    [
      "b.....",
      ".*c.*",
      ".*d.*"
    ]

##### Output
    null


#### Example 2
##### Input
    [
      "Apple",
      "Banana",
      "Cherry"
    ]

##### Filter
> **Operator**: regex: doesn't match any caseless string of

> **Path**: 

> **Filter**:

    [
      "b.....",
      ".*c.*",
      ".*d.*"
    ]

##### Output
    [
      "Apple"
    ]

</details>


----
### Operator: `contains any line of`
<details><summary>
Returns an entire value if any of the elements matches any line of a text given in a filter, `null` otherwise.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    banana

##### Filter
> **Operator**: contains any line of

> **Path**: 

> **Filter**:

    apple
    banana
    cherry

##### Output
    banana


#### Example 2
##### Input
    [
      "apple",
      "banana",
      "cherry"
    ]

##### Filter
> **Operator**: contains any line of

> **Path**: 

> **Filter**:

    melon
    orange
    banana
    

##### Output
    [
      "apple",
      "banana",
      "cherry"
    ]

#### Example 3
##### Input
    [
      "apple",
      "banana",
      "cherry"
    ]

##### Filter
> **Operator**: contains any line of

> **Path**: 

> **Filter**:

    melon
    lemon
    orange
    

##### Output
    null

</details>


----
### Operator: `contains any caseless line of`
<details><summary>
Returns an entire value if any of the elements matches any line of a text given in a filter, `null` otherwise.
The matching is peformed case-insensitively.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    Banana

##### Filter
> **Operator**: contains any caseless line of

> **Path**: 

> **Filter**:

    apple
    banana
    cherry

##### Output
    Banana


#### Example 2
##### Input
    [
      "Apple",
      "Banana",
      "Cherry"
    ]

##### Filter
> **Operator**: contains any caseless line of

> **Path**: 

> **Filter**:

    melon
    orange
    banana
    

##### Output
    [
      "Apple",
      "Banana",
      "Cherry"
    ]

</details>


----
### Operator: `doesn't contain any line of`
<details><summary>
Returns an entire value if all of the elements doesn't match any line of a text given in a filter, `null` otherwise.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    banana

##### Filter
> **Operator**: doesn't contain any line of

> **Path**: 

> **Filter**:

    apple
    banana
    cherry

##### Output
    null


#### Example 2
##### Input
    [
      "apple",
      "banana",
      "cherry"
    ]

##### Filter
> **Operator**: doesn't contain any line of

> **Path**: 

> **Filter**:

    melon
    lemon
    orange
    

##### Output
    [
      "apple",
      "banana",
      "cherry"
    ]

#### Example 3
##### Input
    [
      "apple",
      "banana",
      "cherry"
    ]

##### Filter
> **Operator**: doesn't contain any line of

> **Path**: 

> **Filter**:

    melon
    orange
    banana
    

##### Output
    null

</details>


----
### Operator: `doesn't contain any caseless line of`
<details><summary>
Returns an entire value if all of the elements doesn't match any line of a text given in a filter, `null` otherwise.
The matching is peformed case-insensitively.
</summary><p/>

> **Filter Format**: `string`

#### Example 1
##### Input
    Banana

##### Filter
> **Operator**: doesn't contain any caseless line of

> **Path**: 

> **Filter**:

    apple
    banana
    cherry

##### Output
    null


#### Example 2
##### Input
    [
      "Apple",
      "Banana",
      "Cherry"
    ]

##### Filter
> **Operator**: doesn't contain any caseless line of

> **Path**: 

> **Filter**:

    melon
    lemon
    orange
    

##### Output
    [
      "Apple",
      "Banana",
      "Cherry"
    ]

#### Example 3
##### Input
    [
      "Apple",
      "Banana",
      "Cherry"
    ]

##### Filter
> **Operator**: doesn't contain any caseless line of

> **Path**: 

> **Filter**:

    melon
    orange
    banana
    

##### Output
    null

</details>


----
### Operator: `contains any string of`
<details><summary>
Returns an entire value if any of the elements matches any strings given in a filter, `null` otherwise.
</summary><p/>

> **Filter Format**: `<JSON string> or <JSON array of string>`

#### Example 1
##### Input
    banana

##### Filter
> **Operator**: contains any string of

> **Path**: 

> **Filter**:

    "banana"

##### Output
    banana


#### Example 2
##### Input
    banana

##### Filter
> **Operator**: contains any string of

> **Path**: 

> **Filter**:

    [
      "apple",
      "banana",
      "cherry"
    ]

##### Output
    banana


#### Example 3
##### Input
    [
      "apple",
      "banana",
      "cherry"
    ]

##### Filter
> **Operator**: contains any string of

> **Path**: 

> **Filter**:

    [
      "melon",
      "orange",
      "banana"
    ]

##### Output
    [
      "apple",
      "banana",
      "cherry"
    ]


#### Example 4
##### Input
    [
      "apple",
      "banana",
      "cherry"
    ]

##### Filter
> **Operator**: contains any string of

> **Path**: 

> **Filter**:

    [
      "melon",
      "lemon",
      "orange"
    ]

##### Output
    null

</details>


----
### Operator: `contains any caseless line of`
<details><summary>
Returns an entire value if any of the elements matches any strings given in a filter, `null` otherwise.
The matching is peformed case-insensitively.
</summary><p/>

> **Filter Format**: `<JSON string> or <JSON array of string>`

#### Example 1
##### Input
    Banana

##### Filter
> **Operator**: contains any caseless line of

> **Path**: 

> **Filter**:

    [
      "apple",
      "banana",
      "cherry"
    ]

##### Output
    Banana


#### Example 2
##### Input
    [
      "Apple",
      "Banana",
      "Cherry"
    ]

##### Filter
> **Operator**: contains any caseless line of

> **Path**: 

> **Filter**:

    [
      "melon",
      "orange",
      "banana"
    ]

##### Output
    [
      "Apple",
      "Banana",
      "Cherry"
    ]

</details>


----
### Operator: `doesn't contain any string of`
<details><summary>
Returns an entire value if all of the elements doesn't match any strings given in a filter, `null` otherwise.
</summary><p/>

> **Filter Format**: `<JSON string> or <JSON array of string>`

#### Example 1
##### Input
    banana

##### Filter
> **Operator**: doesn't contain any string of

> **Path**: 

> **Filter**:

    [
      "apple",
      "banana",
      "cherry"
    ]

##### Output
    null


#### Example 2
##### Input
    [
      "apple",
      "banana",
      "cherry"
    ]

##### Filter
> **Operator**: doesn't contain any string of

> **Path**: 

> **Filter**:

    [
      "melon",
      "lemon",
      "orange"
    ]

##### Output
    [
      "apple",
      "banana",
      "cherry"
    ]

#### Example 3
##### Input
    [
      "apple",
      "banana",
      "cherry"
    ]

##### Filter
> **Operator**: doesn't contain any string of

> **Path**: 

> **Filter**:

    [
      "melon",
      "orange",
      "banana"
    ]

##### Output
    null

</details>


----
### Operator: `doesn't contain any caseless line of`
<details><summary>
Returns an entire value if all of the elements doesn't match any strings given in a filter, `null` otherwise.
The matching is peformed case-insensitively.
</summary><p/>

> **Filter Format**: `<JSON string> or <JSON array of string>`

#### Example 1
##### Input
    Banana

##### Filter
> **Operator**: doesn't contain any caseless line of

> **Path**: 

> **Filter**:

    [
      "apple",
      "banana",
      "cherry"
    ]

##### Output
    null


#### Example 2
##### Input
    [
      "Apple",
      "Banana",
      "Cherry"
    ]

##### Filter
> **Operator**: doesn't contain any caseless line of

> **Path**: 

> **Filter**:

    [
      "melon",
      "lemon",
      "orange"
    ]

##### Output
    [
      "Apple",
      "Banana",
      "Cherry"
    ]

#### Example 3
##### Input
    [
      "Apple",
      "Banana",
      "Cherry"
    ]

##### Filter
> **Operator**: doesn't contain any caseless line of

> **Path**: 

> **Filter**:

    [
      "melon",
      "orange",
      "banana"
    ]

##### Output
    null

</details>


----
### Operator: `wildcard: contains any string of`
<details><summary>
Returns an entire value if any of the elements matches any wildcard patterns given in a filter, `null` otherwise.
</summary><p/>

> **Filter Format**: `<JSON string> or <JSON array of string>`

#### Example 1
##### Input
    banana

##### Filter
> **Operator**: wildcard: contains any string of

> **Path**: 

> **Filter**:

    "b?????"

##### Output
    banana


#### Example 2
##### Input
    banana

##### Filter
> **Operator**: wildcard: contains any string of

> **Path**: 

> **Filter**:

    [
      "b?????",
      "*c*",
      "*d*"
    ]

##### Output
    banana


#### Example 3
##### Input
    [
      "apple",
      "banana",
      "cherry"
    ]

##### Filter
> **Operator**: wildcard: contains any string of

> **Path**: 

> **Filter**:

    [
      "b?????",
      "*c*",
      "*d*"
    ]

##### Output
    [
      "apple",
      "banana",
      "cherry"
    ]


#### Example 4
##### Input
    [
      "melon",
      "lemon",
      "orange"
    ]

##### Filter
> **Operator**: wildcard: contains any string of

> **Path**: 

> **Filter**:

    [
      "b?????",
      "*c*",
      "*d*"
    ]

##### Output
    null

</details>


----
### Operator: `wildcard: contains any caseless string of`
<details><summary>
Returns an entire value if any of the elements matches any wildcard patterns given in a filter, `null` otherwise.
The matching is peformed case-insensitively.
</summary><p/>

> **Filter Format**: `<JSON string> or <JSON array of string>`

#### Example 1
##### Input
    Banana

##### Filter
> **Operator**: wildcard: contains any caseless string of

> **Path**: 

> **Filter**:

    [
      "b?????",
      "*c*",
      "*d*"
    ]

##### Output
    Banana


#### Example 2
##### Input
    [
      "Apple",
      "Banana",
      "Cherry"
    ]

##### Filter
> **Operator**: wildcard: contains any caseless string of

> **Path**: 

> **Filter**:

    [
      "b?????",
      "*c*",
      "*d*"
    ]

##### Output
    [
      "Apple",
      "Banana",
      "Cherry"
    ]

</details>


----
### Operator: `wildcard: doesn't contain any string of`
<details><summary>
Returns an entire value if all of the elements doesn't match any wildcard patterns given in a filter, `null` otherwise.
</summary><p/>

> **Filter Format**: `<JSON string> or <JSON array of string>`

#### Example 1
##### Input
    banana

##### Filter
> **Operator**: wildcard: doesn't contain any string of

> **Path**: 

> **Filter**:

    [
      "b?????",
      "*c*",
      "*d*"
    ]

##### Output
    null


#### Example 2
##### Input
    [
      "apple",
      "banana",
      "cherry"
    ]

##### Filter
> **Operator**: wildcard: doesn't contain any string of

> **Path**: 

> **Filter**:

    [
      "b?????",
      "*c*",
      "*d*"
    ]

##### Output
    null

#### Example 3
##### Input
    [
      "melon",
      "lemon",
      "orange"
    ]

##### Filter
> **Operator**: wildcard: doesn't contain any string of

> **Path**: 

> **Filter**:

    [
      "b?????",
      "*c*",
      "*d*"
    ]

##### Output
    [
      "melon",
      "lemon",
      "orange"
    ]

</details>


----
### Operator: `wildcard: doesn't contain any caseless line of`
<details><summary>
Returns an entire value if all of the elements doesn't match any wildcard patterns given in a filter, `null` otherwise.
The matching is peformed case-insensitively.
</summary><p/>

> **Filter Format**: `<JSON string> or <JSON array of string>`

#### Example 1
##### Input
    Banana

##### Filter
> **Operator**: wildcard: doesn't contain any caseless line of

> **Path**: 

> **Filter**:

    [
      "b?????",
      "*c*",
      "*d*"
    ]

##### Output
    null


#### Example 2
##### Input
    [
      "Melon",
      "Lemon",
      "Orange"
    ]

##### Filter
> **Operator**: wildcard: doesn't contain any caseless line of

> **Path**: 

> **Filter**:

    [
      "b?????",
      "*c*",
      "*d*"
    ]

##### Output
    [
      "Melon",
      "Lemon",
      "Orange"
    ]

#### Example 3
##### Input
    [
      "Apple",
      "Banana",
      "Cherry"
    ]

##### Filter
> **Operator**: wildcard: doesn't contain any caseless line of

> **Path**: 

> **Filter**:

    [
      "b?????",
      "*c*",
      "*d*"
    ]

##### Output
    null

</details>


----
### Operator: `regex: contains any string of`
<details><summary>
Returns an entire value if any of the elements matches any regular expression patterns given in a filter, `null` otherwise.
</summary><p/>

> **Filter Format**: `<JSON string> or <JSON array of string>`

#### Example 1
##### Input
    banana

##### Filter
> **Operator**: regex: contains any string of

> **Path**: 

> **Filter**:

    "b....."

##### Output
    banana


#### Example 2
##### Input
    banana

##### Filter
> **Operator**: regex: contains any string of

> **Path**: 

> **Filter**:

    [
      "b.....",
      ".*c.*",
      ".*d.*"
    ]

##### Output
    banana


#### Example 3
##### Input
    [
      "apple",
      "banana",
      "cherry"
    ]

##### Filter
> **Operator**: regex: contains any string of

> **Path**: 

> **Filter**:

    [
      "b.....",
      ".*c.*",
      ".*d.*"
    ]

##### Output
    [
      "apple",
      "banana",
      "cherry"
    ]


#### Example 4
##### Input
    [
      "melon",
      "lemon",
      "orange"
    ]

##### Filter
> **Operator**: regex: contains any string of

> **Path**: 

> **Filter**:

    [
      "b.....",
      ".*c.*",
      ".*d.*"
    ]

##### Output
    null

</details>


----
### Operator: `regex: contains any caseless string of`
<details><summary>
Returns an entire value if any of the elements matches any regex patterns given in a filter, `null` otherwise.
The matching is peformed case-insensitively.
</summary><p/>

> **Filter Format**: `<JSON string> or <JSON array of string>`

#### Example 1
##### Input
    Banana

##### Filter
> **Operator**: regex: contains any caseless string of

> **Path**: 

> **Filter**:

    [
      "b.....",
      ".*c.*",
      ".*d.*"
    ]

##### Output
    Banana


#### Example 2
##### Input
    [
      "Apple",
      "Banana",
      "Cherry"
    ]

##### Filter
> **Operator**: regex: contains any caseless string of

> **Path**: 

> **Filter**:

    [
      "b.....",
      ".*c.*",
      ".*d.*"
    ]

##### Output
    [
      "Apple",
      "Banana",
      "Cherry"
    ]

</details>


----
### Operator: `regex: doesn't contain any string of`
<details><summary>
Returns an entire value if all of the elements doesn't match any regex patterns given in a filter, `null` otherwise.
</summary><p/>

> **Filter Format**: `<JSON string> or <JSON array of string>`

#### Example 1
##### Input
    banana

##### Filter
> **Operator**: regex: doesn't contain any string of

> **Path**: 

> **Filter**:

    [
      "b.....",
      ".*c.*",
      ".*d.*"
    ]

##### Output
    null


#### Example 2
##### Input
    [
      "apple",
      "banana",
      "cherry"
    ]

##### Filter
> **Operator**: regex: doesn't contain any string of

> **Path**: 

> **Filter**:

    [
      "b.....",
      ".*c.*",
      ".*d.*"
    ]

##### Output
    null

#### Example 3
##### Input
    [
      "melon",
      "lemon",
      "orange"
    ]

##### Filter
> **Operator**: regex: doesn't contain any string of

> **Path**: 

> **Filter**:

    [
      "b.....",
      ".*c.*",
      ".*d.*"
    ]

##### Output
    [
      "melon",
      "lemon",
      "orange"
    ]

</details>


----
### Operator: `regex: doesn't contain any caseless line of`
<details><summary>
Returns an entire value if all of the elements doesn't match any regex patterns given in a filter, `null` otherwise.
The matching is peformed case-insensitively.
</summary><p/>

> **Filter Format**: `<JSON string> or <JSON array of string>`

#### Example 1
##### Input
    Banana

##### Filter
> **Operator**: regex: doesn't contain any caseless line of

> **Path**: 

> **Filter**:

    [
      "b.....",
      ".*c.*",
      ".*d.*"
    ]

##### Output
    null


#### Example 2
##### Input
    [
      "Melon",
      "Lemon",
      "Orange"
    ]

##### Filter
> **Operator**: regex: doesn't contain any caseless line of

> **Path**: 

> **Filter**:

    [
      "b.....",
      ".*c.*",
      ".*d.*"
    ]

##### Output
    [
      "Melon",
      "Lemon",
      "Orange"
    ]

#### Example 3
##### Input
    [
      "Apple",
      "Banana",
      "Cherry"
    ]

##### Filter
> **Operator**: regex: doesn't contain any caseless line of

> **Path**: 

> **Filter**:

    [
      "b.....",
      ".*c.*",
      ".*d.*"
    ]

##### Output
    null

</details>


----
### Operator: `matches expressions of`
<details><summary>
Returns the result of a value filtered by `expressions` given.
See `Filter Syntax` for the details of `expressions`.
</summary><p/>

> **Filter Format**: `expressions`

#### Example 1
##### Input
    [
      "aaa.dat",
      "bbb.exe",
      "ccc.exe"
    ]

##### Filter
> **Operator**: matches expressions of

> **Path**: 

> **Filter**:

    {
      "ends with": ".exe",
      "starts with": "c"
    }

##### Output
    [
      "ccc.exe"
    ]


#### Example 2
##### Input
    
    {
      "Domain": [
        "www.paloaltonetworks.com",
        "www.paloaltonetworks.co.jp",
        "www.demisto.com"
      ],
      "IP": [
        "1.1.1.1",
        "2.2.2.2",
        "3.3.3.3"
      ]
    }

##### Filter
> **Operator**: matches expressions of

> **Path**: Domain

> **Filter**:

    [
      {"ends with": ".co.jp"},
      "or",
      {"includes": "demisto"}
    ]

##### Output
    {
      "Domain": [
        "www.paloaltonetworks.co.jp",
        "www.demisto.com"
      ],
      "IP": [
        "1.1.1.1",
        "2.2.2.2",
        "3.3.3.3"
      ]
    }

</details>


----
### Operator: `matches conditions of`
<details><summary>
Returns the result of a value filtered by `conditions` given.
See `Filter Syntax` for the details of `conditions`.
</summary><p/>

> **Filter Format**: `conditions`

#### Example 1
##### Input
    {
      "TrustedDevices": [
        "D000002",
        "D000003"
      ],
      "Events": [
        {
          "Description": "User Logged In - Success",
          "DeviceID": "D000001"
        },
        {
          "Description": "File uploaded",
          "DeviceID": "D000001"
        },
        {
          "Description": "File downloaded",
          "DeviceID": "D000002"
        },
        {
          "Description": "User Logged In - Failed",
          "DeviceID": "D000003"
        }
      ]
    }

##### Filter
> **Operator**: matches conditions of

> **Path**: Events

> **Filter**:

    [
      {
        "Description": {
          "==": "User Logged In - Failed"
        }
      },
      "or",
      [
        {
          "Description": {
            "in list": "File uploaded,File downloaded"
          }
        },
        "and",
        "not",
        {
          "DeviceID": {
            "matches any string of": "${local.TrustedDevices}"
          }
        }
      ]
    ]

##### Output
    {
      "Events": [
         {
          "Description": "File uploaded",
          "DeviceID": "D000001"
        },
        {
          "Description": "User Logged In - Failed",
          "DeviceID": "D000003"
        }
      ],
      "TrustedDevices": [
        "D000002",
        "D000003"
      ]
    }


#### Example 2
##### Input
    {
      "Result": {
        "File": [
          {
            "Name": "a.dat",
            "Size": 100
          },
          {
            "Name": "b.exe",
            "Size": 200
          },
          {
            "Name": "c.txt",
            "Size": 300
          }
        ],
        "Host": [
          {
            "Name": "computer1",
            "IP": "1.1.1.1"
          },
          {
            "Name": "server1",
            "IP": "2.2.2.2"
          }
        ]
      }
    }

##### Filter
> **Operator**: matches conditions of

> **Path**: 

> **Filter**:

    {
      "Result.File": {
        "is filtered with" : {
          "Name": {
            "ends with": ".exe"
          }
        }
      },
      "Result.Host": {
        "is filtered with" : {
          "Name": {
            "starts with": "server"
          }
        }
      }
    }

##### Output
    {
      "Result": {
        "File": [
          {
            "Name": "b.exe",
            "Size": 200
          }
        ],
        "Host": [
          {
            "Name": "server1",
            "IP": "2.2.2.2"
          }
        ]
      }
    }


#### Example 3
##### Input
    {
      "Result": {
        "File": [
          {
            "Name": "a.dat",
            "Size": 100
          },
          {
            "Name": "b.exe",
            "Size": 200
          },
          {
            "Name": "c.txt",
            "Size": 300
          }
        ],
        "Host": [
          {
            "Name": "computer1",
            "IP": "1.1.1.1"
          },
          {
            "Name": "server1",
            "IP": "2.2.2.2"
          }
        ]
      }
    }

##### Filter
> **Operator**: matches conditions of

> **Path**: 

> **Filter**:

    {
      "Result": {
        "is filtered with" : {
          "File": {
            "is filtered with": {
              "Name": {
                "ends with": ".exe"
              }
            }
          },
          "Host": {
            "is filtered with": {
              "Name": {
                "starts with": "server"
              }
            }
          }
        }
      }
    }

##### Output
    {
      "Result": {
        "File": [
          {
            "Name": "b.exe",
            "Size": 200
          }
        ],
        "Host": [
          {
            "Name": "server1",
            "IP": "2.2.2.2"
          }
        ]
      }
    }


#### Example 4
##### Input
    {
      "Result" : {
        "Domain" : [
          "www.paloaltonetworks.com",
          "www.demisto.com",
          "paloaltonetowrks.com"
        ],
        "IP" : [
          "1.1.1.1",
          "2.2.2.2",
          "3.3.3.3"
        ]
      }
    }

##### Filter
> **Operator**: matches conditions of

> **Path**: 

> **Filter**:

    {
      "Result.Domain": {
        "is filtered with": {
          "": {
            "starts with": "www."
          }
        }
      }
    }

##### Output
    {
      "Result" : {
        "Domain" : [
          "www.paloaltonetworks.com",
          "www.demisto.com"
        ],
        "IP" : [
          "1.1.1.1",
          "2.2.2.2",
          "3.3.3.3"
        ]
      }
    }

</details>


----
### Operator: `value matches expressions of`
<details><summary>
Evaluates each value of dictionary elements or each element for values whose data type is not `dictionary`, and returns a set of the elements matched to expressions given in a filter.
See `Filter Syntax` for the details of `expressions`.
</summary><p/>

> **Filter Format**: `expressions`

#### Example 1
##### Input
    [
      "1.1.1.1",
      "2.2.2.2",
      "3.3.3.3"
    ]

##### Filter
> **Operator**: value matches expressions of

> **Path**: 

> **Filter**:

    {
      "contains": "1.1.1.1"
    }

##### Output
    [
      "1.1.1.1"
    ]


#### Example 2
##### Input
    {
      "Communication": {
        "Host1": [
          "1.1.1.1",
          "2.2.2.2"
        ],
        "Host2": "1.1.1.1",
        "Host3": [
          "3.3.3.3",
          "4.4.4.4"
        ]
      }
    }

##### Filter
> **Operator**: value matches expressions of

> **Path**: Communication

> **Filter**:

    {
      "contains": "1.1.1.1"
    }

##### Output
    {
      "Communication": {
        "Host1": [
          "1.1.1.1",
          "2.2.2.2"
        ],
        "Host2": "1.1.1.1"
      }
    }


</details>


----
### Operator: `value matches conditions of`
<details><summary>
Evaluates each value of dictionary elements, and returns a set of the elements matched to conditions given in a filter.
See `Filter Syntax` for the details of `conditions`.
</summary><p/>

> **Filter Format**: `conditions`

#### Example 1
##### Input
    {
      "Host1": {
        "User": "JDOE",
        "IP": "192.168.1.1",
        "Score": 30
      },
      "Host2": {
        "User": "TYAMADA",
        "IP": "192.168.1.2",
        "Score": 10
      },
      "Host3": {
        "User": "MBLACK",
        "IP": "3.3.3.3",
        "Score": 40
      }
    }

##### Filter
> **Operator**: value matches conditions of

> **Path**: 

> **Filter**:

    {
      "Score": {
        ">=": 20
      }
    }

##### Output
    {
      "Host1": {
        "User": "JDOE",
        "IP": "192.168.1.1",
        "Score": 30
      },
      "Host3": {
        "User": "MBLACK",
        "IP": "3.3.3.3",
        "Score": 40
      }
    }


#### Example 2
##### Input
    {
      "Host1": {
        "User": "JDOE",
        "IP": "192.168.1.1",
        "Score": 30,
        "File": {
          "Risk": [
            "xxx.exe",
            "yyy.pdf"
          ]
        }
      },
      "Host2": {
        "User": "TYAMADA",
        "IP": "192.168.1.2",
        "Score": 10
      },
      "Host3": {
        "User": "MBLACK",
        "IP": "3.3.3.3",
        "Score": 40,
        "File": {
          "Risk": [
            "aaa.pdf",
            "bbb.exe"
          ]
        }
      }
    }

##### Filter
> **Operator**: value matches conditions of

> **Path**: 

> **Filter**:

    {
      "Score": {
        ">=": 20
      },
      "File.Risk": {
        "is filtered with": {
          "": {
            "ends with": ".exe"
          }
        }
      }
    }

##### Output
    {
      "Host1": {
        "User": "JDOE",
        "IP": "192.168.1.1",
        "Score": 30,
        "File": {
          "Risk": [
            "xxx.exe"
          ]
        }
      },
      "Host3": {
        "User": "MBLACK",
        "IP": "3.3.3.3",
        "Score": 40,
        "File": {
          "Risk": [
            "bbb.exe"
          ]
        }
      }
    }


</details>


----
### Operator: `json: encode array`
<details><summary>
Returns an string in JSON which is encoded the entire value.
</summary><p/>

> **Filter Format**: `dict[str,Any]`

| *Parameter* | *Data Type* | *Description* |
| - | - | - |
| indent | int | The number of spaces per indent (Default: None) |

#### Example 1
##### Input
    [
      10,
      20
    ]

##### Filter
> **Operator**: json: encode array

> **Path**: 

> **Filter**:

    {
    }

##### Output
    "[10,20]"


#### Example 2
##### Input
    [
      10,
      20
    ]

##### Filter
> **Operator**: json: encode array

> **Path**: 

> **Filter**:

    {
      "indent": 4
    }

##### Output
    [
        "1.1.1.1",
        "2.2.2.2"
    ]


</details>


----
### Operator: `json: encode`
<details><summary>
Encodes each element and returns a set of JSON-encoded string.
</summary><p/>

> **Filter Format**: `dict[str,Any]`

| *Parameter* | *Data Type* | *Description* |
| - | - | - |
| indent | int | The number of spaces per indent (Default: None) |

#### Example 1
##### Input
    [
      {
        "xxx": 10
      },
      20
    ]

##### Filter
> **Operator**: json: encode

> **Path**: 

> **Filter**:

    {
    }

##### Output
    [
      {"xxx":10},
      20
    ]


#### Example 2
##### Input
    [
      {
        "xxx": 10
      },
      20
    ]

##### Filter
> **Operator**: json: encode

> **Path**: 

> **Filter**:

    {
      "indent": 4
    }

##### Output
    [
      {
          "xxx": 10
      },
      20
    ]


</details>


----
### Operator: `json: decode`
<details><summary>
Returns a set of JSON decoded-values from the each element.
</summary><p/>

> **Filter Format**: `dict[str,Any]`

| *Parameter* | *Data Type* | *Description* |
| - | - | - |
(parameter is currently not required)

#### Example 1
##### Input
    [
      {"xxx":10},
      {"yyy":20}
    ]

##### Filter
> **Operator**: json: decode

> **Path**: 

> **Filter**:

    {
    }

##### Output
    [
      {
        "xxx": 10
      },
      {
        "yyy": 20
      }
    ]


</details>


----
### Operator: `base64: encode`
<details><summary>
Encodes each element and returns a set of BASE64-encoded string.
</summary><p/>

> **Filter Format**: `dict[str,Any]`

| *Parameter* | *Data Type* | *Description* |
| - | - | - |
(parameter is currently not required)

#### Example 1
##### Input
    [
      "xxx",
      "yyy"
    ]

##### Filter
> **Operator**: base64: encode

> **Path**: 

> **Filter**:

    {
    }

##### Output
    [
      "eHh4",
      "eXl5"
    ]


</details>


----
### Operator: `base64: decode`
<details><summary>
Returns a set of BASE64 decoded-values from the each element.
</summary><p/>

> **Filter Format**: `dict[str,Any]`

| *Parameter* | *Data Type* | *Description* |
| - | - | - |
(parameter is currently not required)

#### Example 1
##### Input
    [
      "eHh4",
      "eXl5"
    ]

##### Filter
> **Operator**: base64: decode

> **Path**: 

> **Filter**:

    {
    }

##### Output
    [
      "xxx",
      "yyy"
    ]


</details>


----
### Operator: `digest`
<details><summary>
Create a set of secure hash value for each element.
</summary><p/>

> **Filter Format**: `dict[str,Any]`

| *Parameter* | *Data Type* | *Description* |
| - | - | - |
| algorithm | string | Secure hash algorithm (Default: sha256). See python hashlib for algorithm names. |

#### Example 1
##### Input
    [
      "xxx",
      "yyy"
    ]

##### Filter
> **Operator**: digest

> **Path**: 

> **Filter**:

    {
    }

##### Output
    [
      "cd2eb0837c9b4c962c22d2ff8b5441b7b45805887f051d39bf133b583baf6860",
      "f2afd1cacb5441a5e65a7a460a5f9898b7b98b08aa6323a2e53c8b9a9686cd86"
    ]


#### Example 2
##### Input
    [
      "xxx",
      "yyy"
    ]

##### Filter
> **Operator**: digest

> **Path**: 

> **Filter**:

    {
      "algorithm": "sha256"
    }

##### Output
    [
      "cd2eb0837c9b4c962c22d2ff8b5441b7b45805887f051d39bf133b583baf6860",
      "f2afd1cacb5441a5e65a7a460a5f9898b7b98b08aa6323a2e53c8b9a9686cd86"
    ]


</details>


----
### Operator: `is replaced with`
<details><summary>
Replaces an entire value with a value given in a filter.
</summary><p/>

> **Filter Format**: `<JSON value>`

#### Example 1
##### Input
    [
      "apple",
      "banana"
    ]

##### Filter
> **Operator**: is replaced with

> **Path**: 

> **Filter**:

    [
      {
        "fruit" : "${local}"
      }
    ]

##### Output
    [
      {
        "fruit" : [
          "apple",
          "banana"
        ]
      }
    ]


#### Example 2
##### Input
    {
      "fruit": "apple"
    }

##### Filter
> **Operator**: is replaced with

> **Path**: 

> **Filter**:

    {
      "fruit": "banana",
      "vegitable": "tomato"
    }

##### Output
    {
      "fruit": "banana",
      "vegitable": "tomato"
    }


</details>


----
### Operator: `is updated with`
<details><summary>
If both of the data types are `dicrionary`, all the elements given in a filter are added to the value.
All the values are replaced with the value given the existing key.
Otherwise, it is simply replaced with a value given in a filter.
</summary><p/>

> **Filter Format**: `<JSON value>`

#### Example 1
##### Input
    [
      "apple",
      "banana"
    ]

##### Filter
> **Operator**: is updated with

> **Path**: 

> **Filter**:

    [
      {
        "fruit" : "${local}"
      }
    ]

##### Output
    [
      {
        "fruit" : [
          "apple",
          "banana"
        ]
      }
    ]


#### Example 2
##### Input
    {
      "fruit": "apple"
    }

##### Filter
> **Operator**: is updated with

> **Path**: 

> **Filter**:

    {
      "vegitable": "tomato"
    }

##### Output
    {
      "fruit": "banana",
      "vegitable": "tomato"
    }


</details>


----
### Operator: `appends`
<details><summary>
Appends all the elements given in a filter to the value.
</summary><p/>

> **Filter Format**: `<JSON value>`

#### Example 1
##### Input
    [
      "apple",
      "banana"
    ]

##### Filter
> **Operator**: appends

> **Path**: 

> **Filter**:

    [
      "cherry",
      "lemon"
    ]

##### Output
    [
      "apple",
      "banana",
      "cherry",
      "lemon"
    ]


#### Example 2
##### Input
    {
      "File": [
        "a.exe",
        "b.pdf"
      ]
    }

##### Filter
> **Operator**: appends

> **Path**: 

> **Filter**:

    {
      "IP": [
        "1.1.1.1",
        "2.2.2.2"
      ]
    }

##### Output
    [
      {
        "File": [
          "a.exe",
          "b.pdf"
        ]
      },
      {
        "IP": [
          "1.1.1.1",
          "2.2.2.2"
        ]
      }
    ]

</details>


----
### Operator: `if-then-else`
<details><summary>
Evaluates each element with `if` condition, and returns a set of the results of `then` or `else` operations.
If `if` condition is not given or returns any value, `then` operation is executed, otherwise `else` operation is executed.
</summary><p/>

> **Filter Format**: `dict[str,Any]`

| *Parameter* | *Data Type* | *Description* |
| - | - | - |
| if | expressions | (Optional) `if` condition |
| then | expressions | Conditions to execute if `if` condition is not given or returns any value. |
| else | expressions | (Optional) Conditions to execute if `if` returns `null`. |


#### Example 1
##### Input
    [
      {
        "Name": "a.dat",
        "Size": 100
      },
      {
        "Name": "b.exe",
        "Size": 200
      },
      {
        "Name": "c.txt",
        "Size": 300
      }
    ]

##### Filter
> **Operator**: if-then-else

> **Path**: 

> **Filter**:

    {
      "if": {
        "is filtered with": {
          "Name": {
            "ends with": ".exe"
          }
        }
      },
      "then": {
        "is updated with": {
          "Executable": true
        }
      },
      "else": {
        "is updated with": {
          "Executable": false
        }
      }
    }

##### Output
    [
      {
        "Name": "a.dat",
        "Size": 100,
        "Executable": false
      },
      {
        "Name": "b.exe",
        "Size": 200,
        "Executable": true
      },
      {
        "Name": "c.txt",
        "Size": 300,
        "Executable": false
      }
    ]


#### Example 2
##### Input
    [
      "a.dat",
      "b.exe",
      "c.txt"
    ]

##### Filter
> **Operator**: if-then-else

> **Path**: 

> **Filter**:

    {
      "if": {
        "ends with": ".exe"
      },
      "then": {
        "is replaced with": 10
      }
    }

##### Output
    [
      "a.dat",
      10,
      "c.txt"
    ]


#### Example 3
##### Input
    [
      "a.dat",
      "b.exe",
      "c.txt"
    ]

##### Filter
> **Operator**: if-then-else

> **Path**: 

> **Filter**:

    {
      "then": {
        "is replaced with": 10
      }
    }

##### Output
    [
      10,
      10,
      10
    ]

</details>


----
### Operator: `switch-case`
<details><summary>
Performs expressions for the label whose `expressions` matches the value.
If any of `expressions` doesn't match the value, `default` operation is executed.
</summary><p/>

> **Filter Format**: `dict[str,Any]`

| *Parameter* | *Data Type* | *Description* |
| - | - | - |
| switch | dict[&lt;label&gt;, expressions] | (Optional) Patterns of conditions. |
| default | expressions | (Optional) Conditions to execute if it doesn't match all the `switch` conditions. |
| &lt;label&gt;| expressions | (Optional) Conditions to execute if it matches the conditions given in the label. |


#### Example 1
##### Input
    [
      {
        "IP": "1.1.1.1",
        "Score": 80
      },
      {
        "IP": "2.2.2.2",
        "Score": 50
      },
      {
        "IP": "3.3.3.3",
        "Score": 20
      }
    ]

##### Filter
> **Operator**: switch-case

> **Path**: 

> **Filter**:

    {
      "switch": {
        "#low": {
          "is filtered with": {
            "Score": {
              "<=": 30
            }
          }
        },
        "#high": {
          "is filtered with": {
            "Score": {
              ">=": 70
            }
          }
        }
      },
      "#low": {
        "is updated with": {
          "Risk": "low"
        }
      },
      "#high": {
        "is updated with": {
          "Risk": "high"
        }
      },
      "default": {
        "is updated with": {
          "Risk": "middle"
        }
      }
    }

##### Output
    [
      {
        "IP": "1.1.1.1",
        "Score": 80,
        "Risk": "high"
      },
      {
        "IP": "2.2.2.2",
        "Score": 50,
        "Risk": "middle"
      },
      {
        "IP": "3.3.3.3",
        "Score": 20,
        "Risk": "low"
      }
    ]


#### Example 2
##### Input
    [
      {
        "IP": "1.1.1.1",
        "Score": 80
      },
      {
        "IP": "2.2.2.2",
        "Score": 50
      },
      {
        "IP": "3.3.3.3",
        "Score": 20
      }
    ]

##### Filter
> **Operator**: switch-case

> **Path**: 

> **Filter**:

    {
      "switch": {
        "#low": {
          "is filtered with": {
            "Score": {
              "<=": 30
            }
          }
        },
        "#high": {
          "is filtered with": {
            "Score": {
              ">=": 70
            }
          }
        }
      },
      "#low": {
        "is updated with": {
          "Risk": "low"
        }
      },
      "#high": {
        "is updated with": {
          "Risk": "high"
        }
      }
    }

##### Output
    [
      {
        "IP": "1.1.1.1",
        "Score": 80,
        "Risk": "high"
      },
      {
        "IP": "2.2.2.2",
        "Score": 50
      },
      {
        "IP": "3.3.3.3",
        "Score": 20,
        "Risk": "low"
      }
    ]


</details>


----
### Operator: `collects values`
<details><summary>
Returns a set of &lt;value&gt; of each element. A value is &lt;value&gt; for `dict`, otherwise element itself.
</summary><p/>

> **Filter Format**: `dict[str,Any]`

| *Parameter* | *Data Type* | *Description* |
| - | - | - |
(parameter is currently not required)

#### Example 1
##### Input
    {
      "JDOE": {
        "IP": [
          "1.1.1.1",
          "1.1.1.2"
        ],
        "Score": 30
      },
      "TYAMADA": {
        "IP": "2.2.2.2",
        "Score": 10
      },
      "MBLACK": {
        "IP": "3.3.3.3",
        "Score": 40
      }
    }

##### Filter
> **Operator**: collects values

> **Path**: 

> **Filter**: {}

##### Output
    [
      {
        "IP": [
          "1.1.1.1",
          "1.1.1.2"
        ],
        "Score": 30
      },
      {
        "IP": "2.2.2.2",
        "Score": 10
      },
      {
        "IP": "3.3.3.3",
        "Score": 40
      }
    ]


#### Example 2
##### Input
    [
      "1.1.1.1",
      "2.2.2.2",
      "3.3.3.3"
    ]

##### Filter
> **Operator**: collects values

> **Path**: 

> **Filter**: {}

##### Output
    [
      "1.1.1.1",
      "2.2.2.2",
      "3.3.3.3"
    ]


</details>


----
### Operator: `collects keys`
<details><summary>
Returns a set of &lt;key&gt; of each `dict` element.
</summary><p/>

> **Filter Format**: `dict[str,Any]`

| *Parameter* | *Data Type* | *Description* |
| - | - | - |
(parameter is currently not required)

#### Example 1
##### Input
    {
      "JDOE": {
        "IP": [
          "1.1.1.1",
          "1.1.1.2"
        ],
        "Score": 30
      },
      "TYAMADA": {
        "IP": "2.2.2.2",
        "Score": 10
      },
      "MBLACK": {
        "IP": "3.3.3.3",
        "Score": 40
      }
    }

##### Filter
> **Operator**: collects keys

> **Path**: 

> **Filter**: {}

##### Output
    [
      "JDOE",
      "TYAMADA",
      "MBLACK"
    ]


</details>


----
### Operator: `flattens with values`
<details><summary>
Returns a set of &lt;value&gt; of all the elements in the tree.
</summary><p/>

> **Filter Format**: `dict[str,Any]`

| *Parameter* | *Data Type* | *Description* |
| - | - | - |
(parameter is currently not required)

#### Example 1
##### Input
    {
      "JDOE": {
        "IP": [
          "1.1.1.1",
          "1.1.1.2"
        ],
        "Score": 30
      },
      "TYAMADA": {
        "IP": "2.2.2.2",
        "Score": 10
      },
      "MBLACK": {
        "IP": "3.3.3.3",
        "Score": 40
      }
    }

##### Filter
> **Operator**: flattens with values

> **Path**: 

> **Filter**: {}

##### Output
    [
      "1.1.1.1",
      "1.1.1.2",
      30,
      "2.2.2.2",
      10,
      "3.3.3.3",
      40
    ]


</details>


----
### Operator: `flattens with keys`
<details><summary>
Returns a set of &lt;key&gt; of all the `dict` elements in the tree.
</summary><p/>

> **Filter Format**: `dict[str,Any]`

| *Parameter* | *Data Type* | *Description* |
| - | - | - |
(parameter is currently not required)

#### Example 1
##### Input
    {
      "JDOE": {
        "IP": [
          "1.1.1.1",
          "1.1.1.2"
        ],
        "Score": 30
      },
      "TYAMADA": {
        "IP": "2.2.2.2",
        "Score": 10
      },
      "MBLACK": {
        "IP": "3.3.3.3",
        "Score": 40
      }
    }

##### Filter
> **Operator**: flattens with keys

> **Path**: 

> **Filter**: {}

##### Output
    [
      "JDOE",
      "IP",
      "Score",
      "TYAMADA",
      "IP",
      "Score",
      "MBLACK",
      "IP",
      "Score"
    ]


</details>


----
### Operator: `abort`
<details><summary>
Raises an exception and exit with the value filtered at the operator. This operator is available for troubleshooting and debugging.
</summary><p/>

> **Filter Format**: `dict[str,Any]`

| *Parameter* | *Data Type* | *Description* |
| - | - | - |
(parameter is currently not required)

#### Example 1

##### Filter
> **Operator**: abort

> **Path**: 

> **Filter**:

    {
    }

</details>
