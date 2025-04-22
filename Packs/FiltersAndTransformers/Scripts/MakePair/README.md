This transformer will create a list of dictionary by aggregating elements from two arrays.
The one is given by `value` (with `array1_key`), another is given by `array2` (with `array2_key`).

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | transformer, general |
| Cortex XSOAR Version | 6.8.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| value | The array1 |
| array1_key | The key or path to get values from the array1 \(value\) |
| array2 | The array2 |
| array2_key | The key or path to get values from the array2 |
| output_name1 | The key name in the output dictionary to which each of element of the array1 are given |
| output_name2 | The key name in the output dictionary to which each of element of the array2 are given |
| determine_output_length_by | How to deal with different size lists. \(Choose from shorter, longer, array1, or array2\) |
| merge_dict | Specify which array will be merged into when each of element is given in dictionary. \(Choose from array1, array2, array1\|2, or array2\|1\) |

## Outputs

---
There are no outputs for this script.


---
## Examples

---
Simply create a list of dictionary by aggregating elements from two arrays.


> value:

```
[
  1,
  2,
  3
]
```

> array1_key:

> array2:

```
[
  "a",
  "b",
  "c"
]
```

> array2_key:

> output_name1: xxx

> output_name2: yyy

> determine_output_length_by:

> merge_dict:

#### Output:

    [
      {
        "xxx": 1,
        "yyy": "a"
      },
      {
        "xxx": 2,
        "yyy": "b"
      },
      {
        "xxx": 3,
        "yyy": "c"
      }
    ]

---
Aggregate each of value from the keys given.

> value:

```
[
  {
    "key1": "a",
    "key2": "A"
  },
  {
    "key1": "b",
    "key2": "B"
  },
  {
    "key2": "C"
  }
]
```

> array1_key: key1

> array2:

```
[
  {
    "key3": "x",
    "key4": "X"
  },
  {
    "key3": "y",
    "key4": "Y"
  },
  {
    "key4": "Z"
  }
]
```

> array2_key: key3

> output_name1: xxx

> output_name2: yyy

> determine_output_length_by:

> merge_dict:

#### Output:

    [
      {
        "xxx": "a",
        "yyy": "x"
      },
      {
        "xxx": "b",
        "yyy": "y"
      },
      {
        "xxx": null,
        "yyy": null
      }
    ]


---
Truncate remaining elements of array2 which is longer than array1.

> value:

```
[
  {
    "key1": "a",
    "key2": "A"
  },
  {
    "key1": "b",
    "key2": "B"
  }
]
```

> array1_key: key1

> array2:

```
[
  {
    "key3": "x",
    "key4": "X"
  },
  {
    "key3": "y",
    "key4": "Y"
  },
  {
    "key3": "z",
    "key4": "Z"
  }
]
```

> array2_key: key3

> output_name1: xxx

> output_name2: yyy

> determine_output_length_by: array1

> merge_dict:

#### Output:

    [
      {
        "xxx": "a",
        "yyy": "x"
      },
      {
        "xxx": "b",
        "yyy": "y"
      }
    ]


---
array2 is longer than array1. fill in shorten elements with null.

> value:

```
[
  {
    "key1": "a",
    "key2": "A"
  },
  {
    "key1": "b",
    "key2": "B"
  }
]
```

> array1_key: key1

> array2:

```
[
  {
    "key3": "x",
    "key4": "X"
  },
  {
    "key3": "y",
    "key4": "Y"
  },
  {
    "key3": "z",
    "key4": "Z"
  }
]
```

> array2_key: key3

> output_name1: xxx

> output_name2: yyy

> determine_output_length_by: array2

> merge_dict:

#### Output:

    [
      {
        "xxx": "a",
        "yyy": "x"
      },
      {
        "xxx": "b",
        "yyy": "y"
      },
      {
        "xxx": null,
        "yyy": "z"
      },
    ]


---
Merge each of dictionary element.

> value:

```
[
  {
    "key1": "a",
    "key2": "A"
  },
  {
    "key1": "b",
    "key2": "B"
  }
]
```

> array1_key:

> array2:

```
[
  {
    "key3": "x",
    "key4": "X"
  },
  {
    "key3": "y",
    "key4": "Y"
  }
]
```

> array2_key:

> output_name1: xxx

> output_name2: yyy

> determine_output_length_by: 

> merge_dict: array1&lt;2

#### Output:

    [
      {
        "key1": "a",
        "key2": "A",
        "key3": "x",
        "key4": "X"
      },
      {
        "key1": "b",
        "key2": "B",
        "key3": "y",
        "key4": "Y"
      }
    ]


---
Merge each of element into a dictionary.

> value:

```
[
  {
    "key1": "a",
    "key2": "A"
  },
  {
    "key1": "b",
    "key2": "B"
  }
]
```

> array1_key:

> array2:

```
[
  1,
  2
]
```

> array2_key:

> output_name1: xxx

> output_name2: yyy

> determine_output_length_by: 

> merge_dict: array1

#### Output:

    [
      {
        "key1": "a",
        "key2": "A",
        "yyy": 1
      },
      {
        "key1": "b",
        "key2": "B",
        "yyy": 2
      }
    ]

