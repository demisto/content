This transformer will remove elements of the array that contain an identical combination of values for the keys given.

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
| value | The array to deduplicate |
| keys | Comma-separated list of keys to identify a value |

## Outputs

---
There are no outputs for this script.


---
## Examples-1

Here is a table to be used as samples in the Examples-1.

| DestinationIP | SourceIP |
| --- | --- |
| 1.1.1.1 | 192.168.1.1 |
| 1.1.1.1 | 192.168.1.1 |
| 1.1.1.1 | 192.168.1.2 |
| 1.1.1.1 | 192.168.1.2 |
| 1.1.1.1 | 192.168.1.3 |
| 1.1.1.1 | 192.168.1.3 |
| 2.2.2.2 | 192.168.1.1 |
| 2.2.2.2 | 192.168.1.1 |
| 2.2.2.2 | 192.168.1.2 |
| 2.2.2.2 | 192.168.1.2 |
| 2.2.2.2 | 192.168.1.3 |
| 2.2.2.2 | 192.168.1.3 |


The JSON data is below to be given to the `value` argument parameter of the transformer for the samples.

```
[
  {
    "DestinationIP": "1.1.1.1",
    "SourceIP": "192.168.1.1"
  },
  {
    "DestinationIP": "1.1.1.1",
    "SourceIP": "192.168.1.1"
  },
  {
    "DestinationIP": "1.1.1.1",
    "SourceIP": "192.168.1.2"
  },
  {
    "DestinationIP": "1.1.1.1",
    "SourceIP": "192.168.1.2"
  },
  {
    "DestinationIP": "1.1.1.1",
    "SourceIP": "192.168.1.3"
  },
  {
    "DestinationIP": "1.1.1.1",
    "SourceIP": "192.168.1.3"
  },
  {
    "DestinationIP": "2.2.2.2",
    "SourceIP": "192.168.1.1"
  },
  {
    "DestinationIP": "2.2.2.2",
    "SourceIP": "192.168.1.1"
  },
  {
    "DestinationIP": "2.2.2.2",
    "SourceIP": "192.168.1.2"
  },
  {
    "DestinationIP": "2.2.2.2",
    "SourceIP": "192.168.1.2"
  },
  {
    "DestinationIP": "2.2.2.2",
    "SourceIP": "192.168.1.3"
  },
  {
    "DestinationIP": "2.2.2.2",
    "SourceIP": "192.168.1.3"
  }
]
```


---
Deduplicate by `SourceIP`.

> keys: SourceIP

#### Output:

It will give you the result below.
It's guaranteed to keep the original order, and gives you the first record when multiple records are found by collecting keys given.

| DestinationIP | SourceIP |
| --- | --- |
| 1.1.1.1 | 192.168.1.1 |
| 1.1.1.1 | 192.168.1.2 |
| 1.1.1.1 | 192.168.1.3 |

```
[
  {
    "DestinationIP": "1.1.1.1",
    "SourceIP": "192.168.1.1"
  },
  {
    "DestinationIP": "1.1.1.1",
    "SourceIP": "192.168.1.2"
  },
  {
    "DestinationIP": "1.1.1.1",
    "SourceIP": "192.168.1.3"
  }
]
```

---
Deduplicate by `SourceIP` and `DestinationIP`.

> keys: SourceIP, DestinationIP

#### Output:

It will give you the result below.
It's guaranteed to keep the original order, and gives you the first record when multiple records are found by collecting keys given.

| DestinationIP | SourceIP |
| --- | --- |
| 1.1.1.1 | 192.168.1.1 |
| 1.1.1.1 | 192.168.1.2 |
| 1.1.1.1 | 192.168.1.3 |
| 2.2.2.2 | 192.168.1.1 |
| 2.2.2.2 | 192.168.1.2 |
| 2.2.2.2 | 192.168.1.3 |

```
[
  {
    "DestinationIP": "1.1.1.1",
    "SourceIP": "192.168.1.1"
  },
  {
    "DestinationIP": "1.1.1.1",
    "SourceIP": "192.168.1.2"
  },
  {
    "DestinationIP": "1.1.1.1",
    "SourceIP": "192.168.1.3"
  },
  {
    "DestinationIP": "2.2.2.2",
    "SourceIP": "192.168.1.1"
  },
  {
    "DestinationIP": "2.2.2.2",
    "SourceIP": "192.168.1.2"
  },
  {
    "DestinationIP": "2.2.2.2",
    "SourceIP": "192.168.1.3"
  }
]
```


---
## Examples-2

Here is an array to be used as samples in the Examples-2.
It will be given to the `value` argument parameter of the transformer for the samples.

```
[
  null,
  1,
  {
    "key": "value1"
  },
  2,
  0.5,
  0,
  0.5,
  "aaa",
  1,
  {
    "key": "value1"
  },
  null,
  "aaa",
  "ZZZ"
]
```

---
Deduplicate an array without keys.

> keys:

#### Output:

It will give you the result below.
It's guaranteed to keep the original order, and gives you the first record when multiple records are found by collecting keys given.


```
[
  null,
  1,
  {
    "key": "value1"
  },
  2,
  0.5,
  0,
  "aaa",
  "ZZZ"
]
```
