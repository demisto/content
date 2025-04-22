This transformer will sort an array of dictionary values by keys in ascending or descending order.
When values have different types of data, the hierarchy is: null < bool < int/float < str < other (null is top in ascending order).

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
| value | The array to sort. |
| keys | Comma-separated list of ordering-keys specifying a sorting hierarchy |
| descending_keys | Comma-separated list of keys to sort in descending order. '\*' is the special symbol to sort the array given without \`keys\` in descending order. |

## Outputs

---
There are no outputs for this script.

---
## Examples-1

Here is a table for the sorting samples in the Examples-1.

| Name | Country | Score |
| --- | --- | --- |
| Alex | US | 30 |
| Kate | US | 50 |
| Chris | US | 20 |
| Janet | Australia | 50 |
| Steve | Australia | 40 |
| Dora | Australia |  |

The JSON data is below to be given to the `value` argument parameter of the transformer for the samples.

    [
      {
        "Name": "Alex",
        "Country": "US",
        "Score": 30
      },
      {
        "Name": "Kate",
        "Country": "US",
        "Score": 50
      },
      {
        "Name": "Chris",
        "Country": "US",
        "Score": 20
      },
      {
        "Name": "Janet",
        "Country": "Australia",
        "Score": 50
      },
      {
        "Name": "Dora",
        "Country": "Australia"
      }
    ]

---
Sort by `Country` in ascending order.

> keys: Country

> descending_keys:


#### Output:

It will give you the result like this. But the order except for the `Country` is not guaranteed.

| Name | Country | Score |
| --- | --- | --- |
| Janet | Australia | 50 |
| Dora | Australia |  |
| Alex | US | 30 |
| Kate | US | 50 |
| Chris | US | 20 |

    [
      {
        "Name": "Janet",
        "Country": "Australia",
        "Score": 50
      },
      {
        "Name": "Dora",
        "Country": "Australia"
      },
      {
        "Name": "Alex",
        "Country": "US",
        "Score": 30
      },
      {
        "Name": "Kate",
        "Country": "US",
        "Score": 50
      },
      {
        "Name": "Chris",
        "Country": "US",
        "Score": 20
      }
    ]

---
Sort by `Country` in ascending order, and sort by `Score` in ascending order with keeping the order by `Country`.

> keys: Country, Score

> descending_keys:


#### Output:

It will give you the result like this. But the order except for the `Country` and `Score` is not guaranteed.

| Name | Country | Score |
| --- | --- | --- |
| Dora | Australia |  |
| Janet | Australia | 50 |
| Chris | US | 20 |
| Alex | US | 30 |
| Kate | US | 50 |

    [
      {
        "Name": "Dora",
        "Country": "Australia"
      },
      {
        "Name": "Janet",
        "Country": "Australia",
        "Score": 50
      },
      {
        "Name": "Chris",
        "Country": "US",
        "Score": 20
      },
      {
        "Name": "Alex",
        "Country": "US",
        "Score": 30
      },
      {
        "Name": "Kate",
        "Country": "US",
        "Score": 50
      }
    ]


---
Sort by `Country` in ascending order, and sort by `Score` in descending order with keeping the order by `Country`.

> keys: Country, Score

> descending_keys: Score


#### Output:

It will give you the result like this. But the order except for the `Country` and `Score` is not guaranteed.

| Name | Country | Score |
| --- | --- | --- |
| Janet | Australia | 50 |
| Dora | Australia |  |
| Kate | US | 50 |
| Alex | US | 30 |
| Chris | US | 20 |

    [
      {
        "Name": "Janet",
        "Country": "Australia",
        "Score": 50
      },
      {
        "Name": "Dora",
        "Country": "Australia"
      },
      {
        "Name": "Kate",
        "Country": "US",
        "Score": 50
      },
      {
        "Name": "Alex",
        "Country": "US",
        "Score": 30
      }
      {
        "Name": "Chris",
        "Country": "US",
        "Score": 20
      }
    ]

---
## Examples-2

Here is an array for the sorting samples in the Examples-2.
It will be given to the `value` argument parameter of the transformer for the samples.

    [
      {
        "key": "value1"
      },
      2,
      0.5,
      0,
      1,
      null,
      "aaa",
      "ZZZ"
    ]

---
Sort in ascending order.

> keys:

> descending_keys:


#### Output:

    [
      null,
      0,
      0.5,
      1,
      2,
      "ZZZ",
      "aaa",
      {
        "key": "value1"
      }
    ]


---
Sort in descending order.

> keys:

> descending_keys: *


#### Output:

    [
      {
        "key": "value1"
      },
      "aaa",
      "ZZZ",
      2,
      1,
      0.5,
      0,
      null
    ]
