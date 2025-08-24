Hello World Script

<img src="/absolute/path/to/image.png" alt="Example Image"><br>

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | helloworld |
| Cortex XSOAR Version | 5.0.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| alertID | |
| UserName | |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| hello.world.result | | String |

## Script Example

```!HelloWorldScript alertID=123456```

## Context Example

```
{
    "hello": {
        "world": {
            "result": "Hello 123456"
        }
    }
}
```

## Human Readable Output

<div>This is content with <unclosed <br> tags and raw < > characters</div>

## Hello 123456
