This script creates a link back to the Prisma Cloud Compute instance.

## Script Data

---

| **Name** | **Description** |
| --- |-----------------|
| Script Type | python3         |
| Cortex XSOAR Version | 6.0.0           |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| type | The type of WAAS alert. |
| imageName | The image name to investigate alerts for. |
| baseUrl | The base url of the Prisma Cloud Compute Instance \(https://&amp;lt;prisma-ip&amp;gt;:&amp;lt;prisma-port&amp;gt;\) |

## Outputs

---
There are no outputs for this script.

## Script Examples

### Example command

```!CreatePrismaCloudComputeLink imageName=dvwa type=sqli baseUrl=`https://prismcloudcomputeurl````

### Context Example

```json
{
    "link": "https://prismcloudcomputeurl/#!/monitor/events/firewall/app/container?filters=imageName%3Ddvwa%26type%3Dsqli"
}
```

### Human Readable Output

>### Results
>|link|
>|---|
>| https://prismcloudcomputeurl/#!/monitor/events/firewall/app/container?filters=imageName%3Ddvwa%26type%3Dsqli |

