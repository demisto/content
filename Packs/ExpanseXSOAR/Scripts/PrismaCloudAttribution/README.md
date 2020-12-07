Prisma Cloud Attribution

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | |
| Demisto Version | 6.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| assets | List of Prisma Cloud assets to return |
| fields | Fields to be returned \(comma separated\) |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| PrismaCloud.Attribution.accountId | Cloud Account ID | Unknown |
| PrismaCloud.Attribution.accountName | Cloud Account Name | Unknown |
| PrismaCloud.Attribution.cloudType | Cloud Type | Unknown |
| PrismaCloud.Attribution.fqdn | FQDNs associated to the resource | Unknown |
| PrismaCloud.Attribution.rrn | Resource RRN | Unknown |
| PrismaCloud.Attribution.ip | IPs associated to the resource | Unknown |
| PrismaCloud.Attribution.regionId | Cloud Region ID | Unknown |
| PrismaCloud.Attribution.hasAlert | Resource has Prisma Cloud Alert | Unknown |
| PrismaCloud.Attribution.resourceName | Resource Name | Unknown |
| PrismaCloud.Attribution.resourceType | Resource Type | Unknown |
| PrismaCloud.Attribution.service | Cloud Service | Unknown |


## Script Example
```!PrismaCloudAttribution assets="${Redlock.Asset}"```

## Context Example
```json
{
    "PrismaCloud": {
        "Attribution": [
            {
                "accountId": "123456",
                "accountName": "aws-user-personal",
                "cloudType": "aws",
                "fqdn": [
                    "application-lb-123456.us-east-1.elb.amazonaws.com"
                ],
                "hasAlert": false,
                "id": "arn:aws:elasticloadbalancing:us-east-1:123456:loadbalancer/app/application-lb/1398164320221c02",
                "ip": null,
                "regionId": "us-east-1",
                "resourceName": "application-lb",
                "resourceType": "Managed Load Balancer",
                "rrn": "rrn::managedLb:us-east-1:123456:b38d940663c047b02c2116be49695cf353976dff:arn%3Aaws%3Aelasticloadbalancing%3Aus-east-1%3A123456%3Aloadbalancer%2Fapp%2Fapplication-lb%2F1398164320221c02",
                "service": "Amazon Elastic Load Balancing"
            },
            {
                "accountId": "123456",
                "accountName": "aws-user-personal",
                "cloudType": "aws",
                "fqdn": [
                    "ec2-35-180-1-1.eu-west-3.compute.amazonaws.com"
                ],
                "hasAlert": false,
                "id": "i-654321b",
                "ip": [
                    "35.180.1.1"
                ],
                "regionId": "eu-west-3",
                "resourceName": "testvm",
                "resourceType": "Instance",
                "rrn": "rrn::instance:eu-west-3:123456:9db2db5fdba47606863c8da86d3ae594fb5aee2b:i-654321b",
                "service": "Amazon EC2"
            }
        ]
    }
}
```

## Human Readable Output

>### Results
>|accountId|accountName|cloudType|fqdn|hasAlert|id|ip|regionId|resourceName|resourceType|rrn|service|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 12345 | aws-user-personal | aws | application-lb-624166765.us-east-1.elb.amazonaws.com | false | arn:aws:elasticloadbalancing:us-east-1:12345:loadbalancer/app/application-lb/1398164320221c02 |  | us-east-1 | application-lb | Managed Load Balancer | rrn::managedLb:us-east-1:12345:b38d940663c047b02c2116be49695cf353976dff:arn%3Aaws%3Aelasticloadbalancing%3Aus-east-1%3A12345%3Aloadbalancer%2Fapp%2Fapplication-lb%2F1398164320221c02 | Amazon Elastic Load Balancing |
>| 12345 | aws-user-personal | aws | ec2-35-180-1-1.eu-west-3.compute.amazonaws.com | false | i-654321 | 35.180.1.1 | eu-west-3 | testvm | Instance | rrn::instance:eu-west-3:12345:9db2db5fdba47606863c8da86d3ae594fb5aee2b:i-654321 | Amazon EC2 |

