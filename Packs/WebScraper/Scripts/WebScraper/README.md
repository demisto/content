An Automation Script to Web Scrap a URL or HTML Page

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |
| Cortex XSOAR Version | 6.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| page_url | Page url to scrap |
| page_html | HTML page to scrap |
| headers | Request headers |
| params | Request parameters |
| navigator_tree | HTML tags navigation tree, example: "body.table" |
| insecure | Ignore certificate validation errors |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| WebScraper.Tree | Scraped Pages | String |


## Script Example
```!WebScraper page_url=https://example.com navigator_tree=body```

## Context Example
```json
{
    "WebScraper": {
        "Tree": [
            {
                "h1": "Example Domain"
            },
            {
                "p": [
                    "This domain is for use in illustrative examples in documents. You may use this\n    domain in literature without prior coordination or asking for permission.",
                    {
                        "a": {
                            "#text": "More information...",
                            "@href": "https://www.iana.org/domains/example"
                        }
                    }
                ]
            }
        ]
    }
}
```

## Human Readable Output

>Scrapping completed!
