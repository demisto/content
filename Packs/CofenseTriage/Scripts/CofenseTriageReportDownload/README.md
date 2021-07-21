Download all reports associated with the email address.

## Script Data

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | enhancement |
| Version | 6.0.0 |

## Dependencies
This script uses the following commands and scripts.
* cofense-report-list
* cofense-report-download

## Inputs

| **Argument Name** | **Description** |
| --- | --- |
| email | From address for which to download the report. |

## Outputs
There are no outputs for this script.


## Script Example
```!CofenseTriageReportDownloadScript email=dummy@xyz.com```

## Context Example
```json
{
    "File": [
        {
            "EntryID": "1234@4696afd6-8bfb-4487-89b3-a9aaaddfe5ee",
            "Extension": "eml",
            "Info": "eml",
            "MD5": "bdb1234321a1ffb216d08e8159924f7f",
            "Name": "Report ID - 88.eml",
            "SHA1": "12a3456a627619f1d84c2385f73f31a38a3433c3",
            "SHA256": "1ca12345f004115c7df1ebeda1e34a76e8f460abd1eb507aa8bf47e1345345da",
            "SHA512": "4d6f4abc1f1a9f5cda9e21fdd174d83c92ab372c5b4b98411ad17105a65a5cd568bb4abf02ce4beb708c655a5c48f4d3fda9e2a4587f6eddde0683d504b169ab",
            "SSDeep": "123:Rro28+wIah4VuBoeSdYKQ3Xf1UXtoDLwKkZkR6klyqX9z6w6G:Zo1+xGRoeSn6Lwx+RhlyueG",
            "Size": 45514,
            "Type": "ASCII text, with CRLF line terminators"
        },
        {
            "EntryID": "1234@4696afd6-8bfb-4487-89b3-a9aaaddfe5ee",
            "Extension": "eml",
            "Info": "eml",
            "MD5": "123456f995bad5f8ffbca6f3336e0f74",
            "Name": "Report ID - 253.eml",
            "SHA1": "7d12345c4ac51998dfdb465fde3188f11d62f930",
            "SHA256": "0f52e1234ccf44f118c13e000683f4b0355232f72c72a7bd306ff875667f8735",
            "SHA512": "0a4c123ab97a6852bdea86605041e48c176059e830c3642f388ae99251f3c90947c24e3f5ec9a8dde86ed17ccb60b549640b899aae4b29ef77727e97d87ca464",
            "SSDeep": "123:b254wJVFXVW2P/B/5mwwjekJYv3XDe4PYAuRAQt/M:bO/tw3GXJx96E",
            "Size": 15771,
            "Type": "ASCII text, with CRLF line terminators"
        }
    ]
}
```
