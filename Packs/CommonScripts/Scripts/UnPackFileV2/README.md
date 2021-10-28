UnPack a RAR archive using file entry ID.  Files unpacked will be pushed to the war room and names will be pushed to the context.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |
| Cortex XSOAR Version | 6.0.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| entry_id | File entry ID. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ExtractedFiles | List of file names which extracted from the archive. | Unknown |


## Script Example
```!UnPackFileV2 entry_id=YqFw8xwnx3qFEFd8YbNZK4@144e08e3-739f-4aa6-8691-f720f144eec5```

## Context Example
```json
{
    "ExtractedFiles": [
        "file2.txt",
        "long fn.txt",
        "file.txt",
        "file1.txt"
    ],
    "File": [
        {
            "EntryID": "GRLHwRe2xSFavMVzdXRdVg@144e08e3-739f-4aa6-8691-f720f144eec5",
            "Extension": "txt",
            "Info": "text/plain; charset=utf-8",
            "MD5": "3d709e89c8ce201e3c928eb917989aef",
            "Name": "file2.txt",
            "SHA1": "639daad06642a8eb86821ff7649e86f5f59c6139",
            "SHA256": "67ee5478eaadb034ba59944eb977797b49ca6aa8d3574587f36ebcbeeb65f70e",
            "SHA512": "24407506629c73302e01cf15c79cf02856a755abbdd2e9f8002a47515933460993afbaa4e806abb4d79ae332f331796c504f2a2ba39847a95f24a3a55159ff9e",
            "SSDeep": "3:x/n:x/",
            "Size": 6,
            "Type": "ASCII text"
        },
        {
            "EntryID": "y8cS5xwHw7qRQvLQDc6epm@144e08e3-739f-4aa6-8691-f720f144eec5",
            "Extension": "txt",
            "Info": "text/plain; charset=utf-8",
            "MD5": "9d3bfd4f20eb3602e4e89bf611ba0ffe",
            "Name": "long fn.txt",
            "SHA1": "8d5f3e8b8676a1a6d8b6eb6d2dc7a79e808ee247",
            "SHA256": "e708f3c52269d19a8ac86b5934ff9cf2a80c696cb04a66a435e96f9ca44f7c18",
            "SHA512": "b424e5f4f68bf5af8f8a05eeaed50e5723e0fff49ae07632db8c5e13e9a8994a1cf07c1b1a3e6369786229cbc05b68dae1f235f9bbe7e575e6b3859957d1b84f",
            "SSDeep": "3:Pb:D",
            "Size": 8,
            "Type": "ASCII text"
        },
        {
            "EntryID": "xCePedgM6TJdL73vArTkZ3@144e08e3-739f-4aa6-8691-f720f144eec5",
            "Extension": "txt",
            "Info": "text/plain; charset=utf-8",
            "MD5": "bbe02f946d5455d74616fc9777557c22",
            "Name": "file.txt",
            "SHA1": "046c168df2244d3a13985f042a50e479fe56455e",
            "SHA256": "8b911a8716b94442f9ca3dff20584048536e4c2f47b8b5bb9096cbd43c3432d5",
            "SHA512": "db88b784d27f0b92b63f0b3b159ea6f049b178546d99ae95f6f7b57c678c61c2d4b50af4374e81a09e812c2c957a5353803cef4c34aa36fe937ae643cc86bb4b",
            "SSDeep": "3:xv:xv",
            "Size": 5,
            "Type": "ASCII text"
        },
        {
            "EntryID": "2HqwpQVdRtEtNorvtLzY6f@144e08e3-739f-4aa6-8691-f720f144eec5",
            "Extension": "txt",
            "Info": "text/plain; charset=utf-8",
            "MD5": "5149d403009a139c7e085405ef762e1a",
            "Name": "file1.txt",
            "SHA1": "38be7d1b981f2fb6a4a0a052453f887373dc1fe8",
            "SHA256": "ecdc5536f73bdae8816f0ea40726ef5e9b810d914493075903bb90623d97b1d8",
            "SHA512": "6cc7bddc064350c67080357976ea6b0538fadf2075d3fe2f65e7345505ac7d7cf9b05af2577f08408a4bdb4478982ca6f52326ba25b5c5ff64c7b8bead0992e0",
            "SSDeep": "3:x2n:x2n",
            "Size": 6,
            "Type": "ASCII text"
        }
    ]
}
```

## Human Readable Output

>### Extracted Files
>|Name|Path
>|---|---|
>| file2.txt | sub/dir2/file2.txt |
>| long fn.txt | sub/with space/long fn.txt |
>| file.txt | sub/üȵĩöḋè/file.txt |
>| file1.txt | sub/dir1/file1.txt |

