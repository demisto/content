Creates a public key (.cer file), a private key (.pfx) file, and a Base64 encoded private key to use to authenticate the EWS Extension Online Powershell v2 integration.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | powershell |
| Tags | basescript |
| Cortex XSOAR Version | 5.5.0 |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| password | Password to protect the certificate. |
| days | Number of days the certificate is available. Default is "365". |
| friendly_name | A friendly name to identify the certificate. |
| country | Country of the certificate issuer. |
| state_or_province | State or province of the certificate issuer. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Certificate.PublicKey | The .cer file to add to the Azure app. | String |
| Certificate.PrivateKey | The binary certificate \(.pfx file\). | String |
| Certificate.PrivateKeyBase64 | The private key encoded in Base64 to use in the integration parameter. | String |


## Script Example
```!CreateCertificate days=365 password=<Will-Prompt-After-Enter> country=FR friendly_name=MyCertificate```

## Context Example
```json
{
    "Certificate": {
        "PrivateKey": "certificate.pfx",
        "PrivateKeyBase64": "certificateBase64.txt",
        "PublicKey": "publickey.cer"
    },
    "File": [
        {
            "EntryID": "K6Zy2whBuhc4TbrFaaiUWZ@0c2becbb-2877-4639-8800-18214f49dc70",
            "Extension": "txt",
            "Info": "text/plain; charset=utf-8",
            "MD5": "fe0e481ba31a93b57e43b08f4088a1ac",
            "Name": "certificateBase64.txt",
            "SHA1": "a185361c8f9d673ccf72ff5acc34a3dfd24e6c2a",
            "SHA256": "95b9692a564ed182b9781cda54a1f199d422b5ec50dcd3c111f7d386b43e2e59",
            "SHA512": "eebc842f1d2892630a5d6eb2379c931083e9870f4287ac2948b209d72cdaf146cc2746c00ddf3724538e480b9163fd53121d30682549bab1749ab543233db8b5",
            "SSDeep": "48:PqtPLOoLAMsR6bOXq/bmuX6lwlHcmHDqCB8+tnUTkufasf/rh/YjQXfNoQt:eKvnYiXq/6uKlwlHcmjSkufaGrhgj+t",
            "Size": 3136,
            "Type": "ASCII text, with very long lines, with no line terminators"
        },
        {
            "EntryID": "BVtgGDapVEboRutfPqhsym@0c2becbb-2877-4639-8800-18214f49dc70",
            "Extension": "cer",
            "Info": "application/pkix-cert",
            "MD5": "585f0480395a1076221d2e393ae7c37b",
            "Name": "publickey.cer",
            "SHA1": "b8608947e9a7f7bcaec45addac684500b65b5eca",
            "SHA256": "84ee1293ad9ab145cf496d099f3d17b136fd7c12456518378e1df6e2aef1401d",
            "SHA512": "841cc16a7f123918eb05e91ff18dd929fd24192361432a18226494552a6db602974ae6308a512ac65bbe48c890f6abbfc86c549e2791618cb65181db77f9d089",
            "SSDeep": "24:Ac7TN9WuxvhE/uj87VBdJTOvYwcR36USpNCFRfnZZ2dlH2t+vhmKJ:Ac7TzvhwuChJFrPSpMFRPY2tMwq",
            "Size": 1185,
            "Type": "ASCII text"
        },
        {
            "EntryID": "nxkeXYpyYK2u9yaFnDqrC9@0c2becbb-2877-4639-8800-18214f49dc70",
            "Extension": "pfx",
            "Info": "application/x-pkcs12",
            "MD5": "9644a72c118cff903e84b0cfd012af7b",
            "Name": "certificate.pfx",
            "SHA1": "9c2824df7b04a2c0248c5d318765cbf22d1253bd",
            "SHA256": "216d298a386f32965dd0cdeddb83665a406c410618697559df8ca16fe7517c1d",
            "SHA512": "7083fbb871f4bb214cc229f6b85979605ce2e953e0950671e03fdb9650aedb21664ce77a5a87a811f0fbcdde82732ec828d7677cf1bd1709b59419d99b46992c",
            "SSDeep": "48:hvP1He7U8nult99tThzHBwClBZI86sJvvNvsN53zdCL:hX1HegkY9DL3hIGJvFvsr3BW",
            "Size": 2351,
            "Type": "data"
        }
    ]
}
```

## Human Readable Output

>### Use those certificates to connect to the desired service.
>| PrivateKey | PrivateKeyBase64 | PublicKey
>| --- | --- | ---
>| "certificate.pfx" | "certificateBase64.txt" | "publickey.cer"

