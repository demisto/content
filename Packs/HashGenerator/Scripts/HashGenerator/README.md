Generates MD5, SHA1, and SHA256 hashes from input text. Can generate a single hash type or all three at once.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | transformer, Utilities, hash |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| text | The text or string to generate hash(es) for. |
| type | Hash algorithm to use. Use 'all' to generate MD5, SHA1, and SHA256 hashes. Default is 'all'. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| HashGenerator.MD5 | The MD5 hash of the input text. | string |
| HashGenerator.SHA1 | The SHA1 hash of the input text. | string |
| HashGenerator.SHA256 | The SHA256 hash of the input text. | string |

## Example

---

```
!HashGenerator text="Hello World"
```

### Output

| Algorithm | Hash |
| --- | --- |
| MD5 | b10a8db164e0754105b7a99be72e3fe5 |
| SHA1 | 0a4d55a8d778e5022fab701977c5d840bbc486d0 |
| SHA256 | a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e |
