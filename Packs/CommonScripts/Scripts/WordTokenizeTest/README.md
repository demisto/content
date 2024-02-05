Tokenize the words in a input text.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | phishing, ml |
| Cortex XSOAR Version | 5.0.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| value | The text value. |
| type | Tokenizer type. you can read more about this here: https://www.nltk.org/api/nltk.tokenize.html |
| cleanHtml | Clean html from text value? |
| removeLineBreaks | Remove line breaks? |
| encoding | Text encoding. |
| hashWordWithSeed | If non-empty hash the words with this seed. |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| WordTokenizeOutput | Output text. | string |
