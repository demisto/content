Extracts indicators from a file.

Supported file types:
- PDF
- TXT
- HTM, HTML
- DOC, DOCX

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
This playbook does not use any sub-playbooks.

### Integrations
This playbook does not use any integrations.

### Scripts
* Set
* ReadPDFFile
* ExtractIndicatorsFromWordFile
* ExtractIndicatorsFromTextFile

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Source** | **Required** |
| --- | --- | --- | --- | --- |
| File | The file to extract indicators from. | None | File | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Domain.Name | The extracted domains. | unknown |
| Account.Email.Address | The extracted emails. | unknown |
| File.MD5 | The extracted MD5 hash of the file. | unknown |
| File.SHA1 | The extracted SHA1 hash of the file. | unknown |
| File.SHA256 | The extracted SHA256 hash of the file. | unknown |
| IP.Address | The extracted IP address. | unknown |
| File.Text | The PDF file extracted from the text. | unknown |
| File.Producer | The producer of the PDF file. | unknown |
| File.Title | The title of the PDF file. | unknown |
| File.xap | The XAP of the PDF file. | unknown |
| File.Author | The author of the PDF file. | unknown |
| File.dc | The DC of the PDF file. | unknown |
| File.xapmm | The XAPMM of the PDF file. | unknown |
| File.ModDate | The modified date of the PDF file. | unknown |
| File.CreationDate | The creation date of the PDF file. | unknown |
| File.Pages | The number of pages in the PDF file. | unknown |
| URL.Data | The list of URLs that were extracted from the PDF file. | unknown |

## Playbook Image
---
![Extract_Indicators_From_File_Generic](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Extract_Indicators_From_File_Generic.png)
