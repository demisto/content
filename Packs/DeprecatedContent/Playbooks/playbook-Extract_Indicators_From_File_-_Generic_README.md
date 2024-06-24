Deprecated. Use the "Extract Indicators From File - Generic v2" playbook instead.
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
* ExtractIndicatorsFromTextFile
* ExtractIndicatorsFromWordFile
* ReadPDFFile
* Set

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| File | The file to extract indicators from. | File | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Domain.Name | Extracted domains | unknown |
| Account.Email.Address | Extracted emails | unknown |
| File.MD5 | Extracted MD5 | unknown |
| File.SHA1 | Extracted SHA1 | unknown |
| File.SHA256 | Extracted SHA256 | unknown |
| IP.Address | Extracted IPs | unknown |
| File.Text | The PDF File extracted text | unknown |
| File.Producer | The PDF File producer | unknown |
| File.Title | The PDF File Title | unknown |
| File.xap | The PDF File xap | unknown |
| File.Author | The PDF File Author | unknown |
| File.dc | The PDF File dc | unknown |
| File.xapmm | The PDF File xapmm | unknown |
| File.ModDate | The PDF File ModDate | unknown |
| File.CreationDate | The PDF File CreationDate | unknown |
| File.Pages | Number of pages in PDF file | unknown |
| URL.Data | List of URLs that were extracted from the PDF file | unknown |

## Playbook Image
---
![Extract_Indicators_From_File_Generic](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/Extract_Indicators_From_File_Generic.png)