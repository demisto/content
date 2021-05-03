Deprecated. Extracts indicators from a file.
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
* ReadPDFFile
* Set
* ExtractIndicatorsFromTextFile
* ExtractIndicatorsFromWordFile

### Commands
This playbook does not use any commands.

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| File | The file to extract indicators from. | File.None | Optional |

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
![Extract Indicators From File - Generic](Insert the link to your image here)