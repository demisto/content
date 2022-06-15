

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
* DeepL

### Scripts
* Set

### Commands
* deepl-submit-document
* deepl-check-document-status
* deepl-get-document

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| entry_id | EntryID of the File to be translated |  | Optional |
| source_lang | BG,CS,DA,DE,EL,EN,ES,ET,FI,FR,HU,IT,JA,LT,LV,NL,PL,PT,RO,RU,SK,SL,SV,ZH |  | Optional |
| target_lang | BG,CS,DA,DE,EL,EN-GB,EN-US,EN,ES,ET,FI,FR,HU,IT,JA,LT,LV,NL,PL,PT-PT,PT-BR,PT,RO,RU,SK,SL,SV,ZH |  | Optional |
| filename | The name of the uploaded file. Can be used as an alternative to including the file name in the file part's content disposition. |  | Optional |
| formality | Sets whether the translated text should lean towards formal or informal language. This feature currently only works for target languages "DE" \(German\), "FR" \(French\), "IT" \(Italian\), "ES" \(Spanish\), "NL" \(Dutch\), "PL" \(Polish\), "PT-PT", "PT-BR" \(Portuguese\) and "RU" \(Russian\).Possible options are: "default" \(default\) "more" - for a more formal language "less" - for a more informal language<br/><br/>values: default,more,less |  | Optional |
| glossary_id | Specify the glossary to use for the document translation. Important: This requires the source_lang parameter to be set and the language pair of the glossary has to match the language pair of the request. |  | Optional |
| translated_filename | filename \(Default is: 'TranslatedFile'\) |  | Optional |

## Playbook Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| TranslatedFile.EntryID | Translated File EntryID | unknown |
