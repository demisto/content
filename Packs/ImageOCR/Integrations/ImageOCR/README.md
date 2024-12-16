Use the Image OCR integration to extract text from images. The integration utilizes the open-source [tesseract](https://github.com/tesseract-ocr/tesseract/) OCR engine.

## Use Cases
* Extract text from images included in emails during a phishing investigation.
* Extract text from images included in an html page.

## Configure Image OCR in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| A CSV of language codes of the language to use for OCR (leave empty to use defaults). | The default language used for OCR is English. Use this parameter to specify a list of additional languages. For example, `eng,fra`. To see all supported language codes, use the ***image-ocr-list-languages*** command. | False |
| Skip on corrupted images | If true, will not raise an error if the image is corrupted and could not be processed. | False |



## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### image-ocr-list-languages

***
Lists supported languages for which the integration can extract text.

#### Base Command

`image-ocr-list-languages`

#### Input

There are no input arguments for this command.

#### Command Example

`!image-ocr-list-languages`

#### Human Readable Output

> ## Image OCR Supported Languages
> * ara
> * chi_sim
> * chi_sim_vert
> * chi_tra
> * chi_tra_vert
> * deu
> * eng
> * fra
> * heb
> * ita
> * jpn
> * jpn_vert
> * pol
> * por
> * rus
> * spa
> * swe
> * tur

### image-ocr-extract-text

***
Extracts text from an image.

#### Base Command

`image-ocr-extract-text`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| entryid | A comma-separated list of Entry IDs of image files to process. | Required | 
| langs | A CSV of language codes of the language to use for OCR. Overrides the default configured language list. | Optional | 
| verbose | Turn on verbose flag to display tesseract and other used libraries versions. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| File.Text | String | Extracted text from the passed image file. | 

#### Command Example

`!image-ocr-extract-text entryid="922@e84104f7-b235-4d82-860a-ea09f5dc0559"`

#### Context Example

```json
{
    "File": {
        "Text": "The quick brown fox\njumped over the 5\nlazy dogs!\n\f", 
        "EntryID": "922@e84104f7-b235-4d82-860a-ea09f5dc0559"
    }
}
```

#### Human Readable Output

> ## Image OCR Extracted Text for Entry ID 1613@1e6b4a55-33e7-433b-8f6f-2c0751c8c444
> The quick brown fox
> jumped over the 5
> lazy dogs!