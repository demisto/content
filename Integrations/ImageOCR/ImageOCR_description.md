## Image OCR
Use the Image OCR integration to extract text from images. The integration utilizes the open-source [**tesseract**](https://github.com/tesseract-ocr/tesseract/) OCR engine.

The default language used for OCR is English. To configure additional languages, in the **Languages** parameter specify a CSV list of language codes. For example, to set the integration for English and French, set this value: *eng,fra*. To see all supported language codes,run the following command:
```
!image-ocr-list-languages
```
 
