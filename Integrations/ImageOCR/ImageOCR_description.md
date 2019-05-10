## Image OCR
Extract text from images. Uses internally the excellent [**tesseract**](https://github.com/tesseract-ocr/tesseract/) open source OCR engine.

The default language used for OCR is English. It is possible to configure additional languages by setting the configuration parameter **Languages**. Set this parameter with a comma separated list of language codes you would like to use for OCR extraction. To see all supported language codes you can run the following command:
```
!image-ocr-list-languages
```
For example: for setting the English and French languages, set the following value: *eng,fra*. 