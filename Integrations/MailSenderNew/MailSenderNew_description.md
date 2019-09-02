## SMTP Sender
  Send emails including support for rich emails with HTML and embedded files.
  - Most fields are optional and we allow empty subject and empty body
  - If both body and htmlBody are provided, we will create an alternative envelope
  - Preconfigured template attachments can be supported by using [data URLs](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/Data_URIs)
  - Support for template replacement variables using {var} syntax

  Implemented in Python to support extensions.
