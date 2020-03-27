## API Modules
This pack is intended for common API logic across integrations. It is not a part of the content bundle.

To use an API module, use `import *` in the integration script, under the `main` function. 
The import line will be replaced by the common logic code and can be used in the integration in the linting process.
This prevents working with the `Export to Demisto` capability in the PyCharm plugin.
