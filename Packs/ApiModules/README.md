## API Modules
This pack is intended for common API logic across integrations. It is not a part of the content bundle.

To use an API module, one should use `import *` in the integration script, under the `main` function. 
The import line will be replaced by the common logic code and will be usable in the integration in the linting process.
Note that this prevents working with the `Export to Demisto` capability in the PyCharm plugin.
