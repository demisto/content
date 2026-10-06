To use the common Google Drive integration logic, run the following command to import the `GoogleDriveApiModule`.

```python
def main():
    run_google_drive_integration()


from GoogleDriveApiModule import *  # noqa: E402

if __name__ in ["builtins", "__main__"]:
    main()
```

Then, the `run_google_drive_integration` entry point and the `GSuiteClient` (re-exported from GSuiteApiModule) will be available for usage. For the canonical consumer, see the `Google Drive` integration.
