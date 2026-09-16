To use the common Microsoft Graph Files integration logic, run the following command to import the `MicrosoftGraphFilesApiModule`.

```python
def main():
    run_microsoft_graph_files_integration()


from MicrosoftGraphFilesApiModule import *  # noqa: E402

if __name__ in ["builtins", "__main__"]:
    main()
```

Then, the `run_microsoft_graph_files_integration` entry point and `MsGraphClient` class will be available for usage. For the canonical consumer, see the `Microsoft Graph Files` integration.
