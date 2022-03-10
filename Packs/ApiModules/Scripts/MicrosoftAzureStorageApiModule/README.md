To use the common Microsoft Azure Storage API logic , run the following command to import the `MicrosoftAzureStorageApiModule`.

```python
def main():
    ...


from MicrosoftAzureStorageApiModule import *  # noqa: E402

if __name__ in ["builtins", "__main__"]:
    main()
```

Then, the `MicrosoftStorageClient` will be available for usage. For examples, see the `Azure Storage Queue` or `Azure Storage Table` integrations.