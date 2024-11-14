To use the common Microsoft Graph Mail API logic (authentication and API requests), run the following command to import the `MicrosoftGraphMailApiModule`.

```python
def main():
    ...


from MicrosoftGraphMailApiModule import *

if __name__ in ["builtins", "__main__"]:
    main()
```

Then, the `MsGraphMailBaseClient` will be available for usage. For examples, see the `Microsoft Graph Listener` or `Microsoft Graph Mail` integrations.
