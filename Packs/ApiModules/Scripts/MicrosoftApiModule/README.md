To use the common Microsoft API logic (authentication and API requests), the `MicrosoftApiModule` 
should be imported in the following manner:

```python
def main():
    ...


from MicrosoftApiModule import *  # noqa: E402

if __name__ in ["builtins", "__main__"]:
    main()
```

Then, the `MicrosoftClient` will be available for usage. For examples, see the `Microsoft Graph Listener` or `Microsoft Graph Mail` integrations.