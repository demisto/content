To use the common GSuite API logic (authentication and API requests), run the following command to import the `GSuiteApiModule`.

```python
def main():
    ...


from GSuiteApiModule import *  # noqa: E402

if __name__ in ["builtins", "__main__"]:
    main()
```

Then, the `GSuiteClient` will be available for usage. For examples, see the `G Suite Admin` or `Google Drive` or `Google Calendar` integrations.