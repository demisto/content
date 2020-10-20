To use the common TAXII 2 Server logic (authentication and API requests), run the following command to import the `TAXII2ApiModule`.

```python
def main():
    ...


from TAXII2ApiModule import *  # noqa: E402

if __name__ in ["builtins", "__main__"]:
    main()
```

Then, the `TAXII2ApiModule` will be available for usage. For examples, see the `TAXII 2 Feed` integration.
