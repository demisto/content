To use the common IAM API logic, run the following command to import the `IAMModule`.

```python
def main():
    ...


from IAMModule import *  # noqa: E402

if __name__ in ["builtins", "__main__"]:
    main()
```

Then, the `IAMModule` will be available for usage. For examples, see the `Workday` or `Okta` integrations.
