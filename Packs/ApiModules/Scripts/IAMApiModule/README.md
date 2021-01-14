To use the common IAM API logic, run the following command to import the `IAMApiModule`.

```python
def main():
    ...


from IAMApiModule import *  # noqa: E402

if __name__ in ["builtins", "__main__"]:
    main()
```

Then, the `IAMApiModule` will be available for usage. For examples, see the `Workday` or `Okta` integrations.

The IAMApiModule contains the following classes:
1. IAMErrors - to manually handle errors in IAM integrations.
2. IAMActions - contains all the IAM actions (e.g. get, update, create, etc.)
3. IAMVendorActionResult - used in IAMUserProfile class to represent actions data.
4. IAMUserProfile - a User Profile object class for IAM integrations.
5. IAMUserAppData - holds user attributes retrieved from an application.
6. IAMCommand - implements the IAM CRUD commands.
