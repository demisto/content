The Okta API Module handles the OAuth 2.0 authentication process when sending requests.

To use the API module, add the `from OktaApiModule import *  # noqa: E402` line of code after the `main` function definition, but before it's being called, as shown in the example below.

```python
def main():
    ...


from OktaApiModule import *  # noqa: E402

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
```
