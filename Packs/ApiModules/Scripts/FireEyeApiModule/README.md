The FireEye API handles the API Key generation from the user/pass authentication.
Manages the API Key and caches it for 10min, to avoid 401 errors for consecutive API Keys generation.
It holds the client command calls to the WSAPIs v2.0.0.
It also includes a few generally used static function converters.
To use the common FireEye API logic, attach the `from FireEyeApiModule import *  # noqa: E402` line of code in the following location to import it. After you import the module, the `FireEyeClient` will be available for use.

```python
def main():
    ...


from FireEyeApiModule import *  # noqa: E402

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
```

For examples, see the [FireEye Central Management](https://xsoar.pan.dev/docs/reference/integrations/fire-eye-central-management) integration.
