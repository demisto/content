The FIreEye API handles the API Key generation from the user/pass authentication.
It holds the client command calls to the wsapis v2.0.0.
It also includes a few generally used static func converters.
To use the common CrowdStrike API logic, attach the `from FireEyeApiModule import *  # noqa: E402` line of code in the following location to import it. After you import the module, the `FireEyeClient` will be available for use.

```python
def main():
    ...


from FireEyeApiModule import *  # noqa: E402

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
```

For examples, see the `FireEye Central Mangagement` integration.
