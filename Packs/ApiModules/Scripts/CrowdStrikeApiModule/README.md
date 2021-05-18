The CrowdStrike API handles the oauth2 authentication process and API requests. When developing a CrowdStrike integration, import the API module to the integration and the authentication process will occur automatically.
To use the common CrowdStrike API logic, attach the `from CrowdStrikeApiModule import *  # noqa: E402` line of code in the following location to import it. After you import the module, the `CrowdStrikeClient` will be available for use.

```python
def main():
    ...


from CrowdStrikeApiModule import *  # noqa: E402

if __name__ in ["builtins", "__main__"]:
    main()
```

For examples, see the `CrowdStrike Falcon Intel v2` integration.
