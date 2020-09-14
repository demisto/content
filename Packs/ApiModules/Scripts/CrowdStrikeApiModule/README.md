The CrowdStrike API handles the oauth2 authentication process and API requests. When developing a CrowdStrike integration, just import the API module to the integration and the authentication process will occur automatically.
To use the common CrowdStrike API logic, run the following command to import the `CrowdStrikeApiModule`. After you import the module, the `CrowdStrikeClient` will be available for use.

```python
def main():
    ...


from CrowdStrikeApiModule import *  # noqa: E402

if __name__ in ["builtins", "__main__"]:
    main()
```
