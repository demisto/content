The Atlassian API handles the OAuth1 authentication process and API requests. When developing an Atlassian integration.

To use the common ServiceNow API logic, attach the `from AtlassianApiModule import *  # noqa: E402` line of code after the `main()` definition, before it is called to import it as shown in the example below. After you import the module, the `AtlassianClient` will be available for use.

```python
def main():
    ...


from AtlassianApiModule import *  # noqa: E402

if __name__ in ["builtins", "__main__"]:
    main()
```

For examples, see the `Jira v2` integration.
