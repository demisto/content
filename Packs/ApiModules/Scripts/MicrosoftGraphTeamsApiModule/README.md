To use the common Microsoft Graph Teams integration logic, add the following code to import the `MicrosoftGraphTeamsApiModule`.

```python
def main():
    run_microsoft_graph_teams_integration()


from MicrosoftGraphTeamsApiModule import *  # noqa: E402

if __name__ in ["builtins", "__main__"]:
    main()
```

Then, the `run_microsoft_graph_teams_integration` entry point and `MsGraphClient` class will be available for usage. For the canonical consumer, see the `O365 Teams (Using Graph API)` integration in the `MicrosoftGraphTeams` pack.
