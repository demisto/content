To use the common CrowdStrike API logic (authentication and API requests), run the following command to import the `CrowdStrikeApiModule`. After you import the module, the `CrowdStrikeClient` will be available to use.

```python
def main():
    ...


from CrowdStrikeApiModule import *  # noqa: E402

if __name__ in ["builtins", "__main__"]:
    main()
```
