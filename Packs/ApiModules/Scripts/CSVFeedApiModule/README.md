To use the common CSV Feed API logic, run the following:

```python
def main():
    feed_main(<FEED_NAME>)


from CSVFeedApiModule import *  # noqa: E402

if __name__ in ["builtins", "__main__"]:
    main()
```

`feed_main` is the main execution of the Feed API module. It can be extended or overriden in the integration `main` function.
Note that the module expectes a `feed_url_to_config` parameter to extract the indicators. This is similar to the configuration in minemeld. 
See the module class docstring for an example. 
