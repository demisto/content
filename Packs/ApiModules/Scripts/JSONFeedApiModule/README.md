To use the common JSON feed API logic, run the following command to import the `JSONFeedApiModule`.
The module expects the feed to be configured with the following parameters:

Per sub-feed name:
* URL
* `jmespath` extractor
* indicator name
* indicator type

See the below example: 

```python
def main():
    ...
    
    feed_name_to_config = {
        'AMAZON': {
            'url': 'https://ip-ranges.amazonaws.com/ip-ranges.json',
            'extractor': "prefixes[?service=='AMAZON']",
            'indicator': 'ip_prefix',
            'indicator_type': FeedIndicatorType.IP,
        }
    }

    params = {k: v for k, v in demisto.params().items() if v is not None}
    params['feed_name_to_config'] = feed_name_to_config
    feed_main(params, 'AWS Feed')


from JSONFeedApiModule import *  # noqa: E402

if __name__ in ["builtins", "__main__"]:
    main()
```
