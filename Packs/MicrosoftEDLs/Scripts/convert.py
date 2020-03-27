indicators = ['test','test2','test3']
feed_url = "testurl.com"
test = {}
result = []
for i in indicators:  # add relevant fields of sub feeds
    result.append({
        "Region": 'north',
        "Service": 'mytest',
        "FeedURL": feed_url
            })

print(result)