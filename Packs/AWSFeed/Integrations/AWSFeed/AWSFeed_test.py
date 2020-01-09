def test_extractors():
    from AWSFeed import get_extractors

    extractors = ['AMAZON', 'EC2']

    mapped_extractors = get_extractors(extractors)

    assert mapped_extractors == ["prefixes[?service=='AMAZON']", "prefixes[?service=='EC2']"]
