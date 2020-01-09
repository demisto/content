import demistomock as demisto

EXTRACTORS = {
    "AMAZON": "prefixes[?service=='AMAZON']",
    "EC2": "prefixes[?service=='EC2']",
    "ROUTE53": "prefixes[?service=='ROUTE53']",
    "ROUTE53_HEALTHCHECKS": "prefixes[?service=='ROUTE53_HEALTHCHECKS']",
    "CLOUDFRONT": "prefixes[?service=='CLOUDFRONT']",
    "S3": "prefixes[?service=='S3']",
    "@": "@"
}


def get_extractors(extractors):
    return [EXTRACTORS.get(extractor) for extractor in extractors if extractor]


from JSONFeedApiModule import *  # noqa: E402


def main():
    params = demisto.params()
    extractors = get_extractors(params.get('extractors', ['@']))
    params['extractors'] = extractors
    feed_main(params, 'AWS')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
