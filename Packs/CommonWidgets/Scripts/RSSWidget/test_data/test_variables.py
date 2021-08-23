import feedparser

NO_ARTICLE = feedparser.util.FeedParserDict({
    'bozo': False,
    'entries': []
})

NO_ARTICLE_RES = []

ONE_ARTICLE = feedparser.util.FeedParserDict({
    'bozo': False,
    'entries': [
        feedparser.util.FeedParserDict({'title': 'Test Article, with comma',
                                        'link': 'https://test-article.com/',
                                        'authors': [
                                            {'name': 'Example'}
                                        ],
                                        'published': 'Fri, 18 Jun 2021 15:35:41 +0000',
                                        'tags': [{'term': 'Malware', 'scheme': None, 'label': None}],
                                        'id': '1234',
                                        'guidislink': False,
                                        'summary': 'this is summary'}),
    ]
})

ONE_ARTICLE_RES = [
    {
        'timestamp': 'June 18, 2021 3:35 PM',
        'link': 'https://test-article.com/',
        'title': 'Test Article, with comma',
        'summary': 'this is summary',
    }
]

ONE_ARTICLE_STRING = '''## [Test Article, with comma](https://test-article.com/)
_June 18, 2021 3:35 PM_
#### this is summary
---
'''

ONE_ARTICLE_NOT_PUBLISHED = feedparser.util.FeedParserDict({
    'bozo': False,
    'entries': [
        feedparser.util.FeedParserDict({'title': 'Test Article, with comma',
                                        'link': 'https://test-article.com/',
                                        'authors': [
                                            {'name': 'Example'}
                                        ],
                                        'published': '',
                                        'tags': [{'term': 'Malware', 'scheme': None, 'label': None}],
                                        'id': '1234',
                                        'guidislink': False,
                                        'summary': "this is summary"}),
    ]
})

ONE_ARTICLE_NOT_PUBLISHED_RES = []


TWO_ARTICLES = feedparser.util.FeedParserDict({
    'bozo': False,
    'entries': [
        feedparser.util.FeedParserDict({'title': 'Test Article, with comma',
                                        'link': 'https://test-article.com/',
                                        'authors': [
                                            {'name': 'Example'}
                                        ],
                                        'published': 'Fri, 18 Jun 2021 15:35:41 +0000',
                                        'tags': [{'term': 'Malware', 'scheme': None, 'label': None}],
                                        'id': '1234',
                                        'guidislink': False,
                                        'summary': 'this is summary'}),
        feedparser.util.FeedParserDict({'title': 'Test Article without comma',
                                        'link': 'https://test-article.com/',
                                        'authors': [
                                            {'name': 'Example'}
                                        ],
                                        'published': 'Fri, 25 Jun 2021 15:35:41 +0000',
                                        'tags': [{'term': 'Malware', 'scheme': None, 'label': None}],
                                        'id': '5678',
                                        'guidislink': False,
                                        'summary': 'this is another summary'}),
    ]
})


TWO_ARTICLES_RES = [
    {
        'timestamp': 'June 18, 2021 3:35 PM',
        'link': 'https://test-article.com/',
        'title': 'Test Article, with comma',
        'summary': 'this is summary',
    },
    {
        'timestamp': 'June 25, 2021 3:35 PM',
        'link': 'https://test-article.com/',
        'title': 'Test Article without comma',
        'summary': 'this is another summary',
    },
]


TWO_ARTICLES_STRING = '''## [Test Article, with comma](https://test-article.com/)
_June 18, 2021 3:35 PM_
#### this is summary
---
## [Test Article without comma](https://test-article.com/)
_June 25, 2021 3:35 PM_
#### this is another summary
---
'''


TWO_ARTICLES_STRING_REVERSED = '''## [Test Article without comma](https://test-article.com/)
_June 25, 2021 3:35 PM_
#### this is another summary
---
## [Test Article, with comma](https://test-article.com/)
_June 18, 2021 3:35 PM_
#### this is summary
---
'''
