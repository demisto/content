import feedparser

NO_ARTICLE = feedparser.util.FeedParserDict({
    'bozo': False,
    'entries': []
})

NO_ARTICLE_RES = []

ONE_ARTICLE_HTML_RES = [{'timestamp': 'June 25, 2021 3:35 PM',
                         'link': 'https://test-article.com/',
                         'title': 'Test html Article without comma',
                         'summary': 'This is HTML article example.\n\n\nThe post [Example](http://example_link/) appeared first on:\n[Example URL](http://example_link/).\n\n',
                         'author': 'Jasmine'}]
ONE_ARTICLE_HTML = feedparser.util.FeedParserDict({
    'bozo': False,
    'entries': [
        feedparser.util.FeedParserDict({'title': 'Test html Article without comma',
                                        'link': 'https://test-article.com/',
                                        'authors': [
                                            {'name': 'Example'}
                                        ],
                                        'published': 'Fri, 25 Jun 2021 15:35:41 +0000',
                                        'tags': [{'term': 'Malware', 'scheme': None, 'label': None}],
                                        'id': '5678',
                                        'guidislink': False,
                                        'summary': '''<p>This is HTML article example.</p>
<p>The post <a href="http://example_link/">Example</a> appeared first on:
<a href="http://example_link/">Example URL</a>.</p>''',
                                        'author': 'Jasmine'}),
    ]
})
ONE_ARTICLE = feedparser.util.FeedParserDict({
    'bozo': False,
    'entries': [
        feedparser.util.FeedParserDict({'title': 'Test Article without comma',
                                        'link': 'https://test-article.com/',
                                        'authors': [
                                            {'name': 'Example'}
                                        ],
                                        'published': 'Fri, 25 Jun 2021 15:35:41 +0000',
                                        'tags': [{'term': 'Malware', 'scheme': None, 'label': None}],
                                        'id': '5678',
                                        'guidislink': False,
                                        'summary': 'this is another summary',
                                        'author': 'Timor'}),
    ]
})

ONE_ARTICLE_RES = [
    {
        'timestamp': 'June 25, 2021 3:35 PM',
        'link': 'https://test-article.com/',
        'title': 'Test Article without comma',
        'summary': 'this is another summary',
        'author': 'Timor',
    },
]

ONE_ARTICLE_STRING = '''**[Test Article without comma](https://test-article.com/)**
*Posted June 25, 2021 3:35 PM by Timor*
this is another summary


'''

ONE_ARTICLE_STRING_FORMATTED = '''**[Test Article without comma](https://test-article.com/)**
{{color:#89A5C1}}(*Posted June 25, 2021 3:35 PM by Timor*)
this is another summary


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
                                        'summary': "this is summary",
                                        'author': 'Timor'}),
    ]
})

ONE_ARTICLE_NOT_PUBLISHED_RES = []

TWO_ARTICLES = feedparser.util.FeedParserDict({
    'bozo': False,
    'entries': [
        feedparser.util.FeedParserDict({'title': 'Test Article without comma',
                                        'link': 'https://test-article.com/',
                                        'authors': [
                                            {'name': 'Example'}
                                        ],
                                        'published': 'Fri, 25 Jun 2021 15:35:41 +0000',
                                        'tags': [{'term': 'Malware', 'scheme': None, 'label': None}],
                                        'id': '5678',
                                        'guidislink': False,
                                        'summary': 'this is another summary',
                                        'author': 'Timor'}),
        feedparser.util.FeedParserDict({'title': 'Test Article, with comma',
                                        'link': 'https://test-article.com/',
                                        'authors': [
                                            {'name': 'Example'}
                                        ],
                                        'published': 'Fri, 18 Jun 2021 15:35:41 +0000',
                                        'tags': [{'term': 'Malware', 'scheme': None, 'label': None}],
                                        'id': '1234',
                                        'guidislink': False,
                                        'summary': 'this is summary',
                                        'author': 'Shai'}),
    ]
})

TWO_ARTICLES_RES = [
    {
        'timestamp': 'June 25, 2021 3:35 PM',
        'link': 'https://test-article.com/',
        'title': 'Test Article without comma',
        'summary': 'this is another summary',
        'author': 'Timor',
    },
    {
        'timestamp': 'June 18, 2021 3:35 PM',
        'link': 'https://test-article.com/',
        'title': 'Test Article, with comma',
        'summary': 'this is summary',
        'author': 'Shai',
    },
]

TWO_ARTICLES_STRING = '''**[Test Article without comma](https://test-article.com/)**
*Posted June 25, 2021 3:35 PM by Timor*
this is another summary


**[Test Article, with comma](https://test-article.com/)**
*Posted June 18, 2021 3:35 PM by Shai*
this is summary


'''
