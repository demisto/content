from DBotBuildPhishingClassifier import *

QUERY = '-status:closed and -category:job and created:>="2020-11-08T00:00:00 +0200"'
MAPPING = 'spam:SPAM,legit:LEGIT,phishing:PHISHING'


def test_no_mapping_no_query():
    args = {'phishingLabels': '*'}
    args = build_query_in_reepect_to_phishing_labels(args)
    assert 'query' not in args


def test_no_mapping_with_query():
    args = {'phishingLabels': '*', 'query': QUERY}
    args = build_query_in_reepect_to_phishing_labels(args)
    assert 'query' in args and args['query'] == QUERY


def test_mapping_no_query():
    args = {'phishingLabels': MAPPING, 'tagField': 'closeReason'}
    args = build_query_in_reepect_to_phishing_labels(args)
    assert 'query' in args and args['query'] == 'closeReason:("spam" "legit" "phishing")'


def test_mapping_with_query():
    args = {'phishingLabels': MAPPING, 'tagField': 'closeReason', 'query': QUERY}
    args = build_query_in_reepect_to_phishing_labels(args)
    assert 'query' in args and args['query'] == '({}) and (closeReason:("spam" "legit" "phishing"))'.format(QUERY)
