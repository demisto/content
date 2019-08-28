import pytest
from GitHub import get_last_event


@pytest.mark.parametrize(
    'commit_ts,comment_ts,review_ts,expected',
    [
        ('2011-04-14T16:00:49Z', '2011-04-14T16:00:49Z', '2011-04-14T16:00:49Z', 'comment'),
        ('2011-04-15T16:00:49Z', '2011-04-14T16:00:49Z', '2011-04-14T16:00:49Z', 'commit'),
        ('2011-04-14T16:00:49Z', '2011-04-14T16:00:49Z', '2011-04-15T16:00:49Z', 'review'),
        ('2011-04-14T16:00:49Z', '2011-04-15T16:00:49Z', '2011-04-14T16:00:49Z', 'comment'),
        ('2011-04-14T16:00:49Z', '', '2011-04-14T16:00:49Z', 'commit'),
        ('', '', '2011-04-14T16:00:49Z', 'review')
    ],
)
def test_get_last_event(commit_ts, comment_ts, review_ts, expected):
    last_event = get_last_event(commit_ts, comment_ts, review_ts)
    assert last_event == expected
