from GoogleCloudStorage import *
from datetime import datetime


def test_ec_key():

    # No entry merging
    assert ec_key('Foo.Bar.Baz') == 'Foo.Bar.Baz'

    # Merge entries by single ID field
    assert ec_key('Foo.Bar.Baz', 'ID') == 'Foo.Bar.Baz(val.ID && val.ID === obj.ID)'

    # Merge entries by multiple ID fields
    assert ec_key('Foo.Bar.Baz', 'ID1', 'ID2') ==\
        'Foo.Bar.Baz(val.ID1 && val.ID1 === obj.ID1' \
        ' && val.ID2 && val.ID2 === obj.ID2)'

    assert ec_key('Foo.Bar.Baz', 'ID1', 'ID2', 'ID3') ==\
        'Foo.Bar.Baz(val.ID1 && val.ID1 === obj.ID1' \
        ' && val.ID2 && val.ID2 === obj.ID2' \
        ' && val.ID3 && val.ID3 === obj.ID3)'


def test_reformat_datetime_str():
    assert reformat_datetime_str('2019-08-28T11:28:47.165Z') == '2019-08-28T11:28:47'
    assert reformat_datetime_str('2001-04-14T23:32:15.999Z') == '2001-04-14T23:32:15'
    assert reformat_datetime_str('2030-11-07T02:00:00.000Z') == '2030-11-07T02:00:00'


def test_datetime2str():
    assert datetime2str(datetime(year=2019, month=8, day=28, hour=11, minute=28, second=47, microsecond=165123))\
        == '2019-08-28T11:28:47'
    assert datetime2str(datetime(year=2001, month=4, day=14, hour=23, minute=32, second=15, microsecond=999999))\
        == '2001-04-14T23:32:15'
    assert datetime2str(datetime(year=2030, month=11, day=7, hour=14, minute=7, second=0, microsecond=0))\
        == '2030-11-07T14:07:00'


def test_human_readable_table():
    # Verify that 1. header order is preserved, 2. spaces are added between (capitalized) header words
    assert human_readable_table(
        'My Table', {'HeaderOne': 'value one', 'HeaderTwo': 'value two', 'HeaderThree': 'value three'})\
        == '### My Table\n' \
           '|Header One|Header Two|Header Three|\n' \
           '|---|---|---|\n' \
           '| value one | value two | value three |\n'


def test_format_error():
    assert format_error(ValueError('Somebody set up us the bomb.')) == 'ValueError: Somebody set up us the bomb.'
    assert format_error(ValueError()) == 'Error occurred in the Google Cloud Storage Integration (ValueError)'
    assert format_error(7) == 'Error occurred in the Google Cloud Storage Integration (7)'
