from DateTimeNowToEpoch import retrieve_epoch


def test_retrieve_epoch():
    assert type(retrieve_epoch()) is int
