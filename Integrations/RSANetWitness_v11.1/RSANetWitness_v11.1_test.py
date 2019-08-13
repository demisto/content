from datetime import datetime


def test_me():
    stamps_to_check = [
        "2019-08-13T09:56:02.440653",
        "2019-08-13T09:56:02.440",
        "2019-08-13T09:56:02"
    ]
    t_formats = [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ"
    ]
    for stamp in stamps_to_check:
        for t_format in t_formats:
            try:
                a = datetime.strptime(stamp, t_format)
                print a
            except ValueError:
                pass


if __name__ == '__main__':
    test_me()
