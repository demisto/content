import demistomock as demisto




def main():
    args: dict = demisto.args()

    s: str = str(args.get('value'))
    length: int = int(args.get('length', 0))
    demisto.results(s.zfill(length))


if __name__ == 'builtins':
    main()
