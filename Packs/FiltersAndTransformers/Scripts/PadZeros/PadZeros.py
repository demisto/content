import demistomock as demisto


from typing import Dict


def main():
    args: Dict = demisto.args()

    s: str = str(args.get('value'))
    length: int = int(args.get('length', 0))
    demisto.results(s.zfill(length))


if __name__ == 'builtins':
    main()
