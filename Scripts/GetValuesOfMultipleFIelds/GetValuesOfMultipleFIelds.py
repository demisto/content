import demistomock as demisto


def main():
    args = demisto.args()
    root = args.get('Key')
    if not isinstance(root, list):
        root = [root]
    keys = args.get('List', '').split(',')

    t = []
    for obj in root:
        for _key in keys:
            temp = obj.get(_key)
            if temp:
                _ = t.extend(temp) if isinstance(temp, list) else t.append(temp)

    initial_value = args.get('value')
    if initial_value:
        _ = t.extend(initial_value) if isinstance(initial_value, list) else t.append(initial_value)
    demisto.results(t)


if __name__ in ('builtins', '__builtin__'):
    main()
