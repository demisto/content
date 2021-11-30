import requests


def main():
    r = requests.get(url='http://127.0.0.1:7000/darya-root/collections/id123/objects/')
    print(r.json())


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()
