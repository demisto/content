import demisto

def main():
    client = demisto.DemistoClient('<your-api-key-goes-here>', 'https://localhost:8443')
    print client
    print 'hello world'

if __name__ == '__main__':
    main()