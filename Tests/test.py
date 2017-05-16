import demisto
import os

def main():
    #client = demisto.DemistoClient('<your-api-key-goes-here>', 'https://localhost:8443')
    print client
    print os.environ.get('testname') # define in circle-ci settings
    print 'hello world'
    print os.environ.get('KEY_THAT_MIGHT_EXIST')

if __name__ == '__main__':
    main()

