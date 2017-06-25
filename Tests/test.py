import demisto
import os
import sys

def print_error(error_str):
    sys.stderr.write(error_str + '\n')

def main():
    #client = demisto.DemistoClient('<your-api-key-goes-here>', 'https://localhost:8443')
    #print client
    print os.environ.get('testname') # define in circle-ci settings
    print 'hello world'
    print_error('helele')

if __name__ == '__main__':
    main()

