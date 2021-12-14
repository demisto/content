from TAXII2Server import *

SERVER = TAXII2Server(url_scheme='http',
                      host='demisto',
                      port=7000,
                      collections={'Test1': 'type:IP', 'Test2': 'type:URL'},
                      certificate='',
                      private_key='',
                      http_server=True,
                      credentials={},
                      version='2.1',
                      service_address='')
