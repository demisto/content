resp = demisto.executeCommand( 'ADGetUserGroups', demisto.args() )
try:
    if not isError(resp[0]):
        for d in resp[0]['Contents']:
            if demisto.args()['groupname'] == d['name']:
                demisto.results("yes")
                sys.exit(0)
        demisto.results("no")
    else:
        demisto.results( { 'Type' : entryTypes['error'], 'ContentsFormat' : formats['text'], 'Contents' : 'Error returned from ADGetUserGroups:\n' + resp[0]['Contents'] } )
except Exception, ex:
    demisto.results( { 'Type' : entryTypes['error'], 'ContentsFormat' : formats['text'], 'Contents' : 'Error occurred while parsing output from ADGetUserGroups. Exception info:\n' + str(ex) + '\n\nInvalid output:\n' + str( resp ) } )
    
