# Optional arguments and default values
attrs = 'name'
if demisto.get(demisto.args(), 'attributes'):
    attrs += "," + demisto.args()['attributes']
resp = ''
memberDN = ''
if demisto.get(demisto.args(), 'dn'):
    memberDN = demisto.args()['dn']
elif demisto.get(demisto.args(), 'name'):
    resp = demisto.executeCommand( 'ad-search', { 'filter' : "(&(objectCategory=User)(name=" + demisto.args()['name'] + "))" } )
elif demisto.get(demisto.args(), 'email'):
    resp = demisto.executeCommand( 'ADGetUsersByEmail', { 'email' : demisto.args()['email'] } )
else:
    demisto.results( { 'Type' : entryTypes['error'], 'ContentsFormat' : formats['text'], 'Contents' : 'You must provide either dn, name or email as argument!' } )
    sys.exit(0)

if type(resp)==list and len( [ r for r in resp if isError(r) ] ) > 0 :
    demisto.results( { 'Type' : entryTypes['error'], 'ContentsFormat' : formats['text'], 'Contents' : 'Error returned by ad command: ' + r['Contents'] } )
    sys.exit(0)

if not memberDN:
    if type(resp)==list and len(resp)==1 and type(resp[0])==dict and 'Contents' in resp[0] and type(resp[0]['Contents'])==list and len(resp[0]['Contents'])==1 and type(resp[0]['Contents'][0])==dict and 'dn' in resp[0]['Contents'][0]:
        memberDN = resp[0]['Contents'][0]['dn']
    else:
        if resp[0]['Contents'] == 'No results':
            demisto.results( { 'Type' : entryTypes['error'], 'ContentsFormat' : formats['text'], 'Contents' : 'User not found.' } )
        else:
            demisto.results( { 'Type' : entryTypes['error'], 'ContentsFormat' : formats['text'], 'Contents' : 'Unexpected output from ad command.' } )
        sys.exit(0)

if memberDN:
    filterstr = r"(&(member=" + memberDN + ")(objectcategory=group))"
    demisto.results( demisto.executeCommand( 'ad-search', { 'filter' : filterstr, 'attributes' : attrs } ) )
else:
    demisto.results( { 'Type' : entryTypes['error'], 'ContentsFormat' : formats['text'], 'Contents' : 'Received empty DN or cannot locate DN for the specified arguments.' } )
