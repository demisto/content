# Optional arguments and default values
attrs = 'name,displayname'
if demisto.get(demisto.args(), 'attributes'):
    attrs += "," + demisto.args()['attributes']
demisto.results( demisto.executeCommand( 'ad-search', { 'filter' : "(objectClass=User)", 'attributes' : attrs } ) )
