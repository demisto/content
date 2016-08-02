# Optional arguments and default values
attrs = 'name,displayname,mail'
if demisto.get(demisto.args(), 'attributes'):
    attrs += "," + demisto.args()['attributes']

email = demisto.args()['email']
filterstr = r"(&(objectClass=user)(mail=" + email + "))"
demisto.results( demisto.executeCommand( 'ad-search', { 'filter' : filterstr, 'attributes' : attrs } ) )
