# Optional arguments and default values
attrs = 'name'
if demisto.get(demisto.args(), 'attributes'):
    attrs += "," + demisto.args()['attributes']
demisto.results( demisto.executeCommand( 'ad-search', { 'filter' : "(objectCategory=Computer)", 'attributes' : attrs } ) )
