# Optional arguments and default values
attrs = 'name,displayname'
if demisto.get(demisto.args(), 'attributes'):
    attrs += "," + demisto.args()['attributes']

filterstr = r"(&(objectCategory=User)(memberof=" + demisto.args()['groupdn'] + "))"
demisto.results( demisto.executeCommand( 'ad-search', { 'filter' : filterstr, 'attributes' : attrs } ) )
