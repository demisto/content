import demistomock as demisto
from CommonServerPython import *
''' IMPORTS '''

from ldap3 import Server, Connection, MODIFY_ADD, MODIFY_REPLACE, MODIFY_DELETE
from ldap3.utils.dn import safe_rdn


''' HELPER FUNCTIONS '''


def return_results(mdTableName, res, entryContext):
    try:
        if res['dn'] is None and dn:
            res['dn'] = dn
    except SyntaxError:
        res['dn'] = None
    try:
        md = tableToMarkdown(mdTableName, res)
        demisto.results({
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': res,
            'HumanReadable': md,
            'ReadableContentsFormat': formats['markdown'],
            'EntryContext': {entryContext: res}
        })
    except Exception as err:
        return_error(err)


class Client():
    def __init__(self, host, port, username, password, secure, getInfo="SCHEMA"):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.useSSL = secure
        self.server = Server(self.host, port=self.port, use_ssl=self.useSSL, get_info=getInfo)
        self.conn = None
        self.bind = None

    def establishConnection(self):
        try:
            self.conn = Connection(self.server, user=self.username, password=self.password, raise_exceptions=False)
            self.bind = self.conn.bind()
            if not self.bind:
                return_error(self.conn.result['description'])
            else:
                return
        except Exception as err:
            return_error(err)

    def search(self, base, inputFilter, attributes=None):
        try:
            self.establishConnection()
            if attributes:
                return self.conn.search(base, inputFilter, attributes=attributes)
            else:
                return self.conn.search(base, inputFilter)
        except Exception as err:
            return_error(err)

    def createEntry(self, dn, objectClass, attributes=None):
        try:
            self.establishConnection()
            return self.conn.add(dn, objectClass, attributes=attributes)
        except Exception as err:
            return_error(err)

    def renameEntry(self, oldDN, newDN):
        try:
            self.establishConnection()
            return self.conn.modify_dn(oldDN, newDN)
        except Exception as err:
            return_error(err)

    def moveEntry(self, dn, rn, location):
        try:
            self.establishConnection()
            return self.conn.modify_dn(dn, rn, new_superior=location)
        except Exception as err:
            return_error(err)

    def modifyAttribute(self, dn, attributes):
        try:
            self.establishConnection()
            return self.conn.modify(dn, attributes)
        except Exception as err:
            return_error(err)

    def checkAttribute(self, dn, attribute, value):
        try:
            self.establishConnection()
            return self.conn.compare(dn, attribute, value)
        except Exception as err:
            return_error(err)


def test_command(client):
    client.establishConnection()
    demisto.results('ok')


def search_command(client):
    attributes = demisto.args().get('attributes', None)
    if attributes:
        attributes = attributes.replace(" ", "").split(",")
    #res = client.search(base, inputFilter, attributes)
    entryList = [json.loads(x.entry_to_json()) for x in client.conn.entries]
    client.conn.result['attributes'] = attributes
    return_results('Search Results:', entryList, 'LDAP.Object.Search(val.dn && val.dn == obj.dn)')


def createEntry_command(client):
    dn = demisto.args().get('dn')
    objectClass = demisto.args().get('objectClass')
    attributes = demisto.args().get('attributes', None)
    if attributes:
        try:
            attributes = json.loads(attributes)
        except Exception as err:
            return_error('Error parsing attributes - {}'.format(err))
    client.createEntry(dn, objectClass, attributes)
    if not client.conn.result['dn']:
        client.conn.result['dn'] = dn
    return_results('Object create:', client.conn.result, 'LDAP.Object.Create(val.dn && val.dn == obj.dn)')


def renameEntry_command(client):
    oldDN = demisto.args().get('oldDN')
    newDN = demisto.args().get('newDN')
    client.renameEntry(oldDN, newDN)
    if not client.conn.result['dn']:
        client.conn.result['dn'] = newDN
    return_results('Object rename:', client.conn.result, 'LDAP.Object.Rename(val.dn && val.dn == obj.dn)')


def moveEntry_command(client):
    dn = demisto.args().get('dn')
    location = demisto.args().get('location')
    rn = safe_rdn(dn)
    client.moveEntry(dn, rn, location)
    if not client.conn.result['dn']:
        client.conn.result['dn'] = dn
    return_results('Object move:', client.conn.result, 'LDAP.Object.Move(val.dn && val.dn == obj.dn)')


def addAttribute_command(client):
    dn = demisto.args().get('dn')
    attributes = demisto.args().get('attributes')
    entries = []
    try:
        attributes = json.loads(attributes)
    except Exception as err:
        return_error('Error parsing attributes = {}'.format(err))
    for k,v in attributes.items():
        attrib = {k: [MODIFY_ADD, v]}
        client.modifyAttribute(dn, attrib)
        if client.conn.result['description'] == "attributeOrValueExists":
            attrib = {k: [MODIFY_REPLACE, v]}
            client.modifyAttribute(dn, attrib)
        if client.conn.result['description'] == "success":
            if not client.conn.result['dn']:
                client.conn.result['dn'] = dn
            client.conn.result['attribute'] = k
            client.conn.result['value'] = v
            entries.append(client.conn.result)
    return_results('Add Attributes:', entries, 'LDAP.Attribute.Add(val.dn && val.dn == obj.dn)')


def modifyAttribute_command(client):
    dn = demisto.args().get('dn')
    attributes = demisto.args().get('attributes')
    entries = []
    try:
        attributes = json.loads(attributes)
    except Exception as err:
        return_error('Error parsing attributes = {}'.format(err))
    for k,v in attributes.items():
        attrib = {k: [MODIFY_REPLACE, v]}
        client.modifyAttribute(dn, attrib)
        if client.conn.result['description'] == "attributeOrValueExists":
            attrib = {k: [MODIFY_ADD, v]}
            client.modifyAttribute(dn, attrib)
        if client.conn.result['description'] == "success":
            if not client.conn.result['dn']:
                client.conn.result['dn'] = dn
            client.conn.result['attribute'] = k
            client.conn.result['value'] = v
            entries.append(client.conn.result)
    return_results('Replace Attributes:', entries, 'LDAP.Attribute.Replace(val.dn && val.dn == obj.dn)')

def deleteAttribute_command(client):
    dn = demisto.args().get('dn')
    attributes = demisto.args().get('attributes')
    attributes = attributes.split(",")
    entries = []
    for k in attributes:
        # Set the value first (to something we know)
        attrib = {k: [MODIFY_REPLACE, "blank"]}
        client.modifyAttribute(dn, attrib)
        # Then delete it
        attrib = {k: [MODIFY_DELETE, "blank"]}
        client.modifyAttribute(dn, attrib)
        if not client.conn.result['dn']:
            client.conn.result['dn'] = dn
        client.conn.result['attribute'] = k
        client.conn.result['value'] = ""
        entries.append(client.conn.result)
    return_results('Delete Attributes:', entries, 'LDAP.Attribute.Delete(val.dn && val.dn == obj.dn)')


def checkAttribute_command(client):
    dn = demisto.args().get('dn')
    attribute = demisto.args().get('attribute')
    value = demisto.args().get('value', None)
    res = client.checkAttribute(dn, attribute, value)
    entry = {"dn": dn, "attribute": attribute, "value": value, "matches": res}
    return_results('Check Attribute {}:'.format(attribute), entry, 'LDAP.Attribute.Check(val.dn && val.dn == obj.dn && val.attribute && val.attribute == obj.attribute)')

def getInfo_command(host, port, username, password, secure):
    infoType = demisto.args().get('type', 'ALL')
    client = Client(host, port, username, password, secure, getInfo=infoType)
    client.establishConnection()
    try:
        info = json.loads(client.server.info.to_json())
    except:     #lgtm [py/catch-base-exception]
        info = None
        pass
    try:
        schema = json.loads(client.server.schema.to_json())
    except:     #lgtm [py/catch-base-exception]
        schema = None
    if info:
        return_results('LDAP Information:', info, 'LDAP.Server.Info(val.type && val.type == obj.type)')
    if schema:
        return_results('LDAP Schema:', schema, 'LDAP.Server.Schema(val.type && val.type == obj.type)')


def main():

    host = demisto.params().get('host')
    port = int(demisto.params().get('port'))
    credentials = demisto.params().get('credentials', None)
    domain = demisto.params().get('domain', None)
    if credentials:
        username = credentials.get('identifier', None)
        password = credentials.get('password', None)
        if domain:
            username = domain + '\\' + username
    else:
        username = None
        password = None
    secure = demisto.params().get('secure')

    client = Client(host, port, username, password, secure)

    if demisto.command() == 'test-module':
        test_command(client)

    if demisto.command() == 'ldap-object-search':
        search_command(client)

    if demisto.command() == 'ldap-object-create':
        createEntry_command(client)

    if demisto.command() == 'ldap-object-rename':
        renameEntry_command(client)

    if demisto.command() == 'ldap-object-move':
        moveEntry_command(client)

    if demisto.command() == 'ldap-attribute-add':
        addAttribute_command(client)

    if demisto.command() == 'ldap-attribute-replace':
        modifyAttribute_command(client)

    if demisto.command() == 'ldap-attribute-delete':
        deleteAttribute_command(client)

    if demisto.command() == 'ldap-attribute-check':
        checkAttribute_command(client)

    if demisto.command() == 'ldap-get-info':
        getInfo_command(host, port, username, password, secure)


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
