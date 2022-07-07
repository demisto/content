import oletools.oleid
from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML


def oleid():
    oid = oletools.oleid.OleID('Archive.2/ActiveBarcode-Demo-Bind-Text.docm')
    indicators = oid.check()
    for i in indicators:
        print('Indicator id=%s name="%s" type=%s value=%s' % (i.id, i.name, i.type, repr(i.value)))
        print('description:\n', i.description)


#
# The file may also be provided as a bytes string containing its data. In that case, the actual filename must be provided for reference, and the file content with the data parameter. For example:
#
# myfile = 'my_file_with_macros.doc'
# filedata = open(myfile, 'rb').read()
# vbaparser = VBA_Parser(myfile, data=filedata)

def olevba():
    try:
        vbaparser = VBA_Parser('Archive.2/ActiveBarcode-Demo-Bind-Text.docm')
    except Exception as e:
        DemistoException(e)


def main():





if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()


