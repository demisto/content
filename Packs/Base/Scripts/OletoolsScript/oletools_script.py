import oletools.oleid
from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML
from CommonServerPython import *

def oleid():
    oid = oletools.oleid.OleID('Archive.2/ActiveBarcode-Demo-Bind-Text.docm')
    indicators = oid.check()
    for i in indicators:
        print('Indicator id=%s name="%s" type=%s value=%s' % (i.id, i.name, i.type, repr(i.value)))
        print('description:\n', i.description)


#
# The file may also be provided as a bytes string containing its data. In that case, the actual filename must be provided for reference, and the file content with the data parameter. For example:
#


def olevba():
    try:
        # vbaparser = VBA_Parser('Archive.2/ActiveBarcode-Demo-Bind-Text.docm')

        my_file = 'Archive.2/ActiveBarcode-Demo-Bind-Text.docm'
        file_data = open(my_file, 'rb').read()
        vbaparser = VBA_Parser(my_file, data=file_data)

        if vbaparser.detect_vba_macros():
            print('VBA Macros found')
        else:
            print('No VBA Macros found')

        all_macros = vbaparser.extract_all_macros()
        reveal = vbaparser.reveal()
        results = vbaparser.analyze_macros()

        print(all_macros)

    except Exception as e:
        return_error(e)


def main():
    olevba()


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()


