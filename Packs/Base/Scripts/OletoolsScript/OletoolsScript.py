import oletools.oleid
from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML
from CommonServerPython import *
import os
from oletools.oleobj import process_file
import demistomock as demisto


def oleid():
    attach_id = demisto.args().get('attach_id', '')
    file_info = demisto.getFilePath(attach_id)
    oid = oletools.oleid.OleID(file_info['path'])
    indicators = oid.check()
    indicators_list = []
    for i in indicators:
        indicators_list.append({'Indicator': str(i.name),
                                'Value': str(i.value),
                                'Risk': str(i.risk),
                                'Description': str(i.description)})

    # oid = oletools.oleid.OleID('Archive.2/ActiveBarcode-Demo-Bind-Text.docm')
    # indicators = oid.check()
    # for i in indicators:
    #     indicators_dict = {'Indicator id' : i.id,
    #                        'Name' : i.name,
    #                        'Type' : i.type,
    #                        'Value' : repr(i.value),
    #                        'Description': i.description}

        # print('Indicator id=%s name="%s" type=%s value=%s' % (i.id, i.name, i.type, repr(i.value)))
        # print('description:\n', i.description)

    cr = CommandResults(readable_output=tableToMarkdown(file_info['name'], indicators_list,
                                                        headers=['Indicator', 'Value', 'Risk', 'Description']), outputs=indicators_list,
                          outputs_prefix='Oletools.Oleid')
    return cr


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


def oleobj():
    import io
    my_file = 'Archive.2/SuperComputer-Overview-simplified.pptm'
    file_data = open(my_file, 'rb').read()
    old_stdout = sys.stdout
    new_stdout = io.StringIO()
    sys.stdout = new_stdout

    process_file(my_file, file_data)

    sys.stdout = old_stdout
    output = new_stdout.getvalue()
    cr = CommandResults(readable_output=output)
    return cr


def main():
    command = demisto.args().get('ole_command')
    commands = {'oleid': oleid,
                'oleobj': oleobj}

    try:
        return_results(commands.get(command)())
    except Exception as e:
        return DemistoException(e)


if __name__ in ['__main__', '__builtin__', 'builtins']:
    main()


