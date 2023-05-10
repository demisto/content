oleid_output = {'sha256': '5e39dc43ecf63d3e670f757991691f0b10317d4eb83662d0898a40149927372f',
                'file_name': 'ActiveBarcode-Demo-Bind-Text.docm', 'ole_command_result': {
        'File_format': {'Value': 'MS Word 2007+ Macro-Enabled Document (.docm)', 'Ole_Risk': 'info', 'Description': ''},
        'Container_format': {'Value': 'OpenXML', 'Ole_Risk': 'info', 'Description': 'Container type'},
        'Encrypted': {'Value': 'False', 'Ole_Risk': 'none', 'Description': 'The file is not encrypted'},
        'VBA_Macros': {'Value': 'Yes', 'Ole_Risk': 'Medium',
                       'Description': 'This file contains VBA macros. No suspicious keyword was found. Use olevba and mraptor for more info.'},
        'XLM_Macros': {'Value': 'No', 'Ole_Risk': 'none',
                       'Description': 'This file does not contain Excel 4/XLM macros.'},
        'External_Relationships': {'Value': '1', 'Ole_Risk': 'HIGH',
                                   'Description': 'External relationships found: hyperlink - use oleobj for details'},
        'ObjectPool': {'Value': 'False', 'Ole_Risk': 'none',
                       'Description': 'Contains an ObjectPool stream, very likely to contain embedded OLE objects or files. Use oleobj to check it.'},
        'Flash_objects': {'Value': '0', 'Ole_Risk': 'none',
                          'Description': 'Number of embedded Flash objects (SWF files) detected in OLE streams. Not 100% accurate, there may be false positives.'}}}

oleobj_output = {'sha256': '5e39dc43ecf63d3e670f757991691f0b10317d4eb83662d0898a40149927372f',
                 'file_name': 'ActiveBarcode-Demo-Bind-Text.docm',
                 'ole_command_result': {'hyperlinks': ['http://www.activebarcode.com']}}

olevba_otuput = {'sha256': '5e39dc43ecf63d3e670f757991691f0b10317d4eb83662d0898a40149927372f',
                 'file_name': 'ActiveBarcode-Demo-Bind-Text.docm', 'ole_command_result': {'macro_list': [
        {'VBA Macro': 'ThisDocument.cls', 'Found in file': 'word/vbaProject.bin', 'Ole stream': 'VBA/ThisDocument'}],
                                                                                          'macro_src_code': '\' Data binding comes "out of the box" for Excel and Access.\n\' To have the same function in Word some lines of VBA are required.\n\' This simpified version just uses a bookmark.\n\' Author: info@activebarcode.de, www.activebarcode.de / www.activebarcode.com\n\' Version 1.0.0\n\n\' Monitor if content of a bookmark is changing\nPrivate MyBookmarkContent As String\n\n\' Start a timer when the document is opened\nPrivate Sub Document_Open()\n  alertTime = Now + TimeValue("00:00:01")\n  Application.OnTime alertTime, "EventHandler"\nEnd Sub\n\nPublic Sub EventHandler()\n  \' Here is the actual data binding and this is how it works:\n  \' Monitor the content of the bookmark.\n  \' If the content of the bookmark has changed, update the barcode.\n  If ActiveDocument.Bookmarks("Bookmark1").Range <> MyBookmarkContent Then\n    MyBookmarkContent = ActiveDocument.Bookmarks("Bookmark1").Range\n    \' This is what actually set the text to the barcode object\n    Barcode1.Text = MyBookmarkContent\n  End If\n  \' Check again in 1 second.\n  alertTime = Now + TimeValue("00:00:01")\n  Application.OnTime alertTime, "EventHandler"\n  \' If you want the timer to stop after a change of the bookmark,\n  \' start the timer in an else clause.\nEnd Sub\n',
                                                                                          'macro_analyze': [
                                                                                              {'Type': 'AutoExec',
                                                                                               'Keyword': 'Document_Open',
                                                                                               'Description': 'Runs when the Word or Publisher document is opened'},
                                                                                              {'Type': 'Suspicious',
                                                                                               'Keyword': 'Base64 Strings',
                                                                                               'Description': 'Base64-encoded strings were detected, may be used to obfuscate strings (option --decode to see all)'}]}}

oleid_decrypted_output = {'sha256': 'c3b4854dd73688154069cfe467b6899d2f77f6420a7a1bf8e22eacbe5eef811b',
                          'file_name': 'ActiveBarcode-Demo-Bind-Text.docm', 'ole_command_result': {
        'File_format': {'Value': 'MS Word 2007+ Macro-Enabled Document (.docm)', 'Ole_Risk': 'info', 'Description': ''},
        'Container_format': {'Value': 'OpenXML', 'Ole_Risk': 'info', 'Description': 'Container type'},
        'Encrypted': {'Value': 'False', 'Ole_Risk': 'none', 'Description': 'The file is not encrypted'},
        'VBA_Macros': {'Value': 'Yes', 'Ole_Risk': 'Medium',
                       'Description': 'This file contains VBA macros. No suspicious keyword was found. Use olevba and mraptor for more info.'},
        'XLM_Macros': {'Value': 'No', 'Ole_Risk': 'none',
                       'Description': 'This file does not contain Excel 4/XLM macros.'},
        'External_Relationships': {'Value': '1', 'Ole_Risk': 'HIGH',
                                   'Description': 'External relationships found: hyperlink - use oleobj for details'},
        'ObjectPool': {'Value': 'False', 'Ole_Risk': 'none',
                       'Description': 'Contains an ObjectPool stream, very likely to contain embedded OLE objects or files. Use oleobj to check it.'},
        'Flash_objects': {'Value': '0', 'Ole_Risk': 'none',
                          'Description': 'Number of embedded Flash objects (SWF files) detected in OLE streams. Not 100% accurate, there may be false positives.'}}}
