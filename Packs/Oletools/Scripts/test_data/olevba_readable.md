### VBA Macros found
### Macros found
|VBA Macro|Found in file|Ole stream|
|---|---|---|
| ThisDocument.cls | word/vbaProject.bin | VBA/ThisDocument |

### Macro source code
 ' Data binding comes "out of the box" for Excel and Access.
' To have the same function in Word some lines of VBA are required.
' This simpified version just uses a bookmark.
' Author: info@activebarcode.de, www.activebarcode.de / www.activebarcode.com
' Version 1.0.0

' Monitor if content of a bookmark is changing
Private MyBookmarkContent As String

' Start a timer when the document is opened
Private Sub Document_Open()
  alertTime = Now + TimeValue("00:00:01")
  Application.OnTime alertTime, "EventHandler"
End Sub

Public Sub EventHandler()
  ' Here is the actual data binding and this is how it works:
  ' Monitor the content of the bookmark.
  ' If the content of the bookmark has changed, update the barcode.
  If ActiveDocument.Bookmarks("Bookmark1").Range <> MyBookmarkContent Then
    MyBookmarkContent = ActiveDocument.Bookmarks("Bookmark1").Range
    ' This is what actually set the text to the barcode object
    Barcode1.Text = MyBookmarkContent
  End If
  ' Check again in 1 second.
  alertTime = Now + TimeValue("00:00:01")
  Application.OnTime alertTime, "EventHandler"
  ' If you want the timer to stop after a change of the bookmark,
  ' start the timer in an else clause.
End Sub

### Macro Analyze
|Type|Keyword|Description|
|---|---|---|
| AutoExec | Document_Open | Runs when the Word or Publisher document is opened |
| Suspicious | Base64 Strings | Base64-encoded strings were detected, may be used to obfuscate strings (option --decode to see all) |
