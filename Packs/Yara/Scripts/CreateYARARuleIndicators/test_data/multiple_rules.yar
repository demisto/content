rule svchost_ANOMALY{	
    meta:		
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"		
        author = "Florian Roth (Nextron Systems)"		
        description = "Abnormal svchost.exe - typical strings not found in file"		
        date = "23/04/2014"		
        score = 55		
        id = "5630054d-9fa4-587f-ba78-cda4478f9cc1"	
    
    strings:		
        $win2003_win7_u1 = "svchost.exe" wide nocase		
        $win2003_win7_u3 = "coinitializesecurityparam" wide fullword nocase		
        $win2003_win7_u4 = "servicedllunloadonstop" wide fullword nocase		
        $win2000 = "Generic Host Process for Win32 Services" wide fullword		
        $win2012 = "Host Process for Windows Services" wide fullword	
    
    condition:		
        filename=="svchost.exe" and uint16(0)==0x5a4d and not 1 of ($win*) and not WINDOWS_UPDATE_BDC
}

rule iexplore_ANOMALY{	
    meta:		
        author = "Florian Roth (Nextron Systems)"		
        description = "Abnormal iexplore.exe - typical strings not found in file"		
        date = "23/04/2014"		
        score = 55		
        nodeepdive = 1		
        id = "ea436608-d191-5058-b844-025e48082edc"	
    
    strings:		
        $win2003_win7_u1 = "IEXPLORE.EXE" wide nocase		
        $win2003_win7_u2 = "Internet Explorer" wide fullword		
        $win2003_win7_u3 = "translation" wide fullword nocase		
        $win2003_win7_u4 = "varfileinfo" wide fullword nocase	
        
    condition:		
        filename=="iexplore.exe" and uint16(0)==0x5a4d and not filepath contains "teamviewer" and not 1 of ($win*) and not WINDOWS_UPDATE_BDC and filepath contains "C:\\" and not filepath contains "Package_for_RollupFix"
}