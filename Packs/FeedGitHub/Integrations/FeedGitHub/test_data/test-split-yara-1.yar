/*
   Yara Rule Set
   Author: Lorem Ipsum
   Date: 2018-03-10
   Identifier: Lorem Ipsum Report
   Reference: https://example.com
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule Lorem_Malware_Mar18_Rule1 {
   meta:
      description = "Detects malware from Lorem Ipsum report"
      license = "Detection Rule License 1.1 https://example.com/license"
      author = "Lorem Ipsum (Example Systems)"
      reference = "https://example.com"
      date = "2018-03-10"
      hash1 = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
      id = "12345678-1234-1234-1234-1234567890ab"
   strings:
      $s1 = "\\Release\\LoremCli.pdb" ascii
      $s2 = "%snewcmd.exe" fullword ascii
      $s3 = "Run cmd error %d" fullword ascii
      $s4 = "%s~loremtmp%08x.ini" fullword ascii
      $s5 = "run file failed" fullword ascii
      $s6 = "Cmd timeout %d" fullword ascii
      $s7 = "2 %s  %d 0 %d" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and 2 of them
}

rule Lorem_Malware_Mar18_Rule2 {
   meta:
      description = "Detects malware from Lorem Ipsum report"
      license = "Detection Rule License 1.1 https://example.com/license"
      author = "Lorem Ipsum (Example Systems)"
      reference = "https://example.com"
      date = "2018-03-10"
      hash1 = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
      id = "abcdef12-3456-7890-abcd-ef1234567890"
   strings:
      $x1 = "del c:\\windows\\temp\\r.exe /f /q" fullword ascii
      $x2 = "%s\\r.exe" fullword ascii

      $s1 = "rights.dll" fullword ascii
      $s2 = "\"%s\">>\"%s\"\\s.txt" fullword ascii
      $s3 = "Nwsapagent" fullword ascii
      $s4 = "%s\\r.bat" fullword ascii
      $s5 = "%s\\s.txt" fullword ascii
      $s6 = "runexe" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and (
        ( pe.exports("RunInstallA") and pe.exports("RunUninstallA") ) or
        1 of ($x*) or
        2 of them
      )
}

rule Lorem_Malware_Mar18_Rule3 {
   meta:
      description = "Detects malware from Lorem Ipsum report"
      license = "Detection Rule License 1.1 https://example.com/license"
      author = "Lorem Ipsum (Example Systems)"
      reference = "https://example.com"
      date = "2018-03-10"
      hash1 = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
      id = "abcdef12-3456-7890-abcd-ef1234567890"
   strings:
      $x1 = "AAAAKQAASCMAABi+AABnhEBj8vep7VRoAEPRWLweGc0/eiDrXGajJXRxbXsTXAcZAABK4QAAPWwAACzWAAByrg==" fullword ascii
      $x2 = "AAAAKQAASCMAABi+AABnhKv3kXJJousn5YzkjGF46eE3G8ZGse4B9uoqJo8Q2oF0AABK4QAAPWwAACzWAAByrg==" fullword ascii

      $a1 = "http://%s/content.html?id=%s" fullword ascii
      $a2 = "http://%s/main.php?ssid=%s" fullword ascii
      $a3 = "http://%s/webmail.php?id=%s" fullword ascii
      $a9 = "http://%s/error.html?tab=%s" fullword ascii

      $s1 = "%s\\~tmp.txt" fullword ascii
      $s2 = "%s /C %s >>\"%s\" 2>&1" fullword ascii
      $s3 = "DisableFirstRunCustomize" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and (
         1 of ($x*) or
         2 of them
      )
}

rule Lorem_Malware_Mar18_Rule4 {
   meta:
      description = "Detects malware from Lorem Ipsum report"
      license = "Detection Rule License 1.1 https://example.com/license"
      author = "Lorem Ipsum (Example Systems)"
      reference = "https://example.com"
      date = "2018-03-10"
      hash1 = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
      id = "abcdef12-3456-7890-abcd-ef1234567890"
   strings:
      $s1 = "\\Release\\LoremTool.pdb" ascii
      $s2 = "LoremTool.exe" fullword wide
      $s3 = "Microsoft.Lorem.WebServices.Data" fullword ascii
      $s4 = "tmp.dat" fullword wide
      $s6 = "/v or /t is null" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 40KB and all of them
}

/*
   Identifier: Lorem = Ipsum = Dolor
   Author: Lorem Ipsum Group
           Revised by Lorem Ipsum for performance reasons
           see https://example.com
           > some rules were untightened
   Date: 2018-03-09
   Reference: https://example.com
*/

rule clean_lorem_patchedcmd {
   meta:
      author = "Lorem Ipsum"
      description = "This is a patched CMD. This is the CMD that LoremCli uses."
      sha256 = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
      id = "abcdef12-3456-7890-abcd-ef1234567890"
   strings:
      $ = "disableCMD" wide
      $ = "%WINDOWS_COPYRIGHT%" wide
      $ = "Cmd.Exe" wide
      $ = "Windows Command Processor" wide
   condition:
      uint16(0) == 0x5A4D and all of them
}

rule malware_lorem_royalcli_1 {
   meta:
      description = "Generic strings found in the Lorem CLI tool"
      author = "Lorem Ipsum"
      sha256 = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
      id = "abcdef12-3456-7890-abcd-ef1234567890"
   strings:
      $ = "%s~loremtmp%08x.tmp" fullword
      $ = "%s /c %s>%s" fullword
      $ = "%snewcmd.exe" fullword
      $ = "%shkcmd.exe" fullword
      $ = "%s~loremtmp%08x.ini" fullword
      $ = "myRObject" fullword
      $ = "myWObject" fullword
      $ = "2 %s  %d 0 %d\x0D\x0A"
      $ = "2 %s  %d 1 %d\x0D\x0A"
      $ = "%s file not exist" fullword
   condition:
      uint16(0) == 0x5A4D and 5 of them
}

rule malware_lorem_royalcli_2 {
   meta:
      author = "Lorem Ipsum"
      description = "Lorem RoyalCli backdoor"
      id = "abcdef12-3456-7890-abcd-ef1234567890"
   strings:
      $string1 = "%shkcmd.exe" fullword
      $string2 = "myRObject" fullword
      $string3 = "%snewcmd.exe" fullword
      $string4 = "%s~loremtmp%08x.tmp" fullword
      $string6 = "myWObject" fullword
   condition:
      uint16(0) == 0x5A4D and 2 of them
}