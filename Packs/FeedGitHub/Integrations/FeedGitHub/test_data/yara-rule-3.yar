rule Agent_BTZ_Proxy_DLL_2 {
   meta:
      description = "Lorem ipsum"
      author = "edge case"
      reference = "http://www.test.test.test"
      date = "2017-08-07"
      hash1 = "73db4295c5b29958c5d93c20be9482c1efffc89fc4e5c8ba59ac9425a4657a88"
      hash2 = "380b0353ba8cd33da8c5e5b95e3e032e83193019e73c71875b58ec1ed389bdac"
      hash3 = "f27e9bba6a2635731845b4334b807c0e4f57d3b790cecdc77d8fef50629f51a2"
      id = "2777443d-6f63-5948-855a-e064a6e0310f"
   strings:
      $s1 = { 38 21 38 2C 38 37 38 42 38 4D 38 58 38 63 38 6E
               38 79 38 84 38 8F 38 9A 38 A5 38 B0 38 BB 38 C6
               38 D1 38 DC 38 E7 38 F2 38 FD 38 08 39 13 39 1E
               39 29 39 34 39 3F 39 4A 39 55 39 60 39 6B 39 76
               39 81 39 8C 39 97 39 A2 39 AD 39 B8 39 C3 39 CE
               39 D9 39 E4 39 EF 39 FA 39 05 3A 10 3A 1B 3A 26
               3A 31 3A 3C 3A 47 3A 52 3A 5D 3A 68 3A 73 3A 7E
               3A 89 3A 94 3A 9F 3A AA 3A B5 3A C0 3A CB 3A D6
               3A E1 3A EC 3A F7 3A }
      $s2 = "activeds.dll" ascii fullword
   condition:
      uint16(0) == 0x5a4d and filesize < 200KB and all of them and pe.imphash() == "09b7c73fbe5529e6de7137e3e8268b7b"
}