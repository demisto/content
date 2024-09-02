rule Lorem_Ipsum {
   meta:
      description = "broking yara rule test"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Lorem ipsum"
      reference = "https://www."
      date = "2022-02-07"
      hash1 = "fc5a58bf0fce9cb96f35ee76842ff17816fe302e3164bc7c6a5ef46f6eff67ed"
      id = "039e5d41-eadb-5c53-82cd-20ffd4105326"
   strings:
      $lznt1_compressed_pe_header_small = { FC B9 00 4D 5A 90 } // This is the lznt1 compressed PE header

      $lznt1_compressed_pe_header_large_1 = { FC B9 00 4D 5A 90 00 03 00 00 00 82 04 00 30 FF FF 00 } 
      $lznt1_compressed_pe_header_large_2 = { 00 b8 00 38 0d 01 00 40 04 38 19 00 10 01 00 00 }
      $lznt1_compressed_pe_header_large_3 = { 00 0e 1f ba 0e 00 b4 09 cd 00 21 b8 01 4c cd 21 }
      $lznt1_compressed_pe_header_large_4 = { 54 68 00 69 73 20 70 72 6f 67 72 00 61 6d 20 63 }
      $lznt1_compressed_pe_header_large_5 = { 61 6e 6e 6f 00 74 20 62 65 20 72 75 6e 00 20 69 }
      $lznt1_compressed_pe_header_large_6 = { 6e 20 44 4f 53 20 00 6d 6f 64 65 2e 0d 0d 0a 02 }