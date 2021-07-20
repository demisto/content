/* Deep Panda APT */

rule DeepPanda_sl_txt_packed {
	meta:
		description = "Test1"
		license = "https://test.org/4.0/"
		author = "TEST1"
		date = "2015/02/08"
		hash = "12345678ABCD"
	strings:
		$s0 = "Command line port scanner" fullword wide
		$s1 = "sl.exe" fullword wide
		$s2 = "CPttpo.txt" fullword ascii
	condition:
		all of them
}

rule DeepPanda_lot1 {
	meta:
		description = "Test2"
		license = "https://test2.org/4.0/"
		author = "TEST2"
		date = "2015/02/08"
		hash = "18273645ACDB"
	strings:
		$s0 = "Unable to open target process: %d, pid %d" fullword ascii
		$s1 = "Couldn't delete target executable from remote machine: %d" fullword ascii
	condition:
		2 of them
}
