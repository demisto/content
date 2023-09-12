rule zeus_js : EK
{
  meta:
	author = "TEST1"
	date = "2016-06-26"
	description = "test"
	hash0 = ""
	sample_filetype = ""
	yaragenerator = ""
  strings:
	$string0 = "string_pattern_0"
  condition:
	14 of them
}
rule vbs_sins_yuge_arrays : vbs qakbot
{
  meta:
    description = ""
    date = "2019-09-15"
    author = ""
    greetz = ""
    samples = ""
    tlp = ""
    prod = ""
  strings:
    $string1 = "string_pattern_1"
    $string2 = "string_pattern_2"
   condition:
    all of them
}
