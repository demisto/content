import re

def is_date_valid(date: str):
	"""
	The method checks whether the date supplied is valid. 
	The SecurityScorecard API requires the date to be in YYYY-MM-DD format.
	"""

#     regex = r'2[0-9][0-9][0-9]-(0[1-9]|1[0-2])-(0[1-9]|1[0-9]|2[0-9]|3[0-1])"'

	regex = r'[1-3]\d{3}-(0[1-9]|1[0-2])-(0[1-9]|1[0-9]|2[0-9]|3[0-1])'

	if date == None:
		return True

	if(re.match(regex, date)):
		return True
	else:
		return False

print("is_date_valid: {0}".format(is_date_valid("3021-12-31")))

print("2011-06-24" < "2010-06-23")