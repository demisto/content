from datetime import datetime

first_date = "2012-10-12"
second_date = "2024-09-23T13:40:03+03:00"
third_date = "2024-09-01T08:45:03+03:00"

def convert_date(date_str):
    try:
        date_obj = datetime.strptime(date_str, "%Y-%m-%d")
        return date_obj.isoformat() + "T00:00:00+00:00"
    except ValueError:
        try:
            datetime.fromisoformat(date_str)
            return None
        except ValueError:
            raise ValueError("Invalid date format provided.")

converted_first_date = convert_date(first_date)
converted_second_date = convert_date(second_date)
converted_third_date = convert_date(third_date)

print("Converted first date:", converted_first_date)  
print("Converted second date:", converted_second_date)  
print("Converted third date:", converted_third_date)  

