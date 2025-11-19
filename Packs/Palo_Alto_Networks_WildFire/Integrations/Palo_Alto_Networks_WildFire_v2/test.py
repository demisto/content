import requests
import re

# Configuration
api_key = '<YOUR_API_KEY>'
file_hash = 'afe6b95ad95bc689c356f34ec8d9094c495e4af57c932ac413b65ef132063acc'
url = 'https://wildfire.paloaltonetworks.com/publicapi/get/sample'

# Prepare the payload (equivalent to -F)
payload = {
    'apikey': api_key,
    'hash': file_hash
}

try:
    # Make the request
    # stream=True is recommended for downloading files to avoid loading them into RAM
    response = requests.post(url, data=payload, stream=True)

    # Check if the request was successful
    if response.status_code == 200:
        
        # 1. Attempt to get filename from Content-Disposition header (Equivalent to -J)
        d = response.headers.get('content-disposition')
        if d:
            fname = re.findall("filename=(.+)", d)[0].strip('"')
        else:
            fname = f"{file_hash}.sample" # Fallback filename

        # 2. Write the file to disk (Equivalent to -O)
        with open(fname, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        
        print(f"Success: Downloaded as {fname}")
        
    elif response.status_code == 404:
        print("Error 404: The file hash was not found in WildFire.")
    elif response.status_code == 403:
        print("Error 403: Access denied. The file is likely 'Benign' and cannot be downloaded.")
    else:
        print(f"Error {response.status_code}: {response.text}")

except Exception as e:
    print(f"An error occurred: {e}")