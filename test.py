import base64
file_data = ''

attach_data = 'sds,sd,sd,sd'


try:



    attach_data = attach_data.encode('ascii') + b'=' * (-len(attach_data) % 4)

    file_data = base64.urlsafe_b64decode(attach_data)
    file_data = base64.urlsafe_b64decode(attach_data.encode('ascii'))
except TypeError as e:
    if str(e) == 'Incorrect padding':
        file_data = attach_data.encode('ascii')

print(file_data)



