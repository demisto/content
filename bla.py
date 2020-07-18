out = ''
with open('./output.txt', 'r') as file:
    f = file.readlines()
    for line in f:
        if not line.startswith('Found bad'):
            continue
        out += line.replace('Found bad dependency ', '').replace(' for pack ', ',').replace(' in test playbook ', ',').replace('!', '') + '\n'

    with open('./output2.txt', 'w') as f:
        f.write(out)
