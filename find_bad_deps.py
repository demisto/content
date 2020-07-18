import os
from demisto_sdk.commands.common.tools import run_command

bad_deps = []

for pack in os.listdir('Packs'):
    result = run_command("./run_deps.sh " + pack)
    lines = result.split('\n')
    for line in lines:
        if not line.startswith('Found bad'):
            continue
        line = line.replace('Found bad dependency ', '').replace(' for pack ', ',').replace(' in test playbook ', ',').replace('!', '')
        results = line.split(',')
        bad_deps.append(results)

print('--------------------------------------')
print('--------------------------------------')
print('--------------------------------------')
print('--------------------------------------')
for bad_dep in bad_deps:
    print(bad_dep)
