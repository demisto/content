import sys

slug = sys.argv[1]
title = sys.argv[2]
p = "unified-connectors-content/CODEOWNERS"
lines = open(p).read().splitlines(keepends=True)
out = [l for l in lines if slug not in l and l.strip() != f"# {title}"]
open(p, "w").writelines(out)
print(f"cleaned CODEOWNERS, removed {len(lines) - len(out)} lines for {slug}")
