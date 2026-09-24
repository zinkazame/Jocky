path = r"D:\Dinku\projects\JOCKY\management_interface\agent_controller.py"
with open(path, "r", encoding="utf-8") as f:
    c = f.read()

bootstrap = '''import sys as _sys, pathlib as _pl
_ROOT = _pl.Path(__file__).resolve().parent.parent
if str(_ROOT) not in _sys.path:
    _sys.path.insert(0, str(_ROOT))
'''

# insert after the first docstring / module-level comment block
# find the line with "from __future__" and insert before it
target = "from __future__ import annotations"
c = c.replace(target, bootstrap + target, 1)

with open(path, "w", encoding="utf-8") as f:
    f.write(c)
print("[+] path bootstrap added to agent_controller.py")

# verify
for i, line in enumerate(open(path, encoding="utf-8")):
    if "_ROOT" in line and "parent.parent" in line:
        print(f"  line {i+1}: {line.rstrip()}")
        break