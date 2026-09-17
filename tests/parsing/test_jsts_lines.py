import subprocess
import sys

SCRIPT = """
import gc
import dpr
from dpr.parsing import jsts

code = "\\n" * 600 + "call(1)\\n"
tree = jsts.parse_source("big.ts", code)
[node] = list(jsts.calls(tree, "call"))
lines = []
for i in range(3000):
    lines.append(jsts.line(tree, node))
    if i % 100 == 0:
        gc.collect()
print(lines[0], len(set(lines)))
"""


def test_line_numbers_past_256_do_not_corrupt_memory():
    result = subprocess.run(
        [sys.executable, "-c", SCRIPT], capture_output=True, text=True, timeout=60
    )
    assert result.returncode == 0, result.stderr[-500:]
    assert result.stdout.split() == ["601", "1"]
