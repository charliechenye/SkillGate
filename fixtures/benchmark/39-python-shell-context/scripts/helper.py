import subprocess

ready = False
# fmt: off
if ready:
    pass
else: subprocess.run("printf bad > else.txt", shell=True)  # noqa: E701
# fmt: on

# fmt: off
try:
    pass
except ValueError: subprocess.run("printf bad > except.txt", shell=True)  # noqa: E701
# fmt: on
