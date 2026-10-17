import os
import shutil
import sys


source, target, *args = sys.argv[1:]
shutil.copytree("/input", "/work", dirs_exist_ok=True, copy_function=shutil.copy2)
os.execv("/usr/bin/python3", ["/usr/bin/python3", "/work/" + target, *args])