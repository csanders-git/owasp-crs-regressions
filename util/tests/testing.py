import os
testFile = "../test.py"
os.system("pep8 --first " + testFile)
os.system("pyflakes " + testFile)
#os.system("pylint testing.py --rcfile=standard.rc")
