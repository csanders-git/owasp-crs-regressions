from log import Log
import sys

class ModSecurityv2(Log):
    def __init__(self):
        self.location = "/var/log/httpd/error_log"
        self.initalData = ""
        self.postTestData = ""
        self.testData = ""
        self.returnValues = {}
    def setLogFile(self,location):
        if(location is None):
            print "[Alert] The ModSecurityv2 Module should have a specified log file (use --log to specify) using the default RHEL Apache log location: /var/log/httpd/error_log"
        else:
            self.location= location
    def startLog(self):
        # Get our inital state
        with open(self.location, 'r') as f:
            self.initalData = f.read()
    def stopLog(self):
        with open(self.location, 'r') as f:
            self.postTestData = f.read()
        # Neive approach probably want to split on newline
        self.testData = self.postTestData.replace(self.initalData,"")
    def parseLog(self):
        out = self.testData.strip().split("\n")
        triggers = []
        # Iterate over each triggered rule (if any)
        for i in out:
            x = i.split(" [")
            # check for the ID from each of triggered rules
            for i in x:
                if(i[:-1][0:2] == "id"):
                    triggers.append(i[4:-2])
        self.returnValues["triggers"] = triggers
        self.returnValues["raw_data"] = self.testData.strip()
        
        
        
