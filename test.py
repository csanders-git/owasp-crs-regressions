import yaml
import sys
import os
import socket
import requests

class TestRequest(object):
    def __init__(self,method="GET",host="localhost",url="/",version="HTTP/1.1",headers={},data="",status=200):
        self.host = host
        self.method = method
        self.url = url
        self.data = data
        self.headers = headers
        self.version = version

    def genCurl(self):
        command = "curl %s%s \\%s" % (self.host,self.url,os.linesep)
        command += "-X %s \\%s" % (self.method, os.linesep)
        if(len(self.headers) != 0):
            for headerName, headerValue in self.headers.iteritems():
                #TODO: Escape quotes in headername and headervalue
                command += '--header "%s: %s" \\%s' % (headerName, headerValue, os.linesep)
        command = command[:-2]
        return command

    def rawHTTP(self):
        CRLF = "\r\n"
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(15)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        #s.setblocking(0)
        s.connect(("www.chaimsanders.com", 80))
        s.send("GET / HTTP/1.1%sHost: chaimsanders.com%sUser-Agent: test%s%s" % (CRLF,CRLF,CRLF,CRLF))
        data = (s.recv(1000000))
        print data
        s.shutdown(1)
        s.close()

    def issueRequest(self):
        req = requests.Request(self.method,'http://stackoverflow.com',headers=self.headers,data=self.data)
        print req.method
        prepared = req.prepare()
        s = requests.Session()
        resp = s.send(prepared)
        print resp.status_code

def returnError(errorString):
        errorString = str(errorString) + os.linesep
        sys.stderr.write(errorString)
        sys.exit(1)

def extractTests(doc):
    myTests = []
    # Iterate over our YAML sections
    for section,tests in doc.iteritems():
        # For each section extract the tests
        for test in tests:
            try:
                inputTestValues = test["test"]["input"]
            except:
                return returnError("No input was found, please specify at least an empty input for defaults")        
            # From the YAML generate the constructor args
            requestArgs = {}
            # if we have an empty input create default constructor
            if inputTestValues == None:
                myReq = TestRequest(**requestArgs)
                continue
            # Otherwise we have input values
            for name,value in inputTestValues.iteritems():
                requestArgs[name] = value
            try:
                # Try to generate a request
                myReq = TestRequest(**requestArgs);
            except TypeError:
                # Almost for sure they passed an invalid name, check the args of Request
                return returnError("An invalid argument was passed to the Request constructor, check your arugments " + str(requestArgs.keys()))
            myTests.append(myReq)
    return myTests

def main():
    try:
        # Load our YAML file
        fd = open('test.yaml', 'r')
    except IOError as e:
        return returnError(str(e))
    try:
        # Process our YAML file
        doc = yaml.safe_load(fd)
    except yaml.YAMLError as e:
        return returnError(str(e))
    finally:
        fd.close()
    myTests = extractTests(doc)
    for i in myTests:
        i.rawHTTP()

if __name__ == "__main__":
    main()
