#!/usr/bin/python
'''
    Authors: Chaim Sanders, Jared Stroud 
'''
import yaml # We reqire pyYaml
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
        self.cookie = ""

    def setRequestURI(self):
        print "XYZ"

    def setHeaders(self):
        self.headers = "X"
        
    # Cookie can be set in headers or here.
    def setCookie(self):
        print "XYZ"

    def setData():
        print "XYZ"

    def genCurl(self):
        command = "curl %s%s \\%s" % (self.host,self.url,os.linesep)
        command += "-X %s \\%s" % (self.method, os.linesep)
        command += "--cookie %s \\%s" % (self.cookie, os.linesep)
        if(len(self.headers) != 0):
            for headerName, headerValue in self.headers.iteritems():
                #TODO: Escape quotes in headername and headervalue
                command += '--header "%s: %s" \\%s' % (headerName, headerValue, os.linesep)
        command = command[:-2]
        return command

    def rawHTTP(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(15)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.connect((self.addr, self.port))
            #s.setblocking(0)
        except socket.error as msg:
            return returnError(msg)
        CRLF = "\r\n"
        
        s.connect(("www.chaimsanders.com", 80))
        s.send("GET / HTTP/1.1%sHost: chaimsanders.com%sUser-Agent: test%s%s" % (CRLF,CRLF,CRLF,CRLF))
        data = (s.recv(1000000))
        #print data
        s.shutdown(1)
        s.close()

    def issueRequest(self):
        req = requests.Request(self.method,'http://stackoverflow.com',headers=self.headers,data=self.data)
        print req.method
        prepared = req.prepare()
        s = requests.Session()
        resp = s.send(prepared)
        print resp.status_code

class TestResponse(object):
    def __init__(self,method="GET"):
        self.method = method
        self.cookie = ""

def returnError(errorString):
        errorString = str(errorString) + os.linesep
        sys.stderr.write(errorString)
        sys.exit(1)

def extractInputTests(doc):
    myTests = []
    for section,tests in doc.iteritems(): # Iterate over YAML sections.
        for test in tests: # Extract test cases from Yaml file.
            try:
                inputTestValues = test["test"]["input"]
            except:
                return returnError("No input was found, please specify at least an empty input for defaults")        
            requestArgs = {} # Generate constructor args.
            headers = {} # Create default constructors...
            if inputTestValues == None:
                myReq = TestRequest(**requestArgs)
                continue
            for name,value in inputTestValues.iteritems(): # Otherwise we have input values.
                if(name == "headers"): # Check if we get a header if so make it into a dict.
                    for header in value: # Process YAML list of dicts into just a dictionary.
                        header = header.popitem()
                        headers[header[0]] = header[1]
                else:
                    requestArgs[name] = value
            requestArgs ["headers"] = headers # Now that our headers is populated, push it!
            try:
                myReq = TestRequest(**requestArgs) # Try to generate a request.
            except TypeError:
                # Almost for sure they passed an invalid name, check the args of Request
                return returnError("An invalid argument was passed to the Request constructor, \
                                    check your arugments " + str(requestArgs.keys()))
            myTests.append(myReq)

    return myTests

def extractOutputTests(doc):
    x = []
    # Iterate over our YAML sections
    for section,tests in doc.iteritems():
        # For each section extract the tests
        for test in tests:
            try:
                inputTestValues = test["test"]["output"]
            except:
                return returnError("No output was found, please specify at least an empty output for defaults")        
            # From the YAML generate the constructor args
            requestArgs = {}
            headers = {}
            # if we have an empty input create default constructor
            if inputTestValues == None:
                #myReq = TestRequest(**requestArgs)
                continue
            # Otherwise we have input values
            for name,value in inputTestValues.iteritems():
                print name,value

def main():
    #TODO: allow for input of where directory is.
    filePath = "."
    myTests = []
    try:
        # Check if the path exists and we have read access
        if(os.path.exists(filePath) and os.access(filePath,os.R_OK)):
            pass
        else:
            return returnError("The YAML test folder specified could not be accessed")
    except OSError as e:
        return returnError("There was a problem accessing our YAML test folder. " + str(e))
    # List all the files in that directory that are yaml files
    # This will return either a list or error, list may be empty.
    try:
        yamlFiles = [f for f in os.listdir(filePath) if (os.path.isfile("/".join([filePath, f])) and f[-5:] == ".yaml")]
    except OSError as e:
        return returnError("There was an issue listing YAML files" + str(e))
    for testFile in yamlFiles:
        try:
            # Load our YAML file
            fd = open(testFile, 'r')
        except IOError as e:
            return returnError(str(e))
        try:
            # Process our YAML file
            doc = yaml.safe_load(fd)
        except yaml.YAMLError as e:
            return returnError(str(e))
        finally:
            fd.close()
        myTests += extractInputTests(doc)
        #for i in myTests:
        #    print i.genCurl()
        extractOutputTests(doc)
    #for i in myTests:
    #    i.rawHTTP()

if __name__ == "__main__":
    main()
