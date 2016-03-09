#!/usr/bin/python
'''
    Authors: Chaim Sanders, Jared Stroud 
'''
import yaml # We reqire pyYaml
import sys
import os
import socket
import time
import string
import requests
import cookielib
import errno

# We use tests to  persist things that must exist between tests
class Test(object):
    def __init__(self,subTests,metaData):
        self.subTests = subTests
        self.meta = metaData
        jar = cookielib.CookieJar()
        self.httpOut = ""

    def runTests(self):
        print "Running Test", str(self.meta)
        for subTest in self.subTests: 
            if(subTest.getType() == "Request"):
                self.httpOut = ""
                self.httpOut = subTest.rawHTTP()
            if(subTest.getType() == "Response"):
                if(self.httpOut == ""):
                    return returnError("Seems like there was no HTTP response")
                subTest.setRawData(self.httpOut)
                subTest.parseHTTP()


    def getCurlCommands(self):
        for subTest in self.subTests:
            if(subTest.getType() == "Request"):
                subTest.genCurl()

class TestRequest(object):
    def __init__(self,protocol="http",addr="www.example.com",port=80,method="GET",url="/",version="HTTP/1.1",headers={},data="",status=200):
        try:
            port = int(port)
        except ValueError:
            returnError("An invalid port value was entered in our YAML")
        self.protocol = protocol
        self.addr = addr
        self.port = int(port)
        self.method = method
        self.url = url
        self.data = data
        self.headers = headers
        self.version = version
        # if cookie is true then we need to check the cookiejar
        if('cookie' in headers.keys()):
            if(headers['cookie']==True):
                pass

    def getType(self):
        return "Request"

    def printTest(self):
        print self.url

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
            self.sock.settimeout(5)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.connect((self.addr, self.port))
        except socket.error as msg:
            return returnError(msg)
        CRLF = "\r\n"
        request = '#method# #url##version#%s#headers#%s#data#' % (CRLF,CRLF)
        request = string.replace(request,"#method#",self.method)
        # We add a space after here to account for HEAD requests with no url
        request = string.replace(request,"#url#",self.url+" ")
        request = string.replace(request,"#version#",self.version)
        # Expand out our headers into a string
        headers = ""
        if self.headers != {}:
            for hName,hValue in self.headers.iteritems():
                headers += str(hName)+": "+str(hValue) + str(CRLF)
        request = string.replace(request,"#headers#",headers)
        # If we have data append it
        if(self.data != ""):
            data = str(self.data) + str(CRLF)
            request = string.replace(request,"#data#",data)
        else:
            request = string.replace(request,"#data#","")
        self.sock.send(request)
        #make socket non blocking
        self.sock.setblocking(0)      
        #total data partwise in an array
        ourData=[];
        data='';
        timeout=.3
        #beginning time
        begin=time.time()
        while True:
            #If we have data then if we're passed the timeout break
            if ourData and time.time()-begin > timeout:
                break     
            #if we're dataless wait just a bit
            elif time.time()-begin > timeout*2:
                break
            #recv data
            try:
                data = self.sock.recv(8192)
                if data:
                    ourData.append(data)
                    begin=time.time()
                else:
                    #sleep for sometime to indicate a gap
                    time.sleep(0.2)
            except socket.error as e:
                # Check if we got a timeout
                if(e.errno == errno.EAGAIN):
                    pass
                # If we didn't it's an error
                else:
                    return returnError(e)
        data = ''.join(ourData)
        self.sock.shutdown(1)
        self.sock.close()
        return data

class TestResponse(object):
    def __init__(self,status="200",saveCookie=False):
        self.status = status
        self.saveCookie = saveCookie
        self.rawData = ""

    def setRawData(self,data):
        self.rawData = data

    def parseHTTP(self):
        response = self.rawData.split("\r\n")
        (version,status,statusMsg) = response[0].split(" ",2)
        if(self.status != status):
            print "FAILED"
        # We start at line 1 because line zero is our status
        currentLine = 1
        headers = {}
        # We're going to get back an empty line, but strictly its \r\n
        while(response[currentLine] != "\r\n" and response[currentLine] != ""):
            (hName,hValue) = response[currentLine].split(":",1)
            headers[hName] = hValue.strip()
            currentLine +=1
        



    def getType(self):
        return "Response"

    def printTest(self):
        print self.saveCookie

def returnError(errorString):
        errorString = str(errorString) + os.linesep
        sys.stderr.write(errorString)
        sys.exit(1)

def extractInputTests(inputTestValues):
    requestArgs = {} # Generate constructor args.
    headers = {} # Create default constructors...
    if inputTestValues == None:
        myReq = TestRequest(**requestArgs)
        return myReq
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
        return myReq
    except TypeError:
        # Almost for sure they passed an invalid name, check the args of Request
        return returnError("An invalid argument was passed to the Request constructor, \
                            check your arugments " + str(requestArgs.keys()))

#def extractMetaTests(metaTestValues):
#    return metaTestValues

def extractTests (doc):
    myTests = []
    # Iterate over the different 'named tests' (AKA YAML sections)
    for section,tests in doc.iteritems(): 
        # Within each YAML section look at each 'test'
        for test in tests:
            ourTest = test['test']
            testData = []
            metaData = {}
            for transactions in ourTest:
                # See if we have an input transaction or input
                if('input' in transactions.keys()):
                    inputTestValues = transactions["input"]
                    # For each Test extract all the input requests
                    testData.append(extractInputTests(inputTestValues))
                elif('output' in transactions.keys()):
                    outputTestValues = transactions["output"]
                    testData.append(extractOutputTests(inputTestValues))
                elif('meta' in transactions.keys()):
                    metaData = transactions["meta"]
                else:  
                    return returnError("No input/output was found, please specify at least an empty input and out for defaults")     
            # sanity check to ensure even number of in's and out's
            requests = 0
            responses = 0
            for i in testData:
                if(i.__class__.__name__ == "TestRequest"):
                    requests += 1
                if(i.__class__.__name__ == "TestResponse"):
                    responses += 1
            if(requests != responses):
                return returnError("No input/output was found, please specify at least an empty input and out for defaults")
            myTest = Test(testData,metaData)
            myTests.append(myTest)
    return myTests

def extractOutputTests(inputTestValues):
    x = []
    # From the YAML generate the constructor args
    responseArgs = {}
    # if we have an empty input create default constructor
    if inputTestValues == None:
        myRes = TestResponse(**responseArgs)
        return myRes
    # Otherwise we have input values
    for name,value in inputTestValues.iteritems():
        #print name,value
        pass
    try:
        myRes = TestResponse(**responseArgs) # Try to generate a request.
        return myRes
    except TypeError:
        # Almost for sure they passed an invalid name, check the args of Request
        return returnError("An invalid argument was passed to the Response constructor, \
                            check your arugments " + str(responseArgs.keys()))

def getYAMLData(filePath="."):
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
    return yamlFiles

def main():
    myTests = []
    #TODO: allow for input of where directory is. argparse?
    yamlFiles = getYAMLData()
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
        myTests = extractTests(doc)
        #TODO: check arguments to see what to do
        for test in myTests:
            test.runTests()

if __name__ == "__main__":
    main()
