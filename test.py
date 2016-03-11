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
import Cookie
import errno
import logging
from IPy import IP

# We use tests to  persist things that must exist between tests
class Test(object):
    def __init__(self,subTests,metaData):
        self.subTests = subTests
        self.meta = metaData
        self.cookieJar = []


    def runTests(self):
        '''
            Name: runTests
            Description: Run tests extracted from YAML.
            Parameters: None.
            Return: Nothing.
        '''
        print "Running",
        try:
            print str(self.meta["name"]) 
        except KeyError:
            print "Test Unnamed"
        httpOut = ""
        domain = ""
        for subTest in self.subTests: 
            if(subTest.getType() == "Request"):
                httpOut = ""
                request = ""
                domain  = ""
                httpOut = subTest.rawHTTP(self.cookieJar)
                domain = subTest.host

            if(subTest.getType() == "Response"):
                if(httpOut == ""):
                    return returnError("Seems like there was no HTTP response")
                # Set the previous requests response data for our response
                subTest.setRawData(httpOut)
                subTest.parseHTTP(self.cookieJar,domain)


    def getCurlCommands(self):
        '''
            Name: getCurlCommands
            Parameters: None.
            Return: Result of gencurl
        '''
        for subTest in self.subTests:
            if(subTest.getType() == "Request"):
                return subTest.genCurl()

class TestRequest(object):

    def __init__(self,rawRequest="", protocol="http",addr="www.example.com",port=80,method="GET",url="/",version="HTTP/1.1",headers={},data="",status=200):
        if(headers == {}):
            headers["Host"] = addr
            headers["User-Agent"] = "OWASP CRS Regression Tests"
        try:
            port = int(port)
        except ValueError:
            returnError("An invalid port value was entered in our YAML")

        self.protocol = protocol
        self.host = addr
        self.port = int(port)
        self.method = method
        self.url = url
        self.data = data
        self.headers = headers
        self.version = version
        self.rawRequest = rawRequest

        if('cookie' in headers.keys()): # If cookie is true, we need to check the cookiejar.
            if(headers['cookie']==True):
                pass

    def getType(self):
        return "Request"

    def printTest(self):
        print self.url
        #for ch in request:
        #    print ord(ch),
        #    if(ord(ch)==10):
        #        print    

    def setRequestURI(self):
        print "XYZ"

    def setHeaders(self):
        self.headers = "X"
        
    # Cookie can be set in headers or here.
    def setCookie(self):
        print "XYZ"

    def getRequest(self):
        return self.rawRequest

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

    def findCookie(self,cookieJar,originDomain):
        for cookie in cookieJar:
            cookieDomain = cookie[1]
            for cookieName, cookieMorsals in cookie[0].iteritems():
                coverDomain = cookieMorsals['domain']
                if coverDomain == "":
                    if(originDomain == cookie[1]):
                        return cookie[0]
                else:
                    # Domain match algorithm 
                    B = coverDomain.lower()
                    HDN = originDomain.lower()
                    NEnd = HDN.find(B)
                    if(NEnd != False):
                        return cookie[0]
        return False


    def rawHTTP(self,cookieJar):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(5)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.connect((self.host, self.port))
        except socket.error as msg:
            return returnError(msg)
        CRLF = "\r\n"
        # If they requested raw HTTP just provide it
        if(self.rawRequest != ""):
            request = self.rawRequest
            request = request.replace("\n",CRLF)
            request += CRLF  
        # Otherwise build our build our request
        else:
            request = '#method# #url##version#%s#headers#%s#data#' % (CRLF,CRLF)
            request = string.replace(request,"#method#",self.method)
            # We add a space after here to account for HEAD requests with no url
            request = string.replace(request,"#url#",self.url+" ")
            request = string.replace(request,"#version#",self.version)
            # Check if we have a cookie that needs using
            cookie = self.findCookie(cookieJar,self.host)
            # If the user has requested a tracked cookie and we have one set it
            if( 'Cookie' in self.headers.keys()):
                if(cookie != False and self.headers['Cookie'] == True):
                    print "\tAdded cookie from previous request"
                    self.headers["Cookie"] = cookie.output() 
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
        # Update our raw request with the generated one
        self.rawRequest = request
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
        self.request = ""
        self.domain = ""

    def setRequestData(self,request):
        self.request = request

    def setRawData(self,data):
        self.rawData = data

    def checkForCookie(self,cookie,originDomain):
        #http://bayou.io/draft/cookie.domain.html
        # Check if our originDomain is an IP
        originIsIP = True
        try:
            IP(originDomain)
        except:
            originIsIP = False

        for cookieName, cookieMorsals in cookie.iteritems():
            # If the coverdomain is blank or the domain is an IP set the domain to be the origin
            if(cookieMorsals['domain'] == "" or originIsIP == True):
                # We want to always add a domain so it's easy to parse later
                return (cookie,originDomain)
            # If the coverdomain is set it can be any subdomain
            else:
                coverDomain = cookieMorsals['domain']
                # strip leading dots
                # Find all leading dots not just first one
                # http://tools.ietf.org/html/rfc6265#section-4.1.2.3
                firstNonDot = 0
                for i in range(len(coverDomain)):
                    if(coverDomain[i] != '.'):
                        firstNonDot = i
                        break
                coverDomain = coverDomain[i:]
                # We must parse the coverDomain to make sure its not in the suffix list
                with open('public_suffix_list.dat','r') as f:
                    for line in f:
                        if line[:2] == "//" or line[0] == " " or line[0].strip() == "":
                            continue
                        if coverDomain == line.strip():
                            return False
                # Generate Origin Domain TLD
                i = originDomain.rfind(".")
                oTLD = originDomain[i+1:]
                # if our cover domain is the origin TLD we ignore
                # Quick sanity check
                if(coverDomain == oTLD):
                    return False
                # check if our coverdomain is a subset of our origin domain
                # Domain match (case insensative)
                if coverDomain == originDomain:
                    return (cookie,originDomain)
                # Domain match algorithm 
                B = coverDomain.lower()
                HDN = originDomain.lower()
                NEnd = HDN.find(B)
                if(NEnd != False):
                    N = HDN[0:NEnd]
                    # Modern browsers don't care about dot
                    if(N[-1]=='.'):
                        N = N[0:-1]
                else:
                    # We don't have an address of the form 
                    return False
                if N == "":
                    return False
                # Doesn't seem to be applicable anymore
                #if('.' in N):
                #    print "FAIL3"
                #    sys.exit()
                # cookieMorsals['domain'] = coverDomain 
                return (cookie,originDomain)



    def parseHTTP(self,cookieJar,originDomain):
        response = self.rawData.split("\r\n")
        (version,status,statusMsg) = response[0].split(" ",2)
        if(int(self.status) != int(status)):
            print "\tTest Failed: " + str(self.status),"-",str(status)
        # We start at line 1 because line zero is our status
        currentLine = 1
        headers = {}
        # We're going to get back an empty line, but strictly its \r\n
        while(response[currentLine] != "\r\n" and response[currentLine] != ""):
            (hName,hValue) = response[currentLine].split(":",1)
            headers[hName] = hValue.strip()
            currentLine +=1
            # If there is a set-cookie header try processing it.
            if(hName == "Set-Cookie" and self.saveCookie==True):
                hValue = "Test=test_value;expires=Sat, 01-Jan-2000 00:00:00 GMT; domain=chaimsanders.com; path=/;"
                try:
                    cookie = Cookie.SimpleCookie() 
                    cookie.load(hValue.lstrip())
                except Cookie.CookieError:
                    return returnError("There was an error processing the cookie into a SimpleCookie")
                # if the checkForCookie is invalid then we don't save it
                if(self.checkForCookie(cookie,originDomain) == False):
                    return returnError("An invalid cookie was specified")
                else:
                    cookieJar.append((cookie,originDomain))

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
                headers[header[0].title()] = header[1]
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
                    testData.append(extractOutputTests(outputTestValues))
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

def extractOutputTests(outputTestValues):
    x = []
    # From the YAML generate the constructor args
    responseArgs = {}
    # if we have an empty input create default constructor
    if outputTestValues == None:
        myRes = TestResponse(**responseArgs)
        return myRes
    # Otherwise we have input values
    for name,value in outputTestValues.iteritems():
        responseArgs[name] = value
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
    
