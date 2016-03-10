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
        print "Running Test", str(self.meta)
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

    def checkForCookie(self,cookieJar,originDomain):
        #http://bayou.io/draft/cookie.domain.html
        # Check if our originDomain is an IP
        originIsIP = True
        try:
            IP(originDomain)
        except:
            originIsIP = False

        # Check if a domain is specified
        for cookie in cookieJar:
            cookieDomain = cookie[1]
            print cookie[0].output()
            for cookieName, cookieMorsals in cookie[0].iteritems():
                # If the coverdomain is not set we only apply to origin domain
                if(cookieMorsals['domain'] == "" or originIsIP == True):
                    if(cookieDomain == originDomain):
                        print "GOT COOKIE"
                    else:
                        print "Not a cookie"
                # If the coverdomain is set it can be any subdomain
                else:
                    coverDomain = cookieMorsals['domain']
                    # strip leading dots
                    # TODO: Find all leading dots not just first one
                    if(coverDomain[0] == '.'):
                        coverDomain = coverDomain[1:]
                    # Logic taken from cookielib but really we need public suffix list
                    i = coverDomain.rfind(".")
                    sld = coverDomain[0:i]
                    tld = coverDomain[i+1:]

                    # If we find a 'public suffix' ignore coverDomain
                    if sld.lower() in ("co", "ac", "com", "edu", "org", "net",
                            "gov", "mil", "int", "aero", "biz", "cat", "coop",
                            "info", "jobs", "mobi", "museum", "name", "pro",
                            "travel", "eu") and len(tld) == 2:
                        if(cookieDomain == originDomain):
                            print "GOT COOKIE"
                        else:
                            print "note cookie"
                    # Generate Origin Domain TLD
                    i = originDomain.rfind(".")
                    oTLD = originDomain[i+1:]
                    # if our cover domain is the origin TLD we ignore
                    if(coverDomain == oTLD):
                        if(cookieDomain == originDomain):
                            print "GOT COOKIE"
                        else:
                            print "note cookie"
                               

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
            # Expand out our headers into a string
            headers = ""
            if self.headers != {}:
                for hName,hValue in self.headers.iteritems():
                    headers += str(hName)+": "+str(hValue) + str(CRLF)
            self.checkForCookie(cookieJar,self.host)
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

    def parseCookie(self,c):
        cook = c.output()
        #cookie = r'restricted_cookie=cookie_value; Domain=PyMOTW; Path=/sub/path; secure'
        #cook = cook.split(';')
        #for element in cook.split(":")



#expires
#path
#comment
#domain
#max-age
#secure
#version
#httponly

    def parseHTTP(self,cookieJar,originDomain):
        response = self.rawData.split("\r\n")
        (version,status,statusMsg) = response[0].split(" ",2)
        print self.status,"-",status
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
        # Append our given cookie
        #cook = "Test=test_value;expires=Sat, 01-Jan-2000 00:00:00 GMT; path=/;"
        #cook = 'expires_at_time=cookie_value; expires=Sat, 14 Feb 2009 19:30:14'
        cook = r'restricted_cookie=cookie_value; Domain=co.uk; Path=/sub/path; secure'
        try:
            cookie = Cookie.SimpleCookie() 
            cookie.load(cook)
            #print cookie.output()
        except Cookie.CookieError:
            print "ERROR"
        cookieJar.append((cookie,originDomain))





        # only the domain matters not the proto or port
            #if(hName == "Set-Cookie"):
            #Set-Cookie:
        '''
        cookie = 'encoded_value_cookie="value"; Comment=Notice that this cookie value has escaped quotes'
        
        
        

        HTTP_COOKIE = r'restricted_cookie=cookie_value; Domain=PyMOTW; Path=/sub/path; secure'
        try:
            cookie = Cookie.SimpleCookie() 
            cookie.load(HTTP_COOKIE)
        except Cookie.CookieError:
            print "ERROR"
        cookieJar.append(cookie)


'''
        #print 'cookie = ', cookie['restricted_cookie']['domain']  
        #cookie = 'with_max_age="expires in 5 minutes"; Max-Age=300'
        #HTTP_COOKIE = r'integer=5; string_with_quotes="He said, \"Hello, World!\""'
        
        #cookie = cookielib.Cookie(version=0, name='OLRProduct',
        #                          value='OLRProduct=xyz|',
        #                          port=None, port_specified=False,
        #                          domain='.dell.com',
        #                          domain_specified=True,
        #                          domain_initial_dot=True, path='/',
        #                          path_specified=True, secure=False,
        #                          expires=None, discard=True, comment=None,
        #                          comment_url=None, rest={'HttpOnly': None})
        #cookieJar.set_cookie(cookie)
        #for cookie in cookieJar:
        #    print('%s --> %s'%(cookie.name,cookie.value))
        #import urllib2
        #print help(cookieJar._cookies_for_domain)
        #req = urllib2.Request("dell.com")

        #print cookieJar.read_all_cookies()

        #cookies_by_path = self.cookies.get(domain)
        #if cookies_by_path is None:
        #    return []

        #cookies = []
        #for path in cookies_by_path.keys():
        #    if not self.policy.path_return_ok(path, request, unverifiable):
        #        continue
        #    for name, cookie in cookies_by_path[path].items():
        #        if not self.policy.return_ok(cookie, request, unverifiable):
        #            debug("   not returning cookie")
        #            continue
        #        debug("   it's a match")
        #        cookies.append(cookie)


        #print
        #print 'From load():'
        #c = Cookie.SimpleCookie()
        #c.load(HTTP_COOKIE)
        #print c.output("Domain")
        #self.parseCookie(c)
        #print c
        #try:
        #    c = Cookie.SimpleCookie(cookie)
        #except Cookie.CookieError:
        #    print "ERROR"
        #print c.keys()
        #cookieJar.set_cookie(c)
        #print c.output()
                #cookie = cookielib.Cookie(version=0, name='PON', value="xxx.xxx.xxx.111", expires=365, port=None, port_specified=False, domain='xxxx', domain_specified=True, domain_initial_dot=False, path='/', path_specified=True, secure=True, discard=False, comment=None, comment_url=None, rest={'HttpOnly': False}, rfc2109=False)
                #cookiejar.set_cookie(cookie)
            #    Set-Cookie: sessionToken=abc123; Expires=Wed, 09 Jun 2021 10:18:14 GMT
            #    ck = cookielib.Cookie(version=0, name='Name', value='1', port=None, port_specified=False, domain='www.example.com', domain_specified=False, domain_initial_dot=False, path='/', path_specified=True, secure=False, expires=None, discard=True, comment=None, comment_url=None, rest={'HttpOnly': None}, rfc2109=False)
            #jar=cookielib.CookieJar()
            #jar.extract_cookies(self.rawData, self.request)



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
    
