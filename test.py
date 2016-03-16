#!/usr/bin/python
'''
    Authors: Chaim Sanders, Jared Stroud
'''
import yaml  # We reqire pyYaml
import sys
import os
import socket
import time
import string
import Cookie
import errno
import ssl
import argparse
from IPy import IP
import importlib
import inspect  # For iterating through class names
import wafs.waf

class Results(object):
    def __init__(self):
        self.results = {}
    def setResult(self, key, value):
        self.results[key] = value
    def getResults(self):
        return self.results
    def setTestData():
        pass
# We use tests to  persist things that must exist between tests
class Test(object):
    def __init__(self, subTests, metaData):
        self.subTests = subTests
        self.meta = metaData
        self.cookieJar = []
        self.logger = None

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
        
        for subTest in self.subTests:
            if subTest.getType() == "Request":
                # We reset the results for each request
                results = Results()
                # start our logging (if applicable)
                self.logger.startLog()
                subTest.rawHTTP(self.cookieJar)
                #print subTest.rawData
                status_headers_data = subTest.parseHTTP(self.cookieJar, subTest.host)
                if subTest.rawData == "":
                    return returnError("Seems like there was no HTTP response")
                results.setResult("status",status_headers_data[0])
                results.setResult("headers",status_headers_data[1])
                results.setResult("data",status_headers_data[2])
                # Stop logging (if applicable)                   
                self.logger.stopLog()
                # Check result
                self.logger.parseLog()
                # Get what the logger returned and enter it into results
                for key, value in self.logger.returnValues.iteritems():
                    results.setResult(key,value)
                #print results.getResults()

            if subTest.getType() == "Response":
                subTest.setResults(results)
                subTest.compareResults()
                # Parse checks
                
                
    def setLogger(self, logger):
        self.logger = logger
        
    def getCurlCommands(self):
        '''
            Name: getCurlCommands
            Parameters: None.
            Return: Result of gencurl
        '''
        for subTest in self.subTests:
            if subTest.getType() == "Request":
                return subTest.genCurl()


class TestRequest(object):

    def __init__(self, rawRequest="",
                 protocol="http",
                 destAddr="localhost",
                 port=80, method="GET",
                 url="/",
                 version="HTTP/1.1",
                 headers={},
                 data="",
                 status=200):
        if headers == {}:
            headers["Host"] = destAddr
            headers["User-Agent"] = "OWASP CRS Regression Tests"
        try:
            port = int(port)
        except ValueError:
            returnError("An invalid port value was entered in our YAML")
        self.protocol = protocol
        self.host = destAddr
        self.port = int(port)
        self.method = method
        self.url = url
        self.data = data
        self.headers = headers
        self.version = version
        self.rawRequest = rawRequest
        self.rawData = ""
        # If cookie is true, we need to check the cookiejar.
        if 'cookie' in headers.keys():
            if headers['cookie'] is True:
                pass

    def getType(self):
        return "Request"

    def printTest(self):
        print self.url
        # for ch in request:
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
        command = "curl %s%s \\%s" % (self.host, self.url, os.linesep)
        command += "-X %s \\%s" % (self.method, os.linesep)
        command += "--cookie %s \\%s" % (self.cookie, os.linesep)
        if len(self.headers) != 0:
            for headerName, headerValue in self.headers.iteritems():
                # TODO: Escape quotes in headername and headervalue
                command += '--header "%s: %s" \\%s' % (headerName, headerValue, os.linesep)
        command = command[:-2]
        return command

    def findCookie(self, cookieJar, originDomain):
        for cookie in cookieJar:
            for cookieName, cookieMorsals in cookie[0].iteritems():
                coverDomain = cookieMorsals['domain']
                if coverDomain == "":
                    if originDomain == cookie[1]:
                        return cookie[0]
                else:
                    # Domain match algorithm
                    B = coverDomain.lower()
                    HDN = originDomain.lower()
                    NEnd = HDN.find(B)
                    if NEnd is not False:
                        return cookie[0]
        return False

    def rawHTTP(self, cookieJar):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(5)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Check if SSL
            if self.protocol == "https":
                self.sock = ssl.wrap_socket(self.sock, ssl_version=ssl.PROTOCOL_SSLv23, ciphers="ADH-AES256-SHA:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:AES128-GCM-SHA256:AES128-SHA256:HIGH:")
            self.sock.connect((self.host, self.port))
        except socket.error as msg:
            return returnError(msg)
        CRLF = "\r\n"
        # If they requested raw HTTP just provide it
        if self.rawRequest != "":
            request = self.rawRequest
            request = request.replace("\n", CRLF)
            request += CRLF
        # Otherwise build our build our request
        else:
            request = '#method# #url##version#%s#headers#%s#data#' % (CRLF, CRLF)
            request = string.replace(request, "#method#", self.method)
            # We add a space after here to account for HEAD requests with no url
            request = string.replace(request, "#url#", self.url+" ")
            request = string.replace(request, "#version#", self.version)
            # Check if we have a cookie that needs using
            cookie = self.findCookie(cookieJar, self.host)
            # If the user has requested a tracked cookie and we have one set it
            if 'Cookie' in self.headers.keys():
                if cookie is not False and self.headers['Cookie'] is True:
                    print "\tAdded cookie from previous request"
                    self.headers["Cookie"] = cookie.output()
            # Expand out our headers into a string
            headers = ""
            if self.headers != {}:
                for hName, hValue in self.headers.iteritems():
                    headers += str(hName)+": "+str(hValue) + str(CRLF)
            request = string.replace(request, "#headers#", headers)
            # If we have data append it
            if self.data != "":
                data = str(self.data) + str(CRLF)
                request = string.replace(request, "#data#", data)
            else:
                request = string.replace(request, "#data#", "")
        # Update our raw request with the generated one
        self.rawRequest = request
        self.sock.send(request)
        # Make socket non blocking
        self.sock.setblocking(0)
        ourData = []
        data = ''
        timeout = .3
        # Beginning time
        begin = time.time()
        while True:
            # If we have data then if we're passed the timeout break
            if ourData and time.time()-begin > timeout:
                break
            # If we're dataless wait just a bit
            elif time.time()-begin > timeout*2:
                break
            # Recv data
            try:
                data = self.sock.recv(8192)
                if data:
                    ourData.append(data)
                    begin = time.time()
                else:
                    # Sleep for sometime to indicate a gap
                    time.sleep(0.2)
            except socket.error as e:
                # Check if we got a timeout
                if e.errno == errno.EAGAIN:
                    pass
                # If we didn't it's an error
                else:
                    return returnError(e)
        data = ''.join(ourData)
        self.sock.shutdown(1)
        self.sock.close()
        #print data
        self.rawData = data

    def checkForCookie(self, cookie, originDomain):
        # http://bayou.io/draft/cookie.domain.html
        # Check if our originDomain is an IP
        originIsIP = True
        try:
            IP(originDomain)
        except:
            originIsIP = False

        for cookieName, cookieMorsals in cookie.iteritems():
            # If the coverdomain is blank or the domain is an IP set the domain to be the origin
            if cookieMorsals['domain'] == "" or originIsIP is True:
                # We want to always add a domain so it's easy to parse later
                return (cookie, originDomain)
            # If the coverdomain is set it can be any subdomain
            else:
                coverDomain = cookieMorsals['domain']
                # strip leading dots
                # Find all leading dots not just first one
                # http://tools.ietf.org/html/rfc6265#section-4.1.2.3
                firstNonDot = 0
                for i in range(len(coverDomain)):
                    if coverDomain[i] != '.':
                        firstNonDot = i
                        break
                coverDomain = coverDomain[firstNonDot:]
                # We must parse the coverDomain to make sure its not in the suffix list
                try:
                    with open('util/public_suffix_list.dat', 'r') as f:
                        for line in f:
                            if line[:2] == "//" or line[0] == " " or line[0].strip() == "":
                                continue
                            if coverDomain == line.strip():
                                return False
                except IOError:
                    return returnError("We were unable to open the needed publix suffix list")
                # Generate Origin Domain TLD
                i = originDomain.rfind(".")
                oTLD = originDomain[i+1:]
                # if our cover domain is the origin TLD we ignore
                # Quick sanity check
                if coverDomain == oTLD:
                    return False
                # check if our coverdomain is a subset of our origin domain
                # Domain match (case insensative)
                if coverDomain == originDomain:
                    return (cookie, originDomain)
                # Domain match algorithm
                B = coverDomain.lower()
                HDN = originDomain.lower()
                NEnd = HDN.find(B)
                if NEnd is not False:
                    N = HDN[0:NEnd]
                    # Modern browsers don't care about dot
                    if N[-1] == '.':
                        N = N[0:-1]
                else:
                    # We don't have an address of the form
                    return False
                if N == "":
                    return False
                # Doesn't seem to be applicable anymore
                # if('.' in N):
                #    print "FAIL3"
                #    sys.exit()
                # cookieMorsals['domain'] = coverDomain
                return (cookie, originDomain)

    def parseHTTP(self, cookieJar, originDomain):
        response = self.rawData.split("\r\n")
        (version, status, statusMsg) = response[0].split(" ", 2)
        # We start at line 1 because line zero is our status
        currentLine = 1
        headers = {}
        # We're going to get back an empty line, but strictly its \r\n
        while(response[currentLine] != "\r\n" and response[currentLine] != ""):
            (hName, hValue) = response[currentLine].split(":", 1)
            headers[hName] = hValue.strip()
            currentLine += 1
            # If there is a set-cookie header try processing it.
            if hName == "Set-Cookie" and self.saveCookie is True:
                hValue = "Test=test_value;expires=Sat, 01-Jan-2000 00:00:00 GMT; domain=chaimsanders.com; path=/;"
                try:
                    cookie = Cookie.SimpleCookie()
                    cookie.load(hValue.lstrip())
                except Cookie.CookieError:
                    return returnError("There was an error processing the cookie into a SimpleCookie")
                # if the checkForCookie is invalid then we don't save it
                if self.checkForCookie(cookie, originDomain) is not False:
                    return returnError("An invalid cookie was specified")
                else:
                    cookieJar.append((cookie, originDomain))
        data = response[currentLine:]
        return (status,headers,data)

class TestResponse(object):
    def __init__(self, status="404", triggers=None, site_contains=None, log_contains=None, saveCookie=False):

        self.status = status
        # Python can't search lists unless elements are strings
        self.triggers = [str(i) for i in triggers]
        self.saveCookie = saveCookie
        self.log_contains=log_contains
        self.site_contains=site_contains
        self.results = {}

    def getType(self):
        return "Response"

    def setResults(self,results):
        self.results = results

    def compareResults(self):
        failedToTrigger = []
        for trigger in self.triggers:
            if trigger not in self.results.getResults()["triggers"]:    
                failedToTrigger.append(trigger)
        if len(failedToTrigger) > 0:
            print "[-] Did not trigger ID(s):", ",".join(failedToTrigger)
        if self.results.getResults()["status"] != self.status:
            print "[-] Status outcome (" + self.results.getResults()["status"] +") did not match - Expected",self.status
    
    def printTest(self):
        pass


def returnError(errorString):
        errorString = str(errorString) + os.linesep
        sys.stderr.write(errorString)
        sys.exit(1)


def extractInputTests(inputTestValues,userOverrides):
    requestArgs = {}  # Generate constructor args.
    headers = {}  # Create default constructors...
    # If we want to override the defaults they will have been
    # provided via the command line
    # If the YAML file provides information it will override these
    for key, value in userOverrides.iteritems():
        requestArgs[key] = value
        # Special exception for overwriting default Host header
        if key == "destAddr":
            headers["Host"] = value

        
    if inputTestValues is None:
        myReq = TestRequest(**requestArgs)
        return myReq
    for name, value in inputTestValues.iteritems():  # Otherwise we have input values.
        if name == "headers":  # Check if we get a header if so make it into a dict.
            for header in value:  # Process YAML list of dicts into just a dictionary.
                header = header.popitem()
                headers[header[0].title()] = header[1]
        else:
            requestArgs[name] = value
    requestArgs["headers"] = headers  # Now that our headers is populated, push it!
    try:
        myReq = TestRequest(**requestArgs)  # Try to generate a request.
        return myReq
    except TypeError:
        # Almost for sure they passed an invalid name, check the args of Request
        return returnError("An invalid argument was passed to the Request constructor, \
                            check your arugments " + str(requestArgs.keys()))

# def extractMetaTests(metaTestValues):
#    return metaTestValues


def extractTests(doc,userOverrides):
    myTests = []
    # Iterate over the different 'named tests' (AKA YAML sections)
    for section, tests in doc.iteritems():
        # Within each YAML section look at each 'test'
        for test in tests:
            ourTest = test['test']
            testData = []
            metaData = {}
            for transactions in ourTest:
                # See if we have an input transaction or input
                if 'input' in transactions.keys():
                    inputTestValues = transactions["input"]
                    # For each Test extract all the input requests
                    testData.append(extractInputTests(inputTestValues,userOverrides))
                elif 'output' in transactions.keys():
                    outputTestValues = transactions["output"]
                    testData.append(extractOutputTests(outputTestValues))
                elif 'meta' in transactions.keys():
                    metaData = transactions["meta"]
                else:
                    return returnError("No input/output was found, please specify at least an empty input and out for defaults")
            # sanity check to ensure even number of in's and out's
            requests = 0
            responses = 0
            for i in testData:
                if i.__class__.__name__ == "TestRequest":
                    requests += 1
                if i.__class__.__name__ == "TestResponse":
                    responses += 1
            if requests != responses:
                return returnError("No input/output was found, please specify at least an empty input and out for defaults")
            myTest = Test(testData, metaData)
            myTests.append(myTest)
    return myTests


def extractOutputTests(outputTestValues):
    # From the YAML generate the constructor args
    responseArgs = {}
    # if we have an empty input create default constructor
    if outputTestValues is None:
        myRes = TestResponse(**responseArgs)
        return myRes
    # Otherwise we have input values
    for name, value in outputTestValues.iteritems():
        responseArgs[name] = value
    try:
        myRes = TestResponse(**responseArgs)  # Try to generate a request.
        return myRes
    except TypeError:
        # Almost for sure they passed an invalid name, check the args of Request
        return returnError("An invalid argument was passed to the Response constructor, \
                            check your arugments " + str(responseArgs.keys()))

# We will loop through a dir looking for files of an extension
def get_files(directory,extension='.py'):
    fileNames = []
    # normally we'll include a file without the 's'
    # as a standard loader class, we'll load this manually
    dirClass = directory[:-1]
    for f in os.listdir(directory):
        fname, ext = os.path.splitext(f)
        # if we have python files that aren't our init or our master class
        if ext == extension and fname != '__init__' and fname != dirClass:
            fileNames.append(fname)
    return fileNames

# Make sure you've gotten the usual talk about running python scripts as root
def loadWAFPlugin(wafChoice, directory="wafs"):
    importNames = get_files(directory)
    for name in importNames:
        if '.' in name:
            return returnError("WAF Plugin names cannot contain dots")
        if name.lower() == wafChoice.lower():
            ourWAF = importlib.import_module(directory + "." + str(name), __name__)
            # Now that we've loaded what we think the right module 
            # make sure it's in the right for format
            for name, obj in inspect.getmembers(ourWAF):
                # loop through members and get classes
                if inspect.isclass(obj):
                    # find the name of the class we're looking for
                    if name.lower() == wafChoice.lower():
                        # Dynamiclly load it
                        mod = getattr(ourWAF, name)
                        return mod
            return returnError("We did not find a valid plugin")


# Make sure you've gotten the usual talk about running python scripts as root
def loadLoggingPlugin(logChoice, directory="logs"):
    importNames = get_files(directory)
    for name in importNames:
        if '.' in name:
            return returnError("Logging Plugin names cannot contain dots")
        if name.lower() == logChoice.lower():
            ourLog = importlib.import_module(directory + "." + str(name), __name__)
            # Now that we've loaded what we think the right module 
            # make sure it's in the right for format
            for name, obj in inspect.getmembers(ourLog):
                # loop through members and get classes
                if inspect.isclass(obj):
                    # find the name of the class we're looking for
                    if name.lower() == logChoice.lower():
                        # Dynamiclly load it
                        mod = getattr(ourLog, name)
                        return mod
            return returnError("We did not find a valid logging plugin")


def getYAMLData(filePath="."):
    try:
        # Check if the path exists and we have read access
        if os.path.exists(filePath) and os.access(filePath, os.R_OK):
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


def parseArgs():
    parser = argparse.ArgumentParser(description='OWASP CRS Regression Tests')
    parser.add_argument('-d', '--directory', dest='directory', action='store',
                       default='.', required=False, help='YAML test directory (default: .)')
    parser.add_argument('-l', '--log', dest='log', action='store', default=None,
                       required=False, help='Location of log file, if required')
    parser.add_argument('-w', '--waf', dest='waf', action='store', default='ModSecurityv2',
                       required=False, help='WAF to initiate  (default: ModSecurityv2)')
    parser.add_argument('-a', '--addr', dest='destAddr', action='store',
                       required=False, help='The default socket/host destination address to use (default: localhost)')                       
    args = parser.parse_args()
    if args.waf.lower() not in get_files("wafs"):
        pluglist = "\n\t".join(get_files("wafs"))  
        return returnError("There is no plugin for the WAF you specified, please choose an existing plugin or try using the generic plugin. \nYour available WAF plugins are:\n\t" + pluglist)
    return args


def main():

    myTests = []
    args = parseArgs()
    wafClass = loadWAFPlugin(args.waf)
    logClass = loadLoggingPlugin(args.waf)
    ourWAF = wafClass()
    ourLogger = logClass()
    ourWAF.startWAF()
    yamlFiles = getYAMLData(args.directory)
    ourLogger.setLogFile(args.log)
    # Allow for users to override defaults
    possibleOverrides = ["destAddr"]
    userOverrides = {}
    
    # loop through the possible overrides to see if they're set
    for override in possibleOverrides:
        # If they are set make sure to add it to our userOverrrides
        if args.__getattribute__(override) is not None:
            userOverrides[override] = args.__getattribute__(override)
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
        # Extract our tests but override with user defaults as needed
        myTests = extractTests(doc,userOverrides)
        # TODO: check arguments to see what to do
        # We pass our logger so that we can parse out individual requests/response data
        for test in myTests:
            # Specify which logger we want to use to run the test
            test.setLogger(ourLogger)
            test.runTests()

            


if __name__ == "__main__":
    main()
