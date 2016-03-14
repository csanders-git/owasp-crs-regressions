import abc

class Log(object):
    __metaclass__ = abc.ABCMeta
    def __init__(self):
        print "HELLO"
    @abc.abstractmethod
    def startLog(self):
        pass
    def stopLog(self):
        pass
    def parseLog(self):
        pass
