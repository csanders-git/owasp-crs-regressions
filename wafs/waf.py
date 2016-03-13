#from abc import ABCMeta, abstractmethod
import abc

class WAF(object):
    __metaclass__ = abc.ABCMeta
    def __init__(self):
        print "HELLO"
    @abc.abstractmethod
    def startWAF(self):
        pass
    def stopWAF(self):
        pass
    def loadRules(self):
        pass
