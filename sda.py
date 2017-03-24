#!/usr/bin/env python3

# Shadow Dictionary Attack
# Author: DillByrne
# Licence: GPLv3+

import optparse
import crypt
import os
import sys
import threading


class CrackThread(threading.Thread):
    'Semaphore limited password cracking thread class'
    
    tLimiter = None

    def __init__(self,line,dictFile):
        super(CrackThread,self).__init__()
        self.line = line
        self.dictFile = dictFile

    def run(self):
        self.tLimiter.acquire()
        try:
            user = self.line.split(':')[0]
            cryptPass = self.line.split(':')[1].strip(' ')
            result = checkPass(cryptPass,self.dictFile)
            print('[*] Cracking Password For: %s ' % user)
            print(result)
            
        finally:
            self.tLimiter.release()


def checkFile(filename):
    'Check file existance and permissions'

    if not os.path.isfile(filename):
        print('[-] %s  does not exist.' % filename)  
        exit(0)
    if not os.access(filename, os.R_OK):
        print('[-] %s  access denied.' % filename) 
        exit(0)


def checkPass(cryptPass,dictFile):
    'Check a salted password against a dictionary file'
    salt = cryptPass
    
    try:
        wordList = open(dictFile,'r',encoding = "ISO-8859-1")

        for word in wordList.readlines():
            word = word.strip('\n')
            cryptWord = crypt.crypt(word,salt)

            if (cryptWord == cryptPass):
                wordList.close()
                return '[+] Found Password: '+word+'\n'
                        

        wordList.close()
        return '[-] Password Not Found.\n'
    
    except Exception as e:
        print(e)
        exit(0)

def main():
	
    parser = optparse.OptionParser('Shadow Dictionary Attack\n'
    'usage: '+sys.argv[0]+ \
    ' -p <password file> -d <dictionary file> -t <number of threads>')

    parser.add_option('-p', dest= 'passFile' , type='string',\
    help='specify password file')
    parser.add_option('-d', dest='dictFile', type='string', \
    help='specify dictionary file')
    parser.add_option('-t', default=1, dest='threadNo', type='int', \
    help='specify dictionary file')
    (opt,args) = parser.parse_args()

    if(opt.passFile == None) | (opt.dictFile == None):
        print(parser.usage)
        exit(0)
    else:

        if opt.threadNo > 0:
            CrackThread.tLimiter = threading.BoundedSemaphore(opt.threadNo)
        else:
            print ('\nInvalid thread paramater: %d' % opt.threadNo)
            print(parser.usage)
            exit(0)
        
        checkFile(opt.dictFile)
        checkFile(opt.passFile)
    
    try:
        passFile = open(opt.passFile,'r',encoding = 'ISO-8859-1')
        for line in passFile.readlines():
            if ":" in line:
                CrackThread(line,opt.dictFile).start()
        passFile.close()

    except Exception as e:
        print(e)
        exit(0)


if __name__ == "__main__":
    main()
