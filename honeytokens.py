#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from tinydb import TinyDB, Query
from twisted.names import dns, error as dnserror, server as dnsserver
import logging
from logging.handlers import SysLogHandler
from twisted.web import server as webserver, resource as webresource
from twisted.internet import reactor, endpoints, defer
import configparser
import smtplib
import threading
import datetime


config = configparser.ConfigParser()
config.read('/opt/honeytokens/config.conf')

conf = config['honeytokens-config']

dbfile = conf['databasefile']
db = TinyDB(dbfile)
query = Query()


class Simple(webresource.Resource):
    isLeaf = True
    def render_GET(self, request):
        req = request.path.decode('utf-8')
        if req.startswith('/token/'):
            tokenid = req.split('/')[2]
            clientip = request.getClientAddress().host
            if checkToken(tokenid):
                http_thread = threading.Thread(target=conCatHTTP, args=(tokenid,clientip))
                http_thread.start()
        return '200'.encode('utf-8')



#check token in database
def checkToken(tokenid):
    print(tokenid)
    result = db.search(query.token == tokenid)
    if result:
        return True
    else:
        print('token not found')
        return False

#token is valid. consolidate data

def conCatHTTP(tokenid, clientip):
    result = db.search(query.token == tokenid)
    request = {'clientip': clientip}
    result.append(request)
    logTo(result)
    return True

    

##############################################
## DNS SERVER ################################
##############################################


class MockDNSResolver:


    def _doDynamicResponse(self, query):
        name = query.name.name
        record = dns.Record_A(address=b"127.0.0.1")
        answer = dns.RRHeader(name=name, payload=record)
        authority = []
        additional = []
        return [answer], authority, additional

    def query(self, query, timeout=None):
        print("Incoming query for:", query.name)
        if query.type == dns.A:
            dns_thread = threading.Thread(target=checkDNSQuery, args=(query.name,))
            dns_thread.start()
            return defer.succeed(self._doDynamicResponse(query))
        else:
            return defer.fail(dnserror.DomainError())


def checkDNSQuery(domain):
    domain = str(domain)
    if domain.startswith("ft."):
        parseDNSQuery(domain)
        print('folder token detected')
    else:
        return 'no token'

def parseDNSQuery(domain):
    print('got dns parse request')
    domainname = '.' + conf['domainname']
    print(domainname)
    data = domain.split('ft.')
    username = data[1].strip('.')
    hostname = data[2].strip('.')
    corpdomain = data[3].strip('.')
    tokenid = data[4].split(domainname)[0]
    print(tokenid)
    if checkToken(tokenid):
        conCatDNS(tokenid, username, hostname, corpdomain)
    #TODO:         

def conCatDNS(tokenid, username, hostname, corpdomain):
    result = db.search(query.token == tokenid)
    request = {'username': username, 'clienthostname': hostname, 'corpdomain': corpdomain}
    result.append(request)
    logTo(result)
    

#################logging########################

def logTo(message):
    if conf.getboolean('logtosiem') == True:
        logToSIEM(message)
    if conf.getboolean('logtosyslog') == True:
        logToSyslog(message)
    if conf.getboolean('logtosmtp') == True:
        if conf['smtptype'] == 'auth':
            smtpAuth(message)
        if conf['smtptype'] == 'open':
            smtpOPN(message)
        


def logToSIEM(message):
    print('logging to siem')
    logger = logging.getLogger()
    if not len(logger.handlers):
        logger.addHandler(SysLogHandler(address=(conf['siemaddress'],conf.getint('siemport'))))
    
    now = datetime.datetime(now)
    now = now.strftime('%b %d %H:%M:%S')
    
    cefheader = str(now) + ' HoneyTokens ' + 'CEF:0|honeypot|honeytoken|1.0|100|HoneyToken Access Detected|10|'
    token = message[0]['token']
    tokentype = message[0]['type']
    hostname = message[0]['hostname']
    ip = message[0]['ip']
    path = message[0]['path'] 
    description = message[0]['description']
    
    if tokentype == 'doc':
        clientip = message[1]['clientip']
        
        cefmessage = cefheader + 'cs1=' + token  + ' cs2=' + tokentype + ' dhost=' + hostname + ' dst=' + ip + ' filePath='  + path + ' cs3=' + description + ' src=' + clientip

    if tokentype == 'folder':
        username = message[1]['username']
        clienthostname = message[1]['clienthostname']
        corpdomain = message[1]['corpdomain']
        
        cefmessage = cefheader + 'cs1=' + token  + ' cs2=' + tokentype + ' dhost=' + hostname + ' dst=' + ip + ' filePath='  + path + ' cs3=' + description + ' suser=' + username + ' shost=' + clienthostname + ' sntdom=' + corpdomain
    logging.warn(cefmessage)

def smtpAuth(msg):
    email_user = conf['smtpuser']
    email_password = conf['smtppassword']
    toaddr = conf['toaddress']
    smtpserver = conf['smtpserver']
    port = conf.getint('smtpport')
    if port == 465:
        server = smtplib.SMTP_SSL(smtpserver, 465, timeout=20)
    if port == 25:
        server = smtplib.SMTP(smtpserver, 25, timeout=20)
    if port != 25 and port != 465:
        print('wrong smtp port, only 25 or 465')
    else:
        print('SMTP ERROR')    
    server.ehlo()
    server.login(email_user, email_password)
    server.sendmail(email_user, toaddr, msg)
    server.close()
    

def smtpOPN(msg):
    email_user = conf['smtpuser']
    toaddr = conf['toaddress']
    smtpserver = conf['smtpserver']
    port = conf.getint('smtpport')
    if port == 465:
        server = smtplib.SMTP_SSL(conf['smtpserver'], 465, timeout=20)
    if port == 25:
        server = smtplib.SMTP(conf['smtpserver'], 25, timeout=20)
    if port != 25 and port != 465:
        print('wrong smtp port, only 25 or 465')
    else:
        print('SMTP ERROR')
    server.sendmail(email_user, toaddr, msg)
    server.quit()


###########################

if __name__ == '__main__':

    webserverport = conf.getint('webserverport')
    dnsserverport = conf.getint('dnsserverport')

    site = webserver.Site(Simple())
    site.displayTracebacks = False
    endpoint = endpoints.TCP4ServerEndpoint(reactor, webserverport, interface=conf['webserveraddress'])
    endpoint.listen(site)


    clients = [MockDNSResolver()]
    factoryDNS = dnsserver.DNSServerFactory(clients=clients)
    protocol = dns.DNSDatagramProtocol(controller=factoryDNS)
    reactor.listenUDP(dnsserverport, protocol, interface=conf['dnsserveraddress'])
    reactor.listenTCP(dnsserverport, factoryDNS, interface=conf['dnsserveraddress'])


    reactor.run()
