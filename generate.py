import uuid
from tinydb import TinyDB
from netaddr import valid_ipv4
import zipfile
import configparser


config = configparser.ConfigParser()
config.read('/opt/honeytokens/config.conf')

conf = config['honeytokens-config']



db = TinyDB('db.json')

randomtoken = str(uuid.uuid4())

payloadtype=input('Payload Type (supported payloads: doc,folder):')
hostname = input('Computer Hostname:')
ip = input('Computer IP:')
path = input('File Path:')
description = input('Description:')


def checkdata(payloadtype,hostname,ip,path,description):
    print('\nChecking data validity..')
    if payloadtype == None:
        print('Payload type is missing')
        return False
    if hostname == None:
        print('Hostname is missing')
        return False
    if ' ' in hostname:
        print('Hostname is not valid')
        return False
    if not valid_ipv4(ip):
        print('Not a valid ip address')
        return False
    if path == None:
        print('Path is missing')
        return False
    if description == None:
        print('Description is missing')
        return False
    else:
        print('Data is valid..')
        #insertData(payloadtype,hostname,ip,path,description)
        if payloadtype == 'doc':
            generateDoc(randomtoken)
            print('Generating Doc file')
        if payloadtype == 'folder':
            generateFolder(randomtoken)
            print('Generating desktop.ini file')
            
        return 'Success'

def insertData(payloadtype,hostname,ip,path,description):
    try:
        print('Inserting in database..')
        db.insert({'token': randomtoken, 'type': payloadtype, 'hostname': hostname, 'ip': ip, 'path': path, 'description': description})
    except:
        return 'Cant insert, ERROR'
    
def generateDoc(randomtoken):
    webserverport = conf['webserverport']
    webserveraddress = conf['webserveraddress']
    server = webserveraddress + ':' + webserverport + '/token/'
    url = server + randomtoken
    docname = randomtoken + '.doc'

    content = """MIME-Version: 1.0
Content-Type: multipart/related; boundary="----=_TBC-CERT_ZK"

------=_TBC-CERT_ZK
Content-Type: text/html; charset="utf-8"

<!DOCTYPE html>

<html>
<head>
<title></title>
<meta charset="utf-8"/></head>
<body>
<img src="%s"></body>
</html>


------=_TBC-CERT_ZK--""" % url

    payloadfile = open(docname, 'w')
    payloadfile.write(content)
    payloadfile.close()    
    insertData(payloadtype,hostname,ip,path,description)





def generateFolder(randomtoken):
    server = conf['domainname']
    url = '\\\\ft.%USERNAME%.ft.%COMPUTERNAME%.ft.%USERDOMAIN%.ft.' + randomtoken + '.' + server + '\\1.dll'
    content = """[.ShellClassInfo]\n
IconResource=%s""" % url
    zipname = randomtoken + '.zip'
    foldername = 'Documents/'
    filename = 'Documents/desktop.ini'


    zf = zipfile.ZipFile(zipname, 'w')

    zifile = zipfile.ZipInfo(filename)
    zifile.external_attr = 0x80
    zifile.external_attr |= 0x02

    zifolder = zipfile.ZipInfo(foldername)
    zifolder.external_attr = 0x10
    zifolder.external_attr |= 0x04

    zf.writestr(zifolder, '')
    zf.writestr(zifile, content)
    zf.close()
    insertData(payloadtype,hostname,ip,path,description)


print(checkdata(payloadtype,hostname,ip,path,description))

