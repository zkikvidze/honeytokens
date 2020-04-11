import uuid
from tinydb import TinyDB
from netaddr import valid_ipv4
import zipfile
import configparser
import argparse
import sys


config = configparser.ConfigParser()
config.read('/opt/honeytokens/config.conf')

conf = config['honeytokens-config']



db = TinyDB('db.json')

randomtoken = str(uuid.uuid4())


def commandLine():
    text = 'This script can generate honeytoken files. It will run in interactive mode when there is no arguments. For non-interactive mode and command line arguments, see help with -h:'
    parser = argparse.ArgumentParser(description=text)

    parser.add_argument('-p', '--payload_type', help='Type of payload, supported values are: doc, folder')
    parser.add_argument('-c', '--computer_hostname', help='Hostname of computer where honeytoken will be placed')
    parser.add_argument('-a', '--computer_address', help='IP address of computer where honeytoken will be placed')
    parser.add_argument('-f', '--file_path', help='File path where honeytoken will be placed')
    parser.add_argument('-d', '--description', help='Description')
    args = parser.parse_args()

    checkdata(args.payload_type,args.computer_hostname,args.computer_address,args.file_path,args.description)


def interActive():
    payloadtype=input('Payload Type (supported payloads: doc,folder):')
    hostname = input('Computer Hostname:')
    ip = input('Computer IP:')
    path = input('File Path:')
    description = input('Description:')
    checkdata(payloadtype,hostname,ip,path,description)

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
        if payloadtype == 'doc':
            print('Generating Doc file')
            generateDoc(randomtoken,hostname,ip,path,description)
        if payloadtype == 'folder':
            print('Generating desktop.ini file')
            generateFolder(randomtoken,hostname,ip,path,description)
            
        return 'Success'

def insertData(payloadtype,hostname,ip,path,description):
    try:
        print('Updating database..')
        db.insert({'token': randomtoken, 'type': payloadtype, 'hostname': hostname, 'ip': ip, 'path': path, 'description': description})
    except:
        return 'Cant insert, ERROR'
    
def generateDoc(randomtoken,hostname,ip,path,description):
    webserverport = conf['webserverport']
    webserveraddress = conf['webserveraddress']
    server = 'http://' + webserveraddress + ':' + webserverport + '/token/'
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
    print('Generated: ' + docname )    
    insertData('doc',hostname,ip,path,description)





def generateFolder(randomtoken,hostname,ip,path,description):
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
    print('Generated: ' + zipname)
    insertData('folder',hostname,ip,path,description)


#print(checkdata(payloadtype,hostname,ip,path,description))
if __name__ == '__main__':
    if not len(sys.argv) > 1:
        print('Running in interactive mode, for command line arguments, see help with -h\n')
        interActive()
    else:
        commandLine()

