#!/usr/bin/python3

import base64
import socket
import time
import ssl
import sys
import argparse
import dns.resolver

def get_mx_record(domain):
    hosts = []
    try:
        records = dns.resolver.query(domain, "MX")
        for rdata in records:
            hosts.append(str(rdata.exchange).rstrip('.'))
        return hosts
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout) as e:
        print (e)

    if (hosts):
        return hosts[0]
    else:
        return None 

parser = argparse.ArgumentParser(description="Just an example", formatter_class=argparse.ArgumentDefaultsHelpFormatter)

parser.add_argument("mail_from", help="nadawca")
parser.add_argument("rcpt_to", help="odbiorca")
parser.add_argument("mx", help="Mail eXchanger")
parser.add_argument("-p", "--port", help="port", type=int, default=25)
parser.add_argument("-e", "--helo", action="store", help="helo")
parser.add_argument("-u", "--user", action="store", help="login do autoryzacji")
parser.add_argument("-s", "--secure", action="store", help="haslo do autoryzacji")
parser.add_argument("-b", "--body", action="store", help="plik z trescia maila")
parser.add_argument("-c", "--cipher", action="store", help="ssl/tls - uzyj STARTTLS/SSL w trakcie sesji SMTP")
parser.add_argument("-a", "--auth", action="store", help="plain/login - uzyj AUTH PLAIN/AUTH LOGIN w trakcie sesji SMTP, (domyslnie plain)")

args = parser.parse_args()
config = vars(args)

print(config) # dict ze zmiennymi
mail_from = (config['mail_from'])
rcpt_to = (config['rcpt_to'])
mx = (config['mx'])
port = (config['port'])
username = (config['user'])
password = (config['secure'])
hostname = (config['helo'])
cipher = (config['cipher'])
auth = (config['auth'])

if config['body'] !=  None:
    with open(config['body']) as file1:
        message = file1.read()
        print(message)
else:
    message = "Subject: test1\r\n\r\nTest Message - nie byl podany, parametr -b plik\r\n"

autoryzacja = False
# if (username != None and password == None) or (username == None and password != None):
if (username == None and password != None):
    username = mail_from
    autoryzacja = True
    print("Podane haslo, -u = mail_from, proba autoryzacji")
    # sys.exit()
elif (username == None and password == None):
    autoryzacja = False
else:
    print("Podany user i haslo - proba autoryzacji")
    autoryzacja = True

# if username == None:
#     username = mail_from
#     print ("Brak --user przyjmujemy za user mail_from")
# else:
#     print ("User/login takie same")

if hostname == None:
    hostname = socket.gethostname()
    print ("Brak -e przyjmujemy za helo socket.gethostname()")
else:
    print (f"Helo: {hostname}")

print(cipher)
if cipher is None:
    print ("Sesja bez szyfrowania")
elif cipher == "ssl":
    print ("Wybrane SSL")
elif cipher == "tls":
    print ("Wybrane STARTTLS")
else:
    print("Szyfrowanie musi byc ssl albo tls (lub brak)")   
    sys.exit()

# Start sesji SMTP

if cipher == "ssl":
    sock = socket.socket()
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    sock = context.wrap_socket(sock, server_hostname=mx)
    sock.connect((mx, port))
    print(type(sock))
    rec_greet = sock.recv(1024)
    rec_greet = rec_greet.decode()
else:
    sock = socket.socket()
    sock.connect((mx, port))
    rec_greet = sock.recv(512)
    rec_greet = rec_greet.decode()
    if rec_greet[:3] != '220':
        print('220 nie ma.')

print("Powitanie: " + rec_greet)

# HELO
helo = 'EHLO ' + hostname + '\r\n'
# print("Helo wysylane :", helo)
sock.send(helo.encode())
rec_helo = sock.recv(1024)
rec_helo = rec_helo.decode()
print("SMTP oferuje: " + rec_helo)
if rec_helo[:3] != '250':
    print('250 nie ma.')

# STARTTLS
if cipher == "tls":
    tlscmd = "STARTTLS\r\n"
    sock.send(tlscmd.encode())
    rec_tlscmd = sock.recv(1024)
    rec_tlscmd = rec_tlscmd.decode()
    print("Wynik STARTTLS: " + rec_tlscmd)
    if rec_helo[:3] != '250':
        print('250 nie ma.')
    print("STARTSSL OK")

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    sock = context.wrap_socket(sock, server_hostname=mx)

    # print(type(sock))

    # HELO
    helo = 'EHLO ' + hostname + '\r\n'
    print("Helo wysylane :", helo)
    sock.send(helo.encode())
    rec_helo = sock.recv(1024)
    rec_helo = rec_helo.decode()
    print("SMTP oferuje: " + rec_helo)
    if rec_helo[:3] != '250':
        print('250 nie ma.')
# Koniec STARTTLS

# Auth
# Info for username and password
print(f"auth = {auth}. autoryzacja = {autoryzacja}")
if autoryzacja is True and (auth == "plain" or auth == None):
    base64_str = ("\x00"+username+"\x00"+password).encode()
    base64_str = base64.b64encode(base64_str)
    authMsg = "AUTH PLAIN ".encode()+base64_str+"\r\n".encode()
    sock.send(authMsg)
    recv_auth = sock.recv(1024)
    print(recv_auth.decode())

    if recv_auth.decode()[:3] != '235':
        print('Autoryzacja nieudana - brak (235 Authentication succeeded)')
        sys.exit()
elif (autoryzacja is True and auth == "login"):
    base64_username = username.encode()
    base64_username = base64.b64encode(base64_username)
    loginMsg = "AUTH LOGIN ".encode()+base64_username+"\r\n".encode()
    # print(loginMsg)
    sock.send(loginMsg)
    recv_auth = sock.recv(1024)
    if recv_auth.decode()[:3] != '334':
        print('Autoryzacja nieudana - brak (334 VXNlcm5hbWU6) - Username: ')
        print(recv_auth.decode())
        sys.exit()
    print(f"Login OK :", recv_auth.decode())
    base64_password = password.encode()
    base64_password = base64.b64encode(base64_password)
    passwordMsg = base64_password+"\r\n".encode()
    # print(passwordMsg)
    sock.send(passwordMsg)
    recv_auth = sock.recv(1024)
    if recv_auth.decode()[:3] != '235':
        print('Autoryzacja nieudana - brak 235 Authentication succeeded')
        print(recv_auth.decode())
        sys.exit()
    print(f"Password OK: ", recv_auth.decode())

# Mail from 
# mfrom = 'mail from:' + mail_from + '\r\n\r\n'
mfrom = 'mail from: <' + mail_from + '>\r\n'
sock.send(mfrom.encode())
rec_from = sock.recv(512)
rec_from = rec_from.decode()
print(f"Mail od:", mfrom, rec_from)
if rec_helo[:3] != '250':
    print('250 nie ma.')

# print("Koniec mail from:")

# Rcpt to
rcpt = 'rcpt to: <' + rcpt_to + '>\r\n'
sock.send(rcpt.encode())
rec_to = sock.recv(512)
rec_to = rec_to.decode()
print(f"Rcpt to:",rcpt_to, rec_to)
if rec_helo[:3] != '250':
    print('250 nie ma.')
elif rec_helo[:3] == '451':
    time.sleep (60)

# print("End of data")

# Rozpoczecie sesji - wyslanie data - czekamy na 354 Enter message, ending with "." on a line by itself
dta = "DATA\n"
sock.send(dta.encode())
dta_recv = sock.recv(512)
dta_recv = dta_recv.decode()
# print(f"Odpowiedz na data : ", dta_recv)
if dta_recv[:3] != '354':
    print('354 nie ma. Cos nie tak z data')
else:
    print('Data przyjete')

# Message!
message = message + '\r\n.\r\n'
print(f"Wysylamy po DATA {message}")
sock.send(message.encode())
print(message.encode())
rec_message = sock.recv(512)
rec_message = rec_message.decode()
print(f"Wiadomosc : ", rec_message)

# Ladnie sie zegnamy zeby nie bylo "The TLS connection was non-properly terminated."
quit = 'QUIT\r\n'
sock.send(quit.encode())
#print(quit.encode())
recv5 = sock.recv(1024)
papa = (recv5.decode())

if papa[:3] != '221':
    print('221 nie ma. Cos nie tak z END')
else:
    print('END przyjete. PAPA')
sock.close()

print('FIN')
