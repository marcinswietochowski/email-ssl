# email-ssl
Simple program to send email without using SMTPLIB

usage: email-ssl1.py [-h] [-p PORT] [-e HELO] [-u USER] [-s SECURE] [-b BODY] [-c CIPHER] [-a AUTH] mail_from rcpt_to mx

Just an example

positional arguments:
  mail_from             nadawca
  rcpt_to               odbiorca
  mx                    Mail eXchanger

options:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  port (default: 25)
  -e HELO, --helo HELO  helo (default: None)
  -u USER, --user USER  login do autoryzacji (default: None)
  -s SECURE, --secure SECURE
                        haslo do autoryzacji (default: None)
  -b BODY, --body BODY  plik z trescia maila (default: None)
  -c CIPHER, --cipher CIPHER
                        ssl/tls - uzyj STARTTLS/SSL w trakcie sesji SMTP (default: None)
  -a AUTH, --auth AUTH  plain/login - uzyj AUTH PLAIN/AUTH LOGIN w trakcie sesji SMTP, (domyslnie plain) (default: None)
  
