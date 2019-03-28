#!/usr/bin/python
#
#    Copyright 2015 Pietro Bertera <pietro@bertera.it>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

import re
import string
import hashlib
from string import printable
from itertools import product, count


class SIPAuth:

    def __init__(self, **settings):
        self.debug = settings.get('debug', False)
        self.uri = settings.get('uri', '')
        self.response = settings.get('response', '')
        self.method = settings.get('method', '')
        self.username = settings.get('username', '')
        self.nonce = settings.get('nonce', '')
        self.realm = settings.get('realm', '')
        self.algorithm = settings.get('algorithm', '')
        self.password = settings.get('password', '')

    def calculateHash(self, password=None):
        if password == None:
            pwd = self.password
        else:
            pwd = password
        a1 = "%s:%s:%s" % (self.username, self.realm, pwd)
        a2 = "%s:%s" % (self.method, self.uri)
        if self.algorithm == 'MD5':
            hashfunc = hashlib.md5
        elif self.algorithm == 'SHA':
            hashfunc = hashlib.sha1
        elif self.algorithm == 'SHA-256':
            hashfunc = hashlib.sha256
        elif self.algorithm == 'SHA-512':
            hashfunc = hashlib.sha512
        ha1 = hashfunc(a1).hexdigest()
        ha2 = hashfunc(a2).hexdigest()
        b = "%s:%s:%s" % (ha1, self.nonce, ha2)
        ret = hashfunc(b).hexdigest()

        if self.debug:
            print("Calculating {} hash:".format(self.algorithm))
            print("A1 hash {}({}): {}".format(self.algorithm, a1, ha1))
            print("A2 hash {}({}): {}".format(self.algorithm, a2, ha2))
            print("B  hash {}({}): {}".format(self.algorithm, b, ret))
        return ret

    def parseAuthorization(self, authorization):
        params = {}
        list = authorization.split(",")
        rx_kv = re.compile("([^=]*)=(.*)")

        for elem in list:
            md = rx_kv.search(elem)
            if md:
                value = string.strip(md.group(2), '" ')
                key = string.strip(md.group(1))
                if key == "uri":
                    self.uri = value
                elif key == "response":
                    self.response = value
                elif key == "nonce":
                    self.nonce = value
                elif key == "username":
                    self.username = value
                elif key == "realm":
                    self.realm = value
                elif key == "algorithm":
                    self.algorithm = value

    def passwords(self, encoding):
        chars = [c.encode(encoding) for c in printable]
        for length in count(start=1):
            for pwd in product(chars, repeat=length):
                yield b''.join(pwd)

    def crack(self, encoding='ascii'):
        expected = self.response
        for pwd in self.passwords(encoding):
            if self.debug:
                print("Password: {}".format(pwd))
            if expected == self.calculateHash(password=pwd):
                return

if __name__ == '__main__':
    import sys
    import optparse

    usage = """%prog [OPTIONS] <crack|check>
This script helps you checking the SIP authentication, the script provides to actions:

- crack:    given the data of challenge response the script will try to bruteforce the password.
            Required options: username, nonce, uri, response, realm, method
            
- check:    given the data of the challenge response and the cleartext password the script will calculate the hash and check if the password is correct
            Required options: username, nonce, uri, realm, method, password
            
You can specify all the challenge response data using the script options or you can let the script trying to parse the string from the Authorization header using the -a option, in this case you should give to the option the the header value after the 'Digest' keyword, in order to provide the comma-separated response values
"""
    opt = optparse.OptionParser(usage=usage)
    opt.add_option('-d', dest='debug', default=False, action='store_true',
                   help='Run in debug mode')
    opt.add_option('-a', '--authorization', dest='authorization', type='string', default='',
                   help='Try to get username, realm, nonce, uri and response from the authorization header, the header must be after the "Digest" keyword')
    opt.add_option('-A', '--algorithm', dest='algorithm', type='choice', default='', choices=('MD5', 'SHA', 'SHA-256', 'SHA-512', ''),
                   help='Hash algorithm')
    opt.add_option('-u', '--username', dest='username', type='string', default='',
                   help='Authentication username')
    opt.add_option('-n', '--nonce', dest='nonce', type='string', default='',
                   help='Challenge nonce')
    opt.add_option('-U', '--uri', dest='uri', type='string', default='',
                   help='Authentication URI')
    opt.add_option('-r', '--response', dest='response', type='string', default='',
                   help='Challenge response')
    opt.add_option('-R', '--realm', dest='realm', type='string', default='',
                   help='Challenge realm')
    opt.add_option('-m', '--method', dest='method', type='string', default='REGISTER',
                   help='SIP Method challenged, default: %default')
    opt.add_option('-p', '--password', dest='password', type='string', default='',
                   help='SIP cleartext password')

    options, args = opt.parse_args(sys.argv[1:])
    if args[0] not in ('check', 'crack'):
        print("ERROR: action must be one of crack or check")
        sys.exit(-1)
    else:
        action = args[0]

    auth = SIPAuth(debug=options.debug, username=options.username, \
            nonce=options.nonce, uri=options.uri, \
            response=options.response, method=options.method, \
            algorithm=options.algorithm, password=options.password)

    if options.authorization:
        auth.parseAuthorization(options.authorization)

    if options.debug:
        print('Challenge response: {}'.format(options.response))
    if auth.username:
        print("ERROR: username is missing")
        sys.exit(-1)
    if auth.realm:
        print("ERROR: realm is missing")
        sys.exit(-1)
    if auth.uri:
        print("ERROR: uri is missing")
        sys.exit(-1)
    if auth.method:
        print("ERROR: method missing")
        sys.exit(-1)
    if auth.nonce:
        print("ERROR: nonce missing")
        sys.exit(-1)

    if action == 'check':
        if auth.password:
            print("ERROR: password is missing")
            sys.exit(-1)
        else:
            auth.password = options.password
        expected_response = auth.calculateHash()

        if expected_response == auth.response:
            print("OK: the password is {}".format(options.password))
        else:
            print("ERROR: the password {} do not match".format(options.password))

    elif action == 'crack':
        if auth.response:
            print("ERROR: response missing")
            sys.exit(-1)
        else:
            auth.response = options.response

        auth.crack(encoding='ascii')
