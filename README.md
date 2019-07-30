# SIP-Auth-helper
Simple Python script to check and work with SIP challenge requests

With this script you can calculate the challenge hash and check the challenge response against a cleartext password.

## Usage

```
$ python SIPAuth.py -h
Usage: SIPAuth.py [OPTIONS] <crack|check>
This script helps you checking the SIP authentication, the script provides to actions:

- crack:    given the data of challenge response the script will try to bruteforce the password.
            Required options: username, nonce, uri, response, realm, method

- check:    given the data of the challenge response and the cleartext password the script will calculate the hash and check if the password is correct
            Required options: username, nonce, uri, realm, method, password

- hash:     calculate the has of the given text (-t) using the defined algorithm (-A).
            Required options: text, hash

You can specify all the challenge response data using the script options or you can let the script trying to parse the string from the Authorization header using the -a option, in this case you should give to the option the the header value after the 'Digest' keyword, in order to provide the comma-separated response values


Options:
  -h, --help            show this help message and exit
  -d                    Run in debug mode
  -a AUTHORIZATION, --authorization=AUTHORIZATION
                        Try to get username, realm, nonce, uri and response
                        from the authorization header, the header must be
                        after the "Digest" keyword
  -A ALGORITHM, --algorithm=ALGORITHM
                        Hash algorithm, default: MD5
  -u USERNAME, --username=USERNAME
                        Authentication username
  -n NONCE, --nonce=NONCE
                        Challenge nonce
  -U URI, --uri=URI     Authentication URI
  -r RESPONSE, --response=RESPONSE
                        Challenge response
  -R REALM, --realm=REALM
                        Challenge realm
  -m METHOD, --method=METHOD
                        SIP Method challenged, default: REGISTER
  -p PASSWORD, --password=PASSWORD
                        SIP cleartext password
  -t TEXT, --text=TEXT  Text to calculate the hash
```

### Calculating an hash

The script can caluclate an hash of a given string, support hash lagorithms are *MD5*, *SHA*, *SHA-256*, *SHA-512*. You can calculate an hash via the `hash` action, you must provide the cleartext string via the `-t` switch.

```
$ python SIPAuth.py -t ThisisMysuperSSecretpass hash
d63524ecc5f20fa07df4155da1cad888
```

### Manually calculate a challenge response hash

The challenge response hash is the result of the following hash functions:

```
- A1: hash(<username>:<realm>:<password>)
- A2: hash(<METHOD>:<domain>)
- B:  hash(A1:<nonce>:A2)
```

### Verify a challenge response hash

You can verify a challenge response hash quite easily, all you need is the `Authorization` header of the response and the cleartext password, lets suppose the password is `ThisisMysuperSSecretpass` and the Authorization header:

```
Authorization: Digest username="user500", realm="example.com", nonce="0D2179767B0F3F5D000000008EE8243A", uri="sip:example.com", response="0d552042fff0df5a46a383fabcb79909"
```

you can execute the script using the `-a` switch and the `check` action

```
$ python ./SIPAuth.py -a 'username="user500", realm="example.com", nonce="0D2179767B0F3F5D000000008EE8243A", uri="sip:example.com", response="0d552042fff0df5a46a383fabcb79909"' -p ThisisMysuperSSecretpass -A MD5 -d check
Parsed Authorization header:
uri: sip:example.com
response: 0d552042fff0df5a46a383fabcb79909
nonce: 0D2179767B0F3F5D000000008EE8243A
username: user500
realm: example.com
algorithm: MD5
Challenge response:
Calculating MD5 hash:
A1 hash MD5(user500:example.com:ThisisMysuperSSecretpass): 2247aed1c8d4df39049fad618eb3cd6d
A2 hash MD5(REGISTER:sip:example.com): 0264b00abe5b31d87fb22979689b883f
B  hash MD5(2247aed1c8d4df39049fad618eb3cd6d:0D2179767B0F3F5D000000008EE8243A:0264b00abe5b31d87fb22979689b883f): 0d552042fff0df5a46a383fabcb79909
OK: the password is ThisisMysuperSSecretpass
```

If you don't have the Authorizaion header you can pass all the parts of the hash via the command switches.

### Cracking a password

You can also let the script guessing the password:

```
$ python ./SIPAuth.py -a 'username="user500", realm="example.com", nonce="0D2179767B0F3F5D000000008EE8243A", uri="sip:example.com", response="d331f3b937bca09d0eaa1d5bf08b731f"' -A MD5 crack
Cleartext password is: 123
```

*NOTE:* this script isn't suitable to crack complex passwords, performaces are very poor.
