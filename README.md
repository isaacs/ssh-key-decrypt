# ssh-key-decrypt

Decrypt encrypted ssh private keys

## USAGE

```javascript
var decrypt = require('ssh-key-decrypt');

// you have to actually know this already of course.
var passphrase = 'hoohah';

var fs = require('fs');
var path = require('path');

var keyfile = path.resolve(process.env.HOME, '.ssh', 'id_rsa');
var fileData = fs.readFileSync(keyfile, 'ascii');

var key = decrypt(fileData, passphrase);

// now key is the decoded data as a buffer
// You can also optionally pass in an output encoding

var b64Key = decrypt(fileData, passphrase, 'base64');
```

## `decrypt(data, passphrase, [outEnc='buffer'])`

Data can be either a string or a buffer.  It is the contents of the
key file.

If the file is not encrypted, then the passphrase doesn't matter.

If the file is encrypted, then it'll decrypt it.

Either way, the data is returned in the output encoding specified.

## WARNING

This module is synchronous, as it performs no I/O.  However, it can
potentially be kind of slow, since it does a bunch of crypto and
hashes, so do not call it often or in hot code paths.

Also, as this is crypto, and thus only either exactly right or
extremely wrong, it throws if anything unexpected is encountered.

## Supported Ciphers

* des3, aka DES-EDE3-CBC
* des, aka DES-CBC
* aes128, aka AES-128-CBC
* aes192, aka AES-192-CBC
* aes256, aka AES-256-CBC

The cipher type is determined from the file.  You do not have to
specify this.
