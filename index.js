module.exports = main

var util = require('util');
var debug;
if (util.debuglog)
  debug = util.debuglog('ssh-key-decrypt');
else if (/\bssh-key-decrypt\b/i.test(process.env.NODE_DEBUG || ''))
  debug = function()
    {
    var msg = util.format.apply(util, arguments);
    console.error('%s %s', 'SSH-KEY-DECRYPT', msg);
    };
else
  debug = function() {};

var crypto = require('crypto');
var assert = require('assert');

var keyBytes =
  {
  'DES-EDE3-CBC': 24,
  'DES-CBC': 8,
  'AES-128-CBC': 16,
  'AES-192-CBC': 24,
  'AES-256-CBC': 32
  };


function main(data, passphrase, outEnc)
  {
  if (Buffer.isBuffer(data))
    {
    data = data.toString('ascii');
    }

  if (!outEnc)
    {
    outEnc = 'buffer';
    }

  // Make sure it looks like a RSA private key before moving forward
  var lines = data.trim().split('\n');
  assert.equal(lines[0], '-----BEGIN RSA PRIVATE KEY-----');
  assert.equal(lines[lines.length - 1], '-----END RSA PRIVATE KEY-----');
  var l = 1;

  var result;
  if (lines[1] === 'Proc-Type: 4,ENCRYPTED')
    {
    var dekInfo = lines[2];
    assert.equal(dekInfo.slice(0, 10), 'DEK-Info: ');
    dekInfo = dekInfo.slice(10).split(',');
    var type = dekInfo[0];
    var iv = new Buffer(dekInfo[1], 'hex');
    assert.equal(lines[3], '');
    var encData = lines.slice(4, -1).join('');
    result = decrypt(encData, type, passphrase, iv, outEnc);
    }
  else
    {
    var data = lines.slice(1, -1).join('');
    result = formatOut(data, outEnc);
    }

  return result;
  }

function formatOut(data, outEnc)
  {
  var result;
  switch (outEnc)
    {
    case 'base64':
      result = data;
      break;

    case 'buffer':
      result = new Buffer(data, 'base64');
      break;

    default:
      result = new Buffer(data, 'base64').toString(outEnc);
      break;
    }
  return result;
  }

function decrypt(encData, type, passphrase, iv, outEnc)
  {
  debug('decrypt', type, outEnc);
  var key = passphraseToKey(type, passphrase, iv);
  var dec = crypto.createDecipheriv(type, key, iv);
  var data = '';
  data += dec.update(encData, 'base64', 'base64');
  data += dec.final('base64');
  return formatOut(data, outEnc);
  }

// port of EVP_BytesToKey, as used when decrypting PEM keys
function passphraseToKey(type, passphrase, salt)
  {
  debug('passphraseToKey', type, passphrase, salt);
  var nkey = keyBytes[type];

  if (!nkey)
    {
    var allowed = Object.keys(keyBytes);
    throw new TypeError('Unsupported type. Allowed: ' + allowed);
    }

  var niv = salt.length;
  var saltLen = 8;
  if (salt.length !== saltLen)
    salt = salt.slice(0, saltLen);
  var mds = 16;
  var addmd = false;
  var md_buf;
  var key = new Buffer(nkey);
  var keyidx = 0;

  while (true)
    {
    debug('loop nkey=%d mds=%d', nkey, mds);
    var c = crypto.createHash('md5');

    if (addmd)
      c.update(md_buf);
    else
      addmd = true;

    if (!Buffer.isBuffer(passphrase))
      c.update(passphrase, 'ascii');
    else
      c.update(passphrase);

    c.update(salt);
    md_buf = c.digest('buffer');

    var i = 0;
    while (nkey && i < mds)
      {
      key[keyidx++] = md_buf[i];
      nkey--;
      i++;
      }

    var steps = Math.min(niv, mds - i);
    niv -= steps;
    i += steps;

    if ((nkey == 0) && (niv == 0)) break;
    }

  return key
  }

