var crypto = require('crypto');
var assert = require('assert');
var fs = require('fs');
var path = require('path');

var decrypt = require('./index.js');

// All the fixtures should decrypt to this key
var unenc = path.resolve(__dirname, 'fixtures', 'id_rsa_unencrypted');
unenc = new Buffer(fs.readFileSync(unenc, 'ascii')
    .trim()
    .split('\n')
    .slice(1, -1)
    .join(''), 'base64');

var tests =
  [
  'aes128',
  'aes192',
  'aes256',
  'des3',
  'des'
  ];

tests = tests.map(function(t)
                    {
                    return 'enc_' + t + '_asdf';
                    });
tests.push('unencrypted');
tests.push(null);

tests.forEach(test);

function test(f, n)
  {
  if (!f)
    {
    console.log('0..%d', n);
    return;
    }

  var file;
  var fileData;
  var ok;

  ok = tryThis(function()
    {
    file = path.resolve(__dirname, 'fixtures', 'id_rsa_' + f)
    fileData = fs.readFileSync(file, 'ascii');
    }, n, f, 'failed reading test key');

  if (!ok)
    return;

  var data;
  ok = tryThis(function()
    {
    assert(data = decrypt(fileData, 'asdf'));
    assert(Buffer.isBuffer(data), 'should be buffer');
    }, n, f, 'failed decryption');

  if (!ok)
    return;

  var hex;
  ok = tryThis(function()
    {
    assert(hex = decrypt(fileData, 'asdf', 'hex'));
    assert.equal(typeof hex, 'string');
    assert.equal(hex, data.toString('hex'));
    }, n, f, 'failed hex decryption');

  if (!ok)
    return;

  var base64;
  ok = tryThis(function()
    {
    assert(base64 = decrypt(fileData, 'asdf', 'base64'));
    assert.equal(typeof base64, 'string');
    assert.equal(base64, data.toString('base64'));
    }, n, f, 'failed base64 decryption');

  if (!ok)
    return;

  ok = tryThis(function()
    {
    assert.equal(data.length, unenc.length);
    }, n, f, 'length differs');

  if (!ok)
    return;

  for (var i = 0; i < data.length; i++)
    {
    ok = tryThis(function()
      {
      assert.equal(data[i], unenc[i]);
      }, n, f, 'differs at position ' + i);

      if (!ok)
        return;
    }

  console.log('ok %d %s\n', n+1, f);
  }

function tryThis(fn, n, f, msg)
  {
  try
    {
    fn();
    return true;
    }
  catch (er)
    {
    console.log('not ok %d %s', n+1, f);
    var m = '';
    if (msg)
      m = msg + '\n';
    m += er.stack // er.message;
    console.log('# ' + m.split('\n').join('\n# '));
    console.log('');
    return false;
    }
  }
