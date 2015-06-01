var crypto = require('crypto');
var assert = require('assert');
var fs = require('fs');
var path = require('path');
var t = require('tap');

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

tests.forEach(test);

function test(f)
  {
  var file;
  var fileData;

  tryThis(function()
    {
    file = path.resolve(__dirname, 'fixtures', 'id_rsa_' + f)
    fileData = fs.readFileSync(file, 'ascii');
    }, f, 'failed reading test key');

  var data;
  tryThis(function()
    {
    assert(data = decrypt(fileData, 'asdf'));
    assert(Buffer.isBuffer(data), 'should be buffer');
    }, f, 'failed decryption');

  var hex;
  tryThis(function()
    {
    assert(hex = decrypt(fileData, 'asdf', 'hex'));
    assert.equal(typeof hex, 'string');
    assert.equal(hex, data.toString('hex'));
    }, f, 'failed hex decryption');

  var base64;
  tryThis(function()
    {
    assert(base64 = decrypt(fileData, 'asdf', 'base64'));
    assert.equal(typeof base64, 'string');
    assert.equal(base64, data.toString('base64'));
    }, f, 'failed base64 decryption');

  tryThis(function()
    {
    assert.equal(data.length, unenc.length);
    }, f, 'length differs');

  tryThis(function()
    {
    for (var i = 0; i < data.length; i++)
      {
      assert.equal(data[i], unenc[i], 'differs at position ' + i);
      }
    }, f, 'byte check');
  }

function tryThis(fn, f, msg)
  {
  t.test(f, function (t)
    {
    t.plan(1)
    t.doesNotThrow(fn, msg)
    })
  }
