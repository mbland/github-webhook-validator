/* jshint node: true */

'use strict'

var bufferEq = require('buffer-equal-constant-time')
var fs = require('fs')
var crypto = require('crypto')

var exports = module.exports = {}

exports.getKeyFiles = function(defaultKeyFile, builderConfigs,
  parseKeyLabelFromConfig) {
  if (!parseKeyLabelFromConfig) {
    parseKeyLabelFromConfig = function(config) { return config.branch }
  }
  if (!builderConfigs) { builderConfigs = [] }

  var files = builderConfigs.map(function(config) {
    var keyLabel = parseKeyLabelFromConfig(config)
    if (config.secretKeyFile) {
      return { label: keyLabel, file: config.secretKeyFile }
    }
  })
  if (defaultKeyFile) {
    files.push({ label: '<default>', file: defaultKeyFile })
  }
  return files.filter(function(item) { return item !== undefined })
}

exports.loadKeyFile = function(keyLabel, keyFileName) {
  return new Promise(function(resolve, reject) {
    fs.readFile(keyFileName, 'utf8', function(err, secretKey) {
      if (err) { return reject(new Error(keyFileName + ': ' + err.message)) }
      resolve({ label: keyLabel, key: secretKey.trim() })
    })
  })
}

exports.loadKeyDictionary = function(defaultKeyFile, builderConfigs,
  parseKeyLabelFromConfig) {
  var dictionary = {}
  var loadKeyPromise = Promise.resolve(dictionary)

  var addToKeyDictionary = function(entry) {
    if (entry.label) { dictionary[entry.label] = entry.key }
  }

  var keyFiles = exports.getKeyFiles(
    defaultKeyFile, builderConfigs, parseKeyLabelFromConfig)

  keyFiles.map(function(item) {
    loadKeyPromise = loadKeyPromise.then(function(keyEntry) {
      addToKeyDictionary(keyEntry)
      return exports.loadKeyFile(item.label, item.file)
    })
  })
  return loadKeyPromise.then(function(keyEntry) {
    addToKeyDictionary(keyEntry)
    return dictionary
  })
}

exports.validatePayload = function(rawBody, signature, secretKey) {
  if (!(signature || secretKey)) { return true }
  if (!(signature && secretKey)) { return false }

  var algorithmAndHash = signature.split('=')
  if (algorithmAndHash.length !== 2) { return false }

  try {
    // Replace bufferEq() once https://github.com/nodejs/node/issues/3043 is
    // resolved and the standard library implementation is available.
    var hmac = crypto.createHmac(algorithmAndHash[0], secretKey)
    var computed = new Buffer(hmac.update(rawBody, 'utf8').digest('hex'))
    var header = new Buffer(algorithmAndHash[1])
    return bufferEq(computed, header)
  } catch (err) {
    return false
  }
}

exports.ValidationError = function(keyLabel, webhookId, ip) {
  this.keyLabel = keyLabel
  this.webhookId = webhookId
  this.ip = ip
  this.toString = function() {
    return 'invalid webhook: ' + [keyLabel, webhookId, ip].join(' ')
  }
}

exports.parseKeyLabelFromBranch = function(rawBody) {
  var branchMatch = new RegExp('"ref": ?"refs/heads/([^"]*)"').exec(rawBody)
  return (branchMatch !== null) ? branchMatch[1] : null
}

exports.middlewareValidator = function(keyDictionary, parseKeyLabelFromBody) {
  if (!parseKeyLabelFromBody) {
    parseKeyLabelFromBody = exports.parseKeyLabelFromBranch
  }
  return function(req, res, buf, encoding) {
    var webhookId = req.get('X-GitHub-Delivery') || '<unknown>'
    var signature = req.get('X-Hub-Signature')
    var rawBody = buf.toString(encoding)
    var keyLabel = parseKeyLabelFromBody(rawBody) || '<default>'
    var secretKey = keyDictionary[keyLabel] || keyDictionary['<default>']

    if (!exports.validatePayload(rawBody, signature, secretKey)) {
      throw new exports.ValidationError(keyLabel, webhookId, req.ip)
    }
  }
}
