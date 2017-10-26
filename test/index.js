'use strict'

var path = require('path')
var chai = require('chai')
var chaiAsPromised = require('chai-as-promised')
var httpMocks = require('node-mocks-http')
var crypto = require('crypto')
var validator = require('../index')

var expect = chai.expect
chai.should()
chai.use(chaiAsPromised)

function makeSignature(payload, secret) {
  return 'sha1=' +
    crypto.createHmac('sha1', secret).update(payload, 'utf8').digest('hex')
}

function check(done, cb) {
  return function(err) { try { cb(err); done() } catch (e) { done(e) } }
}

describe('PayloadValidator', function() {
  var keyPaths = [
    'secret0',
    'secret1',
    'secret2'
  ].map(function (item) { return path.join(__dirname, 'data', item) })
  var defaultKeyPath = path.join(__dirname, 'data', 'defaultKey')

  describe('getKeyFiles', function() {
    it('should return an empty array if no files specified', function() {
      expect(validator.getKeyFiles(undefined)).to.be.empty
    })

    it('should provide the default key file only', function() {
      expect(validator.getKeyFiles('keys/defaultKey')).to.eql([
        { label: '<default>', file: 'keys/defaultKey' }
      ])
    })

    it('should provide only branch keys with keys', function() {
      var branchConfigs = [
        { branch: 'foo', secretKeyFile: 'keys/fooKey' },
        { branch: 'bar' },
        { branch: 'baz', secretKeyFile: 'keys/barKey' }
      ]
      expect(validator.getKeyFiles('keys/defaultKey', branchConfigs)).to.eql([
        { label: 'foo', file: 'keys/fooKey' },
        { label: 'baz', file: 'keys/barKey' },
        { label: '<default>', file: 'keys/defaultKey' }
      ])
    })
  })

  describe('loadKeyFile', function() {
    it('should fail for a nonexistent file', function() {
      return validator.loadKeyFile('<default>', 'nonexistent_file')
        .should.be.rejectedWith(Error, 'nonexistent_file: ENOENT')
    })

    it('should succeed for an existing key file', function() {
      return validator.loadKeyFile('<default>', keyPaths[0])
        .should.become({ label: '<default>', key: 'deadbeef' })
    })
  })

  describe('loadKeyDictionary', function() {
    it('should return an empty dictionary if no keys defined', function() {
      return validator.loadKeyDictionary().should.become({})
    })

    it('should provide the default key file only', function() {
      return validator.loadKeyDictionary(defaultKeyPath)
        .should.become({ '<default>': 'default secret' })
    })

    it('should provide the default key and every branch key', function() {
      var branchConfigs = [
        { branch: 'foo', secretKeyFile: keyPaths[0] },
        { branch: 'bar', secretKeyFile: keyPaths[1] },
        { branch: 'baz', secretKeyFile: keyPaths[2] }
      ]
      return validator.loadKeyDictionary(defaultKeyPath, branchConfigs)
        .should.become({
          '<default>': 'default secret',
          'foo': 'deadbeef',
          'bar': 'feedbead',
          'baz': 'secret the third'
        })
    })

    it('should not create branch entries if no default', function() {
      var branchConfigs = [
        { branch: 'foo', secretKeyFile: keyPaths[0] },
        { branch: 'bar' },
        { branch: 'baz', secretKeyFile: keyPaths[2] }
      ]
      return validator.loadKeyDictionary(undefined, branchConfigs)
        .should.become({
          'foo': 'deadbeef',
          'baz': 'secret the third'
        })
    })

    it('should fail if a key file fails to open', function() {
      var branchConfigs = [
        { branch: 'foo', secretKeyFile: keyPaths[0] },
        { branch: 'bar', secretKeyFile: 'nonexistent_file' },
        { branch: 'baz', secretKeyFile: keyPaths[2] }
      ]
      return validator.loadKeyDictionary(undefined, branchConfigs)
        .should.be.rejectedWith(Error, 'nonexistent_file: ENOENT')
    })
  })

  describe('validatePayload', function() {
    var payload = '{ "ref": "refs/heads/18f-pages" }'
    var secret = 'deadbeef'
    var signature = makeSignature(payload, secret)

    it('should pass if no signature and no secret defined', function() {
      expect(validator.validatePayload(payload)).to.be.true
    })

    it('should fail if signature defined and no secret defined', function() {
      expect(validator.validatePayload(payload, signature)).to.be.false
    })

    it('should fail if signature not defined and secret defined', function() {
      expect(validator.validatePayload(payload, null, secret)).to.be.false
    })

    it('should pass if signature matches payload', function() {
      expect(validator.validatePayload(payload, signature, secret)).to.be.true
    })

    it('should fail if signature does not match payload', function() {
      expect(validator.validatePayload(payload, signature, secret + ' extra'))
        .to.be.false
    })

    it('should fail if the signature algorithm is not supported', function() {
      var algorithmAndHash = signature.split('=')
      signature = 'foobar=' + algorithmAndHash[1]
      expect(validator.validatePayload(payload, signature, secret))
        .to.be.false
    })

    it('should properly handle strings with UTF-8 characters', function() {
      // Note the apostrophe in `it’s` is a UTF-8 smart quote.
      var payload = '"description": "Guide to help agencies understand what ' +
        'it’s like to work with 18F. ",'
      signature = makeSignature(payload, secret)
      expect(signature).to.equal(
        'sha1=6364b3c77dc014e0226e541fc47615141e54428d')
      expect(validator.validatePayload(payload, signature, secret)).to.be.true
    })
  })

  describe('parseKeyLabelFromBranch', function() {
    var payload = '{ "ref": "refs/heads/18f-pages" }'

    it('should parse the branch from the payload', function() {
      expect(validator.parseKeyLabelFromBranch(payload)).to.eql('18f-pages')
    })

    it('should return null if no branch ref is present', function() {
      expect(validator.parseKeyLabelFromBranch('')).to.be.null
    })
  })

  describe('ValidationError', function() {
    it('should be an Error', function() {
      try {
        throw new validator.ValidationError('foobar', 'bazquux', '127.0.0.1')
      } catch (err) {
        err.keyLabel.should.equal('foobar')
        err.webhookId.should.equal('bazquux')
        err.ip.should.equal('127.0.0.1')
        err.toString().should.equal('Error: invalid webhook: ' +
          'foobar bazquux 127.0.0.1')
        err.should.be.an('Error')
      }
    })
  })

  describe('middlewareValidator', function() {
    var payload
    var keyDictionary
    var webhookId = '01234567-0123-0123-1234-0123456789ab'
    var ipAddr = '127.0.0.1'
    var httpOptions

    beforeEach(function() {
      payload = '{ "ref": "refs/heads/18f-pages" }'
      keyDictionary = {}
      httpOptions = { headers: { 'X-GitHub-Delivery': webhookId } }
    })

    var addSignatureToHttpHeaders = function(rawBody, secret) {
      httpOptions.headers['X-Hub-Signature'] = makeSignature(rawBody, secret)
    }

    var loadKeyDictionary = function(done) {
      var branchConfigs = [
        { branch: '18f-pages', secretKeyFile: keyPaths[0] }
      ]
      validator.loadKeyDictionary(defaultKeyPath, branchConfigs)
        .then(function(dictionary) { keyDictionary = dictionary; done() })
        .catch(done)
    }

    var middlewareValidatorTestWrapper = function(rawBody) {
      var validate = validator.middlewareValidator(keyDictionary)
      var req = httpMocks.createRequest(httpOptions)
      req.ip = ipAddr
      return function() { validate(req, undefined, rawBody, 'utf8') }
    }

    var expectedErrorMsg = function(label) {
      return 'invalid webhook: ' + [label, webhookId, ipAddr].join(' ')
    }

    it('should pass if no keys defined', function() {
      expect(middlewareValidatorTestWrapper(payload))
        .to.not.throw(validator.ValidationError)
    })

    it('should fail if no keys defined but signature present', function() {
      addSignatureToHttpHeaders(payload, 'some bogus secret')
      expect(middlewareValidatorTestWrapper(payload)).to.throw(
        validator.ValidationError, expectedErrorMsg('18f-pages'))
    })

    it('should pass if signature matches branch secret', function(done) {
      loadKeyDictionary(check(done, function() {
        addSignatureToHttpHeaders(payload, keyDictionary['18f-pages'])
        expect(middlewareValidatorTestWrapper(payload))
          .to.not.throw(validator.ValidationError)
      }))
    })

    it('should pass even if no space between key and value', function(done) {
      loadKeyDictionary(check(done, function() {
        payload = '{ "ref":"refs/heads/18f-pages" }'
        addSignatureToHttpHeaders(payload, keyDictionary['18f-pages'])
        expect(middlewareValidatorTestWrapper(payload))
          .to.not.throw(validator.ValidationError)
      }))
    })

    it('should pass if branch signature matches default', function(done) {
      loadKeyDictionary(check(done, function() {
        payload = '{ "ref": "refs/heads/18f-pages-use-default" }'
        addSignatureToHttpHeaders(payload, keyDictionary['<default>'])
        expect(middlewareValidatorTestWrapper(payload))
          .to.not.throw(validator.ValidationError)
      }))
    })

    it('should pass if no label parsed but matches default', function(done) {
      loadKeyDictionary(check(done, function() {
        payload = '{ "not_a_ref": "but still signed content" }'
        addSignatureToHttpHeaders(payload, keyDictionary['<default>'])
        expect(middlewareValidatorTestWrapper(payload))
          .to.not.throw(validator.ValidationError)
      }))
    })

    it('should fail if signature does not match secret', function(done) {
      loadKeyDictionary(check(done, function() {
        addSignatureToHttpHeaders(payload, 'some bogus secret')
        expect(middlewareValidatorTestWrapper(payload)).to.throw(
          validator.ValidationError, expectedErrorMsg('18f-pages'))
      }))
    })

    it('should fail if branch without secret and no default', function(done) {
      loadKeyDictionary(check(done, function() {
        payload = '{ "ref": "refs/heads/18f-pages-use-default" }'
        addSignatureToHttpHeaders(payload, keyDictionary['<default>'])
        keyDictionary['<default>'] = undefined
        expect(middlewareValidatorTestWrapper(payload)).to.throw(
          validator.ValidationError, expectedErrorMsg('18f-pages-use-default'))
      }))
    })

    it('should fail if no label parsed and no default defined', function(done) {
      loadKeyDictionary(check(done, function() {
        payload = '{ "not_a_ref": "but still signed content" }'
        addSignatureToHttpHeaders(payload, keyDictionary['<default>'])
        keyDictionary['<default>'] = undefined
        expect(middlewareValidatorTestWrapper(payload)).to.throw(
          validator.ValidationError, expectedErrorMsg('<default>'))
      }))
    })
  })
})
