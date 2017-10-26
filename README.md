# github-webhook-validator

This library provides an [Express][] middleware validator for [GitHub
webhooks][] that have a secret key defined.

[Express]:         https://expressjs.com/
[GitHub webhooks]: https://developer.github.com/webhooks/

It was primarily developed for the [pages-server][]. It enables authentication
across multiple webhooks handled by the same server.

[pages-server]: https://github.com/mbland/pages-server

## Installation

To make this library part of your project:

```sh
$ npm install github-webhook-validator --save
```

Note that [Node.js][] version 4.8.5 or higher is required; check your installed
version with `node -v`.

[Node.js]: https://nodejs.org/

## Usage

During the initialization phase of your application:

```js
var express = require('express');
var bodyParser = require('body-parser');
var webhookValidator = require('github-webhook-validator');

module.exports.launchServer = function(config) {
  // loadKeyDictionary returns a Promise that creates an object comprised of
  // `label: key` mappings.
  return webhookValidator.loadKeyDictionary(
    config.secretKeyFile, config.builders)
    .then(function(keyDictionary) { return doLaunch(config, keyDictionary); })
    .catch(function(err) { console.error('Failed to start server:', err); });
}

function doLaunch(config, keyDictionary) {
  // Once the keyDictionary is loaded, create a middlewareValidator that can
  // be passed to Express middleware body parsers.
  var middlewareOptions = {
    verify: webhookValidator.middlewareValidator(keyDictionary)
  };
  var server = express();
  server.use(bodyParser.json(middlewareOptions));

  // Continue server initialization...
}
```

## API

### loadKeyDictionary([defaultKeyFile[, builderConfigs[, parseKeyLabelFromConfig]]])

Returns a [Promise][] that will, upon success, resolve to an object comprised of
`label: key` mappings for use by the middleware validator.

[Promise]: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise

* **defaultKeyFile**: path to the file containing the secret key used to
  validate all payloads by default
* **builderConfigs**: array of objects pertaining to individual branches or
  other entities managed by the webhook server
  * Each may contain an optional **secretKeyFile** member, which will be used
    in place of the top-level **defaultKeyFile** for that builder.
* **parseKeyLabelFromConfig**: maps each element of **builderConfigs** to a
  label for the element's **secretKeyFile** contents
  * The default parser returns the value of the element's `branch` member,
    as the original use case supports differentiating webhooks by branch.

It is possible for **defaultKeyFile** to be undefined, while individual
**builderConfigs** have their own **secretKeyFile** definitions.

If no arguments are defined, the Promise will resolve to an empty object,
effectively disabling validation, except that _any incoming webhooks with the
`X-Hub-Signature` HTTP header defined will fail validation_. The solution
would be to add the secret key to the server, or to remove it from the webhook
definition.

### middlewareValidator(keyDictionary[, parseKeyLabelFromBody])

Returns a function corresponding to the `verify` function interface passed as
an option to [Express `body-parser` middleware][bp]. The returned function will
abort the request with an error message if validation fails, prior to parsing
taking place.

[bp]: https://www.npmjs.com/package/body-parser

* **keyDictionary**: the result from **loadKeyDictionary()**
* **parseKeyLabelFromBody**: maps the raw contents of the request body to a
  label for one of the keys within **keyDictionary**
  * The default parser parses the name of the branch from the `ref` field, if
    present.

**Raises:**
* **ValidationError**: if validation fails for any reason; this object
  contains:
  * **keyLabel**: the value returned from **parseKeyLabelFromBody**
  * **webhookId**: the value of the `X-GitHub-Delivery` HTTP header
  * **ip**: the IP address of the request source

If the parser returns `null` or `undefined`, or if the value does not match a
member of **keyDictionary**, the value of the **defaultKeyFile** from
**loadKeyDictionary()** will be used as the secret key, if it exists. If it
does not exist, _any incoming requests with the `X-Hub-Signature` HTTP header
will fail validation_. The fix would be to add a default key, to add a
branch-specific key, or to remove the secret key from the webhook definition.

### Open Source License

This software is made available as [Open Source software][oss-def] under the
[ISC License][].  For the text of the license, see the [LICENSE](LICENSE.md)
file.

[oss-def]:     https://opensource.org/osd-annotated
[isc license]: https://www.isc.org/downloads/software-support-policy/isc-license/
