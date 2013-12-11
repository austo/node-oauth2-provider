'use strict';

var EventEmitter = require('events').EventEmitter,
  assert = require('assert'),
  util = require('util'),
  helpers = require('./helpers');

var defaults = Object.freeze({
  AUTHORIZE_URI: '/oauth/authorize',
  ACCESS_TOKEN_URI: '/oauth/access_token'
});

function setDefaults(options) {
  if (typeof options.authorize_uri !== 'string') {
    options.authorize_uri = defaults.AUTHORIZE_URL;
  }
  if (typeof options.access_token_uri !== 'string') {
    options.access_token_uri = defaults.ACCESS_TOKEN_URL;
  }
}

function Provider(options) {
  assert(typeof options === 'object');
  assert(typeof options.crypt_key === 'string');
  assert(typeof options.sign_key === 'string');

  if (!this instanceof Provider) {
    return new Provider(options);
  }

  EventEmitter.call(this);

  setDefaults(options);
  this.options = options;
  helpers.attach(this);
}

util.inherits(Provider, EventEmitter);

module.exports = Provider;