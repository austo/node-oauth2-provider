'use strict';

var querystring = require('querystring'),
  serializer = require('serializer');

exports.attach = function (self) {
  self.serializer = serializer
    .createSecureSerializer(self.options.crypt_key, self.options.sign_key);

  function extend(dest, source) {
    var sources = [],
      i, l;
    if (typeof source === 'object') {
      sources.push(source);
    }
    else if (typeof source === 'array') {
      for (i = 0, l = sources.length; i < l; ++i) {
        sources.push(extend({}, source[i]));
      }
    }
    else {
      throw new Error("Invalid argument");
    }

    for (i = 0, l = sources.length; i < l; ++i) {
      for (var key in sources[i]) {
        dest[key] = sources[i][key];
      }
    }
    return dest;
  }

  function parseAuthorization(auth) {
    debugger;
    if (!auth) {
      return null;
    }
    var parts = auth.split(' ');

    if (parts.length !== 2 || parts[0] !== 'Basic') {
      return null;
    }
    debugger;
    var creds = new Buffer(parts[1], 'base64').toString(),
      i = creds.indexOf(':');

    if (i === -1) {
      return null;
    }
    var username = creds.slice(0, i),
      password = creds.slice(i + 1);

    return [username, password];
  }

  function generateAccessToken(user_id, client_id, extra_data, token_options) {
    debugger;
    token_options = token_options || {};
    var out = extend(token_options, {
      access_token: self.serializer.stringify(
        [user_id, client_id, new Date().valueOf(), extra_data]),
      refresh_token: null
    });
    return out;
  }

  function createAccessToken(user_id, client_id, cb) {
    self.emit('create_access_token',
      user_id, client_id, function (extra_data, token_options) {
        var atok = generateAccessToken(
          user_id, client_id, extra_data, token_options);

        if (self.listeners('save_access_token').length > 0) {
          self.emit('save_access_token', user_id, client_id, atok);
        }

        return cb(atok);
      });
  }

  function getAuthorization(req, res) {
    var client_id = req.query.client_id;
    var redirect_uri = req.query.redirect_uri;

    if (!client_id || !redirect_uri) {
      res.writeHead(400);
      return res.end('client_id and redirect_uri required');
    }

    // authorization form will be POSTed to same URL, so we'll have all params
    var authorize_url = req.url;

    self.emit('enforce_login', req, res, authorize_url, function (user_id) {
      // store user_id in an HMAC-protected encrypted query param
      authorize_url += '&' + querystring.stringify({
        x_user_id: self.serializer.stringify(user_id)
      });

      // user is logged in, render approval page
      self.emit('authorize_form', req, res, client_id, authorize_url);
    });
  }

  function postAuthorization(req, res) {
    var client_id = (req.query.client_id || req.body.client_id),
      redirect_uri = (req.query.redirect_uri || req.body.redirect_uri),
      response_type =
        (req.query.response_type || req.body.response_type) || 'code',
      state = (req.query.state || req.body.state),
      x_user_id = (req.query.x_user_id || req.body.x_user_id),
      code;

    var url = redirect_uri;

    switch (response_type) {
    case 'code':
      url += '?';
      break;
    case 'token':
      url += '#';
      break;
    default:
      res.writeHead(400);
      return res.end('invalid response_type requested');
    }

    if ('allow' in req.body) {
      if ('token' === response_type) {
        var user_id;

        try {
          user_id = self.serializer.parse(x_user_id);
        }
        catch (e) {
          console.error('allow/token error', e.stack);
          res.writeHead(500);
          return res.end(e.message);
        }

        self.emit('create_access_token',
          user_id, client_id,
          function (extra_data, token_options) {
            var atok =
              generateAccessToken(user_id, client_id, extra_data, token_options);

            if (self.listeners('save_access_token').length > 0) {
              self.emit('save_access_token', user_id, client_id, atok);
            }

            url += querystring.stringify(atok);

            res.writeHead(303, {
              Location: url
            });
            res.end();
          });
      }
      else {
        code = serializer.randomString(128);

        self.emit('save_grant', req, client_id, code, function () {
          var extras = {
            code: code,
          };
          // pass back anti-CSRF opaque value
          if (state) {
            extras['state'] = state;
          }
          url += querystring.stringify(extras);
          res.writeHead(303, {
            Location: url
          });
          res.end();
        });
      }
    }
    else {
      url += querystring.stringify({
        error: 'access_denied'
      });
      res.writeHead(303, {
        Location: url
      });
      res.end();
    }
  }

  function postAccessToken(req, res) {
    var client_id = req.body.client_id,
      client_secret = req.body.client_secret,
      code = req.body.code;

    if (!client_id || !client_secret) {
      var authorization = parseAuthorization(req.headers.authorization);

      if (!authorization) {
        res.writeHead(400);
        return res.end('client_id and client_secret required');
      }

      client_id = authorization[0];
      client_secret = authorization[1];
    }

    if ('password' === req.body.grant_type) {
      if (self.listeners('client_auth').length === 0) {
        res.writeHead(401);
        return res.end('client authentication not supported');
      }

      self.emit('client_auth',
        client_id, client_secret, req.body.username, req.body.password,
        function (err, user_id) {
          if (err) {
            res.writeHead(401);
            return res.end(err.message);
          }

          res.writeHead(200, {
            'Content-type': 'application/json'
          });

          createAccessToken(user_id, client_id, function (atok) {
            res.end(JSON.stringify(atok));
          });
        });
    }
    else {
      self.emit('lookup_grant', client_id, client_secret, code,
        function (err, user_id) {
          if (err) {
            res.writeHead(400);
            return res.end(err.message);
          }

          res.writeHead(200, {
            'Content-type': 'application/json'
          });

          createAccessToken(user_id, client_id, function (atok) {
            self.emit('remove_grant', user_id, client_id, code);
            res.end(JSON.stringify(atok));
          });
        });
    }
  }

  function login() {
    return function (req, res, next) {
      var data, atok, user_id, client_id, grant_date, extra_data;

      if (req.query['access_token']) {
        atok = req.query['access_token'];
      }
      else if ((req.headers['authorization'] || '').indexOf('Bearer ') === 0) {
        atok = req.headers['authorization'].replace('Bearer', '').trim();
      }
      else {
        return next();
      }

      try {
        data = self.serializer.parse(atok);
        user_id = data[0];
        client_id = data[1];
        grant_date = new Date(data[2]);
        extra_data = data[3];
      }
      catch (e) {
        res.writeHead(400);
        return res.end(e.message);
      }

      self.emit('access_token', req, {
        user_id: user_id,
        client_id: client_id,
        extra_data: extra_data,
        grant_date: grant_date
      }, next);
    };
  }

  function oauth() {
    return function (req, res, next) {
      var uri = ~req.url.indexOf('?') ?
        req.url.substr(0, req.url.indexOf('?')) : req.url;

      if (req.method === 'GET' && self.options.authorize_uri === uri) {
        getAuthorization(req, res);
      }
      else if (req.method === 'POST' && self.options.authorize_uri === uri) {
        postAuthorization(req, res);
      }
      else if (req.method === 'POST' && self.options.access_token_uri === uri) {
        debugger;
        postAccessToken(req, res);
      }
      else {
        return next();
      }
    };
  }

  self.login = login;
  self.oauth = oauth;
};