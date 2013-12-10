var qs = require('qs'),
  ee = require('events');

function OAuth2Provider(options) {
  // js_hint_no_problem
  this.options = options;
}

function parse_authorization(authorization) {
  if (!authorization) {
    return null;
  }

  var parts = authorization.split(' ');

  if (parts.length !== 2 || parts[0] !== 'Basic') {
    return null;
  }

  // TODO: do we need Buffer here?
  var creds = new Buffer(parts[1], 'base64').toString(),
    i = creds.indexOf(':');

  if (i === -1) {
    return null;
  }

  var username = creds.slice(0, i),
    password = creds.slice(i + 1);

  return [username, password];
}


OAuth2Provider.prototype.oauth = function () {

  var client_id,
    redirect_uri,
    response_type,
    state,
    x_user_id,
    client_secret,
    code,
    self = this;

  function getLogin (req, res) {
    client_id = req.query.client_id;
    redirect_uri = req.query.redirect_uri;

    if (!client_id || !redirect_uri) {
      res.writeHead(400);
      return res.end('client_id and redirect_uri required');
    }

    // authorization form will be POSTed to same URL, so we'll have all params
    var authorize_url = req.url;

    if (!self instanceof ee.EventEmitter) {
      return;
    }

    self.emit(
      'enforce_login',
      req,
      res,
      authorize_url,
      function (user_id) {
        // store user_id in an HMAC-protected encrypted query param
        authorize_url += '&' + qs.stringify({
          x_user_id: self.serializer.stringify(user_id)
        });

        // user is logged in, render approval page
        self.emit(
          'authorize_form',
          req,
          res,
          client_id,
          authorize_url);
      });
  }

  function handleLogin(req, res, next) {
    // ~int returns 0 if int = -1
    var uri = ~req.url.indexOf('?') ?
      req.url.substr(0, req.url.indexOf('?')) : req.url;

    if (req.method === 'GET' && self.options.authorize_uri === uri) {
      getLogin(req, res);
    }
    else if (req.method === 'POST' && self.options.authorize_uri === uri) {
      client_id = (req.query.client_id || req.body.client_id);
      redirect_uri = (req.query.redirect_uri || req.body.redirect_uri);
      response_type = (req.query.response_type || req.body.response_type) || 'code';
      state = (req.query.state || req.body.state);
      x_user_id = (req.query.x_user_id || req.body.x_user_id);

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

          self.emit(
            'create_access_token',
            user_id,
            client_id,
            function (extra_data, token_options) {
              var atok = self.generateAccessToken(
                user_id, client_id, extra_data, token_options);

              if (self.listeners('save_access_token').length > 0) {
                self.emit('save_access_token', user_id, client_id, atok);
              }

              url += qs.stringify(atok);

              res.writeHead(303, {
                Location: url
              });
              res.end();
            });
        }
        else {
          code = self.serializer.randomString(128);

          self.emit('save_grant', req, client_id, code, function () {
            var extras = {
              code: code,
            };

            // TODO: pass back anti-CSRF opaque? value
            if (state) {
              extras['state'] = state;
            }

            url += qs.stringify(extras);

            res.writeHead(303, {
              Location: url
            });
            res.end();
          });
        }
      }
      else {
        url += qs.stringify({
          error: 'access_denied'
        });

        res.writeHead(303, {
          Location: url
        });
        res.end();
      }

    }

    else if (req.method === 'POST' && self.options.access_token_uri === uri) {
      client_id = req.body.client_id;
      client_secret = req.body.client_secret;
      redirect_uri = req.body.redirect_uri;
      code = req.body.code;

      if (!client_id || !client_secret) {
        var authorization = parse_authorization(req.headers.authorization);

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

        self.emit(
          'client_auth',
          client_id,
          client_secret,
          req.body.username,
          req.body.password,
          function (err, user_id) {
            if (err) {
              res.writeHead(401);
              return res.end(err.message);
            }

            res.writeHead(200, {
              'Content-type': 'application/json'
            });

            self._createAccessToken(user_id, client_id, function (atok) {
              res.end(JSON.stringify(atok));
            });
          });
      }
      else {
        self.emit(
          'lookup_grant',
          client_id,
          client_secret,
          code,
          function (err, user_id) {
            if (err) {
              res.writeHead(400);
              return res.end(err.message);
            }

            res.writeHead(200, {
              'Content-type': 'application/json'
            });

            self._createAccessToken(user_id, client_id, function (atok) {
              self.emit('remove_grant', user_id, client_id, code);

              res.end(JSON.stringify(atok));
            });
          });
      }
    }

    else {
      return next();
    }
  };

  return {
    handleLogin: handleLogin
  };
};