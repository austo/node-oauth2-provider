var qs = require('querystring');

var client_id,
  redirect_uri,
  response_type,
  state,
  x_user_id,
  code,
  self = this;


function postLogin(req, res) {
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