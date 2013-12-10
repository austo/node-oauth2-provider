var qs = require('querystring'),
  ee = require('events');

function handleLogin(self, req, res) {
  var client_id = req.query.client_id;
  var redirect_uri = req.query.redirect_uri;

  if (!client_id || !redirect_uri) {
    res.writeHead(400);
    return res.end('client_id and redirect_uri required');
  }

  // authorization form will be POSTed to same URL, so we'll have all params
  var authorize_url = req.url;

  if (!this instanceof ee.EventEmitter) {
    return;
  }

  this.emit(
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