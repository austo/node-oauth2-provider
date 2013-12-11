var sinon = require('sinon'),
  should = require('chai').should(),
  serializer = require('serializer');

var OAuthProvider = require('../');

describe('Provider', function () {
  var parseStub,
    createSerializerStub,
    oAuth2Provider,
    access_token;

  describe('login', function () {
    beforeEach(function () {
      var crypt_key = '123131',
        sign_key = 'asdfasdfas';


      // create parse stub that will be used to parse incoming requests
      parseStub = sinon.stub();
      access_token = '123412341234124312341234';

      // stub method to return object that has parseStub for parser
      createSerializerStub = sinon.stub(serializer, 'createSecureSerializer');
      createSerializerStub.withArgs(crypt_key, sign_key).returns({
        parse: parseStub
      });

      oAuth2Provider = createProvider();
    });

    afterEach(function () {
      createSerializerStub.restore();
    });

    var accessTokenKey = 'access_token';
    // for backwards compatibility

    it('should return function that emits access_token event with parsed user data if token can be parsed from request', function () {
      // SETUP

      var user_id = 'james',
        client_id = '1231231',
        dateString = '01/05/2012',
        extra_data = 'wadfasdfasfasdfas';

      // below data result from serialization
      var expectedParsedData = [user_id, client_id, dateString, extra_data];
      // setup serializer so that returns above data for that access token
      parseStub.withArgs(access_token).returns(expectedParsedData);

      oAuth2Provider.emit = sinon.spy();

      // TEST
      // build arguments that are passed to middleware function
      var req = {
        query: {
          'access_token': access_token
        }
      };

      var nextFunction = function () {};
      // get login middle ware function, and invoke it with above arguments
      var middlewareFunction = oAuth2Provider.login();
      middlewareFunction(req, {}, nextFunction);

      // SHOULD
      // make sure emit was called with correct arguments
      oAuth2Provider.emit.calledOnce.should.equal(true);
      var callArgs = oAuth2Provider.emit.firstCall.args;
      callArgs[0].should.eql('access_token');
      callArgs[1].should.eql(req);
      callArgs[2].should.eql({
        user_id: user_id,
        client_id: client_id,
        extra_data: extra_data,
        grant_date: new Date(dateString)
      });
      callArgs[3].should.equal(nextFunction);
    });

    it('should write error to response if cannot parse access token', function () {
      // SETUP
      var errorMessage = 'could not parse data';
      // change serializer to throw an error with the access token
      parseStub.withArgs(access_token).throws({
        message: errorMessage
      });

      var req = {
        query: {
          'access_token': access_token
        }
      },
        res = {
          writeHead: sinon.spy(),
          end: sinon.stub()
        };

      // TEST
      // get login middleware function, and invoke it with above arguments
      var middlewareFunction = oAuth2Provider.login();
      middlewareFunction(req, res);

      // SHOULD
      res.writeHead.calledWith(400).should.be.ok;
      res.end.calledWith(errorMessage).should.be.ok;
    });
  });
});



// utility methods
var createProvider = function (crypt_key, sign_key) {
  var crypt_key = crypt_key || '123131',
    sign_key = sign_key || 'asdfasdfas';

  return new OAuthProvider({
    crypt_key: crypt_key,
    sign_key: sign_key
  });
};