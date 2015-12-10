/**
 * Login With linkedin
 *
 * An example web application implementing OAuth2 in Cloud Code
 *
 * There will be four routes:
 * / - The main route will show a page with a Login with linkedin link
 *       JavaScript will detect if it's logged in and navigate to /main
 * /authorize - This url will start the OAuth process and redirect to linkedin
 * /oauthCallback - Sent back from linkedin, this will validate the authorization
 *                    and create/update a Parse User before using 'become' to
 *                    set the user on the client side and redirecting to /main
 * /main - The application queries and displays some of the users linkedin data
 *
 * @author Fosco Marotto (Facebook) <fjm@fb.com>
 */

/**
 * Load needed modules.
 */
var express = require('express');
var querystring = require('querystring');
var _ = require('underscore');
var Buffer = require('buffer').Buffer;

/**
 * Create an express application instance
 */
var app = express();

/**
 * linkedin specific details, including application id and secret
 */
var linkedinClientId = '78sa2dm1e0ps6h';
var linkedinClientSecret = 'pvsukjjJijc6NOEq';

var linkedinRedirectEndpoint = 'https://www.linkedin.com/uas/oauth2/authorization?';
var linkedinValidateEndpoint = 'https://www.linkedin.com/uas/oauth2/accessToken';
var linkedinUserEndpoint = 'https://api.linkedin.com/v1/people/~:(id,first-name,last-name,picture-url)';

/**
 * In the Data Browser, set the Class Permissions for these 2 classes to
 *   disallow public access for Get/Find/Create/Update/Delete operations.
 * Only the master key should be able to query or write to these classes.
 */
var TokenRequest = Parse.Object.extend("TokenRequest");
var TokenStorage = Parse.Object.extend("TokenStorage");

/**
 * Create a Parse ACL which prohibits public access.  This will be used
 *   in several places throughout the application, to explicitly protect
 *   Parse User, TokenRequest, and TokenStorage objects.
 */
var restrictedAcl = new Parse.ACL();
restrictedAcl.setPublicReadAccess(false);
restrictedAcl.setPublicWriteAccess(false);

/**
 * Global app configuration section
 */
app.set('views', 'cloud/views');  // Specify the folder to find templates
app.set('view engine', 'ejs');    // Set the template engine
app.use(express.bodyParser());    // Middleware for reading request body

/**
 * Main route.
 *
 * When called, render the login.ejs view
 */
app.get('/', function(req, res) {
  res.render('login', {});
});

/**
 * Login with linkedin route.
 *
 * When called, generate a request token and redirect the browser to linkedin.
 */
app.get('/authorize', function(req, res) {

  var redirectUri = "https://spd-genericlogin.parseapp.com/oauthCallback";
  var responseType = "code";
  var tokenRequest = new TokenRequest();
  // Secure the object against public access.
  tokenRequest.setACL(restrictedAcl);
  /**
   * Save this request in a Parse Object for validation when linkedin responds
   * Use the master key because this class is protected
   */
  tokenRequest.save(null, { useMasterKey: true }).then(function(obj) {
    /**
     * Redirect the browser to linkedin for authorization.
     * This uses the objectId of the new TokenRequest as the 'state'
     *   variable in the linkedin redirect.
     */
    res.redirect(
      linkedinRedirectEndpoint + querystring.stringify({
        client_id: linkedinClientId,
        state: obj.id,
        response_type: responseType,
        redirect_uri: redirectUri
      })
    );
  }, function(error) {
    // If there's an error storing the request, render the error page.
    res.render('error', { errorMessage: 'Failed to save auth request.'});
  });

});

/**
 * OAuth Callback route.
 *
 * This is intended to be accessed via redirect from linkedin.  The request
 *   will be validated against a previously stored TokenRequest and against
 *   another linkedin endpoint, and if valid, a User will be created and/or
 *   updated with details from linkedin.  A page will be rendered which will
 *   'become' the user on the client-side and redirect to the /main page.
 */
app.get('/oauthCallback', function(req, res) {
  var data = req.query;
  var token;
  /**
   * Validate that code and state have been passed in as query parameters.
   * Render an error page if this is invalid.
   */
  if (!(data && data.code && data.state)) {
    res.render('error', { errorMessage: 'Invalid auth response received.'});
    return;
  }
  var query = new Parse.Query(TokenRequest);
  /**
   * Check if the provided state object exists as a TokenRequest
   * Use the master key as operations on TokenRequest are protected
   */
  Parse.Cloud.useMasterKey();
  Parse.Promise.as().then(function() {
    return query.get(data.state);
  }).then(function(obj) {
    // Destroy the TokenRequest before continuing.
    return obj.destroy();
  }).then(function() {
    // Validate & Exchange the code parameter for an access token from linkedin
    return getlinkedinAccessToken(data.code);
  }).then(function(access) {
    /**
     * Process the response from linkedin, return either the getlinkedinUserDetails
     *   promise, or reject the promise.
     */
    var linkedinData = access.data;
    if (linkedinData && linkedinData.access_token) {
      token = linkedinData.access_token;
      return getlinkedinUserDetails(token);
    } else {
      return Parse.Promise.error("Invalid access request.");
    }
  }).then(function(userDataResponse) {
    /**
     * Process the users linkedin details, return either the upsertlinkedinUser
     *   promise, or reject the promise.
     */
    /*var userDataXml = userDataResponse.text;
    $userDataXml = $( userDataXml ),
    var userData = $userDataXml.find('id');*/
    var userData = userDataResponse.data;
    if (userData && userData.id) {
      return upsertlinkedinUser(token, userData);
    } else {
		return Parse.Promise.error("Unable to parse Linkedin data");
    }
  }).then(function(user) {
    /**
     * Render a page which sets the current user on the client-side and then
     *   redirects to /main
     */
    res.render('store_auth', { sessionToken: user.getSessionToken() });
  }, function(error) {
    /**
     * If the error is an object error (e.g. from a Parse function) convert it
     *   to a string for display to the user.
     */
    if (error && error.code && error.error) {
      error = error.code + ' ' + error.error;
    }
    res.render('error', { errorMessage: JSON.stringify(error) });
  });

});

/**
 * Logged in route.
 *
 * JavaScript will validate login and call a Cloud function to get the users
 *   linkedin details using the stored access token.
 */
app.get('/main', function(req, res) {
  res.render('main', {});
});

/**
 * Attach the express app to Cloud Code to process the inbound request.
 */
app.listen();

/**
 * Cloud function which will load a user's accessToken from TokenStorage and
 * request their details from linkedin for display on the client side.
 */
Parse.Cloud.define('getlinkedinData', function(request, response) {
  if (!request.user) {
    return response.error('Must be logged in.');
  }
  var query = new Parse.Query(TokenStorage);
  query.equalTo('user', request.user);
  query.ascending('createdAt');
  Parse.Promise.as().then(function() {
    return query.first({ useMasterKey: true });
  }).then(function(tokenData) {
    if (!tokenData) {
      return Parse.Promise.error('No linkedin data found.');
    }
    return getlinkedinUserDetails(tokenData.get('accessToken'));
  }).then(function(userDataResponse) {
    var userData = userDataResponse.data;
    response.success(userData);
  }, function(error) {
    response.error(error);
  });
});

/**
 * This function is called when linkedin redirects the user back after
 *   authorization.  It calls back to linkedin to validate and exchange the code
 *   for an access token.
 */
var getlinkedinAccessToken = function(code) {
  var grantType = "authorization_code";
   var redirectUri = "https://spd-genericlogin.parseapp.com/oauthCallback";

  var body = querystring.stringify({
	grant_type: grantType,
    client_id: linkedinClientId,
    client_secret: linkedinClientSecret,
    code: code,
    redirect_uri: redirectUri
  });
  return Parse.Cloud.httpRequest({
    method: 'POST',
    url: linkedinValidateEndpoint,
    headers: {
      'Accept': 'application/json',
      'User-Agent': 'Parse.com Cloud Code'
    },
    body: body
  });
}

/**
 * This function calls the linkedinUserEndpoint to get the user details for the
 * provided access token, returning the promise from the httpRequest.
 */
var getlinkedinUserDetails = function(accessToken) {
  return Parse.Cloud.httpRequest({
    method: 'GET',
    url: linkedinUserEndpoint,
    params: { oauth2_access_token: accessToken,
      format: 'json'
    },
    headers: {
      'User-Agent': 'Parse.com Cloud Code',
      'Content-Type': 'application/json'
    }
  });
}

/**
 * This function checks to see if this linkedin user has logged in before.
 * If the user is found, update the accessToken (if necessary) and return
 *   the users session token.  If not found, return the newlinkedinUser promise.
 */
var upsertlinkedinUser = function(accessToken, linkedinData) {
  var query = new Parse.Query(TokenStorage);
  query.equalTo('linkedinId', linkedinData.id);
  query.ascending('createdAt');
  var password;
  // Check if this linkedinId has previously logged in, using the master key
  return query.first({ useMasterKey: true }).then(function(tokenData) {
    // If not, create a new user.
    if (!tokenData) {
      return newlinkedinUser(accessToken, linkedinData);
    }
    // If found, fetch the user.
    var user = tokenData.get('user');
    return user.fetch({ useMasterKey: true }).then(function(user) {
      // Update the accessToken if it is different.
      if (accessToken !== tokenData.get('accessToken')) {
        tokenData.set('accessToken', accessToken);
      }
      /**
       * This save will not use an API request if the token was not changed.
       * e.g. when a new user is created and upsert is called again.
       */
      return tokenData.save(null, { useMasterKey: true });
    }).then(function(obj) {
		password = new Buffer(24);
		_.times(24, function(i) {
			password.set(i, _.random(0, 255));
		});
		password = password.toString('base64')
		user.setPassword(password);
		return user.save();
    }).then(function(user) {
		return Parse.User.logIn(user.get('username'), password);
    }).then(function(user) {
     // Return the user object.
      return Parse.Promise.as(user);
    });
  });
}

/**
 * This function creates a Parse User with a random login and password, and
 *   associates it with an object in the TokenStorage class.
 * Once completed, this will return upsertlinkedinUser.  This is done to protect
 *   against a race condition:  In the rare event where 2 new users are created
 *   at the same time, only the first one will actually get used.
 */
var newlinkedinUser = function(accessToken, linkedinData) {
  var user = new Parse.User();
  // Generate a random username and password.
  var username = new Buffer(24);
  var password = new Buffer(24);
  _.times(24, function(i) {
    username.set(i, _.random(0, 255));
    password.set(i, _.random(0, 255));
  });
  user.set("username", username.toString('base64'));
  user.set("password", password.toString('base64'));
  // Sign up the new User
  return user.signUp().then(function(user) {
    // create a new TokenStorage object to store the user+linkedin association.
    var ts = new TokenStorage();
    ts.set('linkedinId', linkedinData.id);
    ts.set('linkedinFirstname', linkedinData.firstName);
    ts.set('linkedinLastname', linkedinData.lastName);
    ts.set('accessToken', accessToken);
    ts.set('user', user);
    ts.setACL(restrictedAcl);
    // Use the master key because TokenStorage objects should be protected.
    return ts.save(null, { useMasterKey: true });
  }).then(function(tokenStorage) {
    return upsertlinkedinUser(accessToken, linkedinData);
  });
}