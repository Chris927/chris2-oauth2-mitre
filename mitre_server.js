Mitre = {};

OAuth.registerService('mitre', 2, null, function(query) {

  var tokens = getToken(query);
  var identity = getIdentity(tokens.access_token);

  var serviceData = {
    id: identity.sub,
    accessToken: OAuth.sealSecret(tokens.access_token),
    refreshToken: OAuth.sealSecret(tokens.refresh_token),
    email: identity.email,
    username: identity.preferred_username
  };
  for (var property in identity) {
    serviceData[property] = identity[property]; // anything we received from mitre should be available in serviceData
  }
  return {
    serviceData: serviceData,
    options: {profile: identity}
  };
});

// http://developer.github.com/v3/#user-agent-required
var userAgent = "Meteor";
if (Meteor.release)
  userAgent += "/" + Meteor.release;

var getConfig = function() {
  var config = ServiceConfiguration.configurations.findOne({ service: 'mitre'});
  if (!config)
    throw new ServiceConfiguration.ConfigError();
  return config;
};

var getToken = function (query) {
  var config = getConfig();

  var response;
  try {
    response = HTTP.post(
      config.issuer + "/token", {
        headers: {
          Accept: 'application/json',
          "User-Agent": userAgent
        },
        params: {
          code: query.code,
          client_id: config.clientId,
          grant_type: 'authorization_code',
          client_secret: OAuth.openSecret(config.secret),
          redirect_uri: OAuth._redirectUri('mitre', config),
          state: query.state
        }
      });
  } catch (err) {
    throw _.extend(new Error("Failed to complete OAuth handshake with Mitre. " + err.message),
                   {response: err.response});
  }
  if (response.data.error) { // if the http response was a json object with an error attribute
    throw new Error("Failed to complete OAuth handshake with Mitre. " + response.data.error);
  } else {
    return {
      access_token: response.data.access_token,
      refresh_token: response.data.refresh_token
    };
  }
};

var getIdentity = function (accessToken) {
  try {
    return HTTP.get(
      getConfig().issuer + "/userinfo", {
        headers: {
          "User-Agent": userAgent // http://developer.github.com/v3/#user-agent-required
        },
        params: { access_token: accessToken }
      }).data;
  } catch (err) {
    throw _.extend(new Error("Failed to fetch identity from Mitre. " + err.message),
                   {response: err.response});
  }
};

Mitre.retrieveCredential = function(credentialToken, credentialSecret) {
  return OAuth.retrieveCredential(credentialToken, credentialSecret);
};

Mitre.http = {};

var getMeteorUser = function(userId) {
  var user = Meteor.users.findOne(userId);
  if (!user) throw new Error('user not found: ' + userId);
  return user;
}

var getAccessTokenOfUser = function(userId) {
  var user = getMeteorUser(userId);
  return user.services.mitre.accessToken;
}

var getRefreshTokenOfUser = function(userId) {
  var user = getMeteorUser(userId);
  return OAuth.openSecret(user.services.mitre.refreshToken);
}

var getNewAccessTokenViaRefresh = function(userId) {
  var config = getConfig();
  try {
    var body = 'grant_type=refresh_token' +
        '&refresh_token=' + getRefreshTokenOfUser(userId) +
        '&client_id=' + config.clientId +
        '&client_secret=' + OAuth.openSecret(config.secret);
    var response = HTTP.post(
      config.issuer + "/token", {
      headers: {
        Accept: 'application/json',
        'User-Agent': userAgent,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      content: body
    });
  } catch (err) {
    // we probably better to "return null", then in the caller remove the (now
    // certainly invalid) refresh token.
    throw _.extend(new Error("Failed to refresh token from Mitre. " + err.message),
                   {response: err.response});
  }
  if (!response.data) throw new Error('no data received');
  if (response.data.error) { // if the http response was a json object with an error attribute
    throw new Error("Failed to refresh token from Mitre: " + response.data.error);
  } else {
    console.log('(MITRE) successfully received new tokens for user ' + userId);
    return {
      access_token: response.data.access_token,
      refresh_token: response.data.refresh_token
    };
  }
}

var storeNewAccessToken = function(userId, newAccessToken, newRefreshToken) {
  Meteor.users.update({ _id: userId }, {
    $set: {
      'services.mitre.accessToken': newAccessToken,
      'services.mitre.refreshToken': newRefreshToken
    }
  });
}

Mitre.http.call = function(userId, method, url, options) {
  var result;

  try {
    result = doCall();
  } catch (e) {
    if (e.response && e.response.statusCode === 401) {
      console.log('(MITRE) access token may have expired, attempting refresh...');
      var tokens = getNewAccessTokenViaRefresh(userId);
      if (tokens) {
        storeNewAccessToken(userId, tokens.access_token, tokens.refresh_token);
        return doCall();
      } else {
        console.log('refresh token seems to have expired / is invalid, deleting it...');
        storeNewAccessToken(userId, null, null);
        throw e;
      }
    } else {
      throw e;
    }
  }

  function doCall() {
    var extendedOptions = _.clone(options) || {};
    extendedOptions.headers = _.extend(extendedOptions.headers || {}, {
      Authorization: 'Bearer ' + getAccessTokenOfUser(userId)
    })
    return Meteor.http.call(method, url, extendedOptions);
  }

  return result;
}
