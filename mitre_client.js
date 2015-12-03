Mitre = {};

// Request Mitre credentials for the user
// @param options {optional}
// @param credentialRequestCompleteCallback {Function} Callback function to call on
//   completion. Takes one argument, credentialToken on success, or Error on
//   error.
Mitre.requestCredential = function (options, credentialRequestCompleteCallback) {
  // support both (options, callback) and (callback).
  if (!credentialRequestCompleteCallback && typeof options === 'function') {
    credentialRequestCompleteCallback = options;
    options = {};
  }

  var config = ServiceConfiguration.configurations.findOne({service: 'mitre'});
  if (!config) {
    credentialRequestCompleteCallback && credentialRequestCompleteCallback(
      new ServiceConfiguration.ConfigError());
    return;
  }
  var credentialToken = Random.secret();

  var scope = (options && options.requestPermissions) || [];
  var flatScope = _.map(scope, encodeURIComponent).join('+');

  var loginStyle = OAuth._loginStyle('mitre', config, options);
  var redirectUri = OAuth._redirectUri('mitre', config);

  var loginUrl =
        config.issuer + '/authorize' +
        '?client_id=' + config.clientId +
        '&scope=' + flatScope +
        '&response_type=code' +
        '&redirect_uri=' + encodeURIComponent(redirectUri) +
        '&state=' + OAuth._stateParam(loginStyle, credentialToken);

  if (options.loginStyle == 'popup') {
    OAuth.showPopup(
      loginUrl,
      _.bind(credentialRequestCompleteCallback, null, credentialToken),
      {width: 900, height: 450}
    );
  } else { // redirect rather than popup
    OAuth.launchLogin({
      loginService: "mitre",
      loginStyle: 'redirect',
      loginUrl: loginUrl,
      credentialRequestCompleteCallback: credentialRequestCompleteCallback,
      credentialToken: credentialToken,
      popupOptions: { height: 600 }
    });
  }
};

Mitre.stateParam = function(loginStyle, credentialToken) {
  return OAuth._stateParam(loginStyle, credentialToken);
}

Mitre.saveDataForRedirect = function(token) {
  OAuth.saveDataForRedirect("mitre", token);
}
