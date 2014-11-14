Tinytest.add('we can have a mitre config', function(test) {
  if (Meteor.isServer) {
    ServiceConfiguration.configurations.remove({ service: 'mitre'});
    ServiceConfiguration.configurations.insert({
      service: 'mitre',
      clientId: '123',
      loginStyle: 'redirect',
      secret: 'wontTell',
      issuer: 'https://myauthserver.com',
      requestPermissions: [ 'email', 'userinfo' ]
    });
    test.equal(ServiceConfiguration.configurations.findOne({ service: 'mitre' }) != null, true);
    test.equal(ServiceConfiguration.configurations.find({ service: 'mitre' }).count(), 1);
  }
});

Tinytest.add('there is a Mitre object on the client', function(test) {
  if (Meteor.isClient) {
    test.equal(Mitre.requestCredential != null, true);
  }
});
