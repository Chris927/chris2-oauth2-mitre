Tinytest.add('example', function (test) { // TODO: silly example
  test.equal(true, true);
});

Tinytest.add('there is no config originally', function(test) {
  ServiceConfiguration.configurations.remove({ service: 'mitre'});
  test.equal(ServiceConfiguration.configurations.findOne({ service: 'mitre' }), null);
  ServiceConfiguration.configurations.insert({
    service: 'mitre',
    clientId: '123',
    loginStyle: 'popup',
    secret: '234'
  });
  test.equal(ServiceConfiguration.configurations.findOne({ service: 'mitre' }) != null, true);
});

Tinytest.add('there is a Mitre object on the client', function(test) {
  if (Meteor.isClient) {
    test.equal(Mitre.requestCredential != null, true);
  }
});
