Package.describe({
  name: 'chris2:oauth2-mitre',
  summary: 'Oauth2 flow for MitreID Connect',
  version: '0.0.3',
  git: 'git@github.com:Chris927/chris2-oauth2-mitre.git'
});

Package.onUse(function(api) {
  api.versionsFrom('1.0');
  api.addFiles('chris2:oauth2-mitre.js');
  api.addFiles('mitre_server.js', 'server');
  api.addFiles('mitre_client.js', 'client');
  api.use('service-configuration', ['client', 'server']);
  api.imply('service-configuration', 'server');
  api.use('oauth', ['client', 'server']);
  api.use('oauth2', ['client', 'server']);
  api.export('Mitre');
});

Package.onTest(function(api) {
  api.use('tinytest');
  api.use('chris2:oauth2-mitre');
  api.use('service-configuration');
  api.addFiles('chris2:oauth2-mitre-tests.js');
});
