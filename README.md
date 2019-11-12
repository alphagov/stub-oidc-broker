# stub-oidc-broker

Stub OIDC Broker is a very simple stub implementation of an OpenID Connect client which uses the Hybrid flow. There is currently no Trust Infrastructure in this implementation and it is very much a work in progress.

You can find the Stub OpenID Connect Provider [here](https://github.com/alphagov/stub-oidc-op)

### To use stub-oidc-broker
* Ensure you have [Stub OIDC OP](https://github.com/alphagov/stub-oidc-op) up and running
* Run startup.sh
* Go to http://localhost:6610/ in your browser and click Send request

### Stub OIDC Broker runs on the PAAS 
* To deploy Stub OIDC Broker simply login to the PAAS and select the build-learn space. 
* Run './gradlew pushToPaas' and this will deploy the app.

### For more information about Open ID Connect - 
* Open ID Connect Spec - https://openid.net/specs/openid-connect-core-1_0.html
* Diagrams of all the OpenID Connect flows - https://medium.com/@darutk/diagrams-of-all-the-openid-connect-flows-6968e3990660
* Dev overflow of OpenID Connect - https://developers.onelogin.com/openid-connect

## License

[MIT](https://github.com/alphagov/stub-oidc-broker/blob/master/LICENCE)
