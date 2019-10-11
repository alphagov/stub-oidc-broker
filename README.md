# verify-stub-client

Verify Stub OP is a very simple stub implementation of an OpenID Connect client which uses the Authentication flow. There is currently no Trust Infrastructure in this implementation and it is very much a work in progress.

You can find the Stub OpenID Connect Provider [here](https://github.com/JHjava/verify-stub-op)

### Verify Stub OP can currently peforms 3 main functions 
* Generate an Authentication Request using OpenID Connect and send it to a OpenID Connect Provider.
* Receive an Authentication Code and use that code to request an Access and ID Token from an OpenID Connect Provider.
* Receive an Access Token and use it to request user information from an OpenID Connect Provider.


### To start up verify-stub-client
* Run startup.sh
* Send an authentication request by hitting the http://localhost:6610/serviceAuthenticationRequest in your browser

### For more information about Open ID Connect - 
* Open ID Connect Spec - https://openid.net/specs/openid-connect-core-1_0.html
* Diagrams of all the OpenID Connect flows - https://medium.com/@darutk/diagrams-of-all-the-openid-connect-flows-6968e3990660
* Dev overflow of OpenID Connect - https://developers.onelogin.com/openid-connect
