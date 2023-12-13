# stub-oidc-broker

>**GOV.UK Verify has closed**
>
>This repository is out of date and has been archived

Stub OIDC Broker is a implementation of an OpenID Connect client and an OpenID Provider which uses the Hybrid flow. It makes up part of the Trust Framework prototype together with the following repos -  

* [Trust-Framework-RP](https://github.com/alphagov/stub-trustframework-rp)
* [Middleware](https://github.com/alphagov/middleware-in-the-middle)
* [Trust-Framework-Directory](https://github.com/alphagov/trust-framework-directory-prototype)
* [Registration](https://github.com/alphagov/tpp-registration-prototype)
* [Trust-Framework-IDP](https://github.com/alphagov/trust-framework-idp)

## Running the Trust Framework locally

### Prerequisites

* Java 11 JDK
* Git
* Gradle
* Node.js
* Python3
* Ruby

### First time clone and prepare

* Clone the `stub-oidc-broker` repo and run `./clone-trustframework-repos.sh` to clone the others.

* Install postgres (if you don't have an instance already):
  
  ```bash
  brew install postgres
  ```

### starting the apps

* Run the `./startup-all-services.sh` script.

This will start up applications to represent 2 different schemes. You can find log output under the logs directory within this repo.

The Middleware is used for establishing Mutual TLS when talking from Broker to Broker across schemes for solely the token and registration endpoints. The Directory and Registration services are used across Schemes within the Framework as a point of trust.

Use the onboarding app to add brokers and IDPs to the directory.

You can pull the latest of all the trustframework repositories  by running the `./update-trustframework-repos.sh` script.

### Registering a Broker to the Directory

* The Directory is the point of trust for the framework and the Registration service is the frontend to the Directory. A Broker/Scheme will need to be registered to the Directory before a Broker on another scheme can register to that Broker. 
* When running locally the Registration service can be located at http://localhost:5000. 
* A Broker will then need to dynamically register to a Broker on another scheme. To do so:
  * obtain the SSA and Private key created from registration on the directory Admin page http://localhost:3000/admin, and
  * use it with either the Broker in Scheme 1 http://localhost:6610 or the Broker in Scheme 2 http://localhost:5510.
* (These Private keys will usually be created offline and are only displayed to demonstrate a simplified on-boarding process.)
* Once a Broker has been registered you can begin a journey using RP-1 using http://localhost:4410 or RP-2 using http://localhost:4412.

### Troubleshooting and logging

* The logs to the applications are outputted to relevant log file in the Log directory within this repository. Apart from the Directory and the 2 IDP apps, where the logs are outputted to the log file within their respective repository. 

### Trust Framework prototype runs on the PAAS

* All Trust Framework prototype applications apart from the Middleware run on the PAAS. The Middleware runs on AWS Lightsail.
* To deploy Stub OIDC Broker simply login to the PAAS and select the build-learn space. 
* Run `./gradlew pushToPaas` and this will deploy both instances of Stub Broker to the PAAS. 

### For more information about Open ID Connect

* Open ID Connect Spec - https://openid.net/specs/openid-connect-core-1_0.html
* Diagrams of all the OpenID Connect flows - https://medium.com/@darutk/diagrams-of-all-the-openid-connect-flows-6968e3990660
* Dev overflow of OpenID Connect - https://developers.onelogin.com/openid-connect

## License

[MIT](https://github.com/alphagov/stub-oidc-broker/blob/master/LICENCE)
