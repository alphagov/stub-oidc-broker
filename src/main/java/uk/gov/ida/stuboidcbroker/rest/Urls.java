package uk.gov.ida.stuboidcbroker.rest;

public interface Urls {

    interface StubBroker {
        String REDIRECT_FORM_URI = "/formPost/validateAuthenticationResponse";
        String REDIRECT_URI = "/authenticationCallback";
    }

    interface StubOp {
        String AUTHORISATION_ENDPOINT_URI = "/authorize";
        String USERINFO_URI = "/userinfo";
        String AUTHORISATION_ENDPOINT_FORM_URI = "/authorizeFormPost/authorize";
    }

    interface Directory {
        String REGISTERED_IDPS = "/organisation/idp";
        String REGISTERED_BROKERS = "/organisation/broker";
    }

    interface Middleware {
        String REGISTRATION_URI = "/register";
        String TOKEN_URI = "/sender";
    }
}
