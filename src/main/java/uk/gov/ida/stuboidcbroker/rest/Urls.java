package uk.gov.ida.stuboidcbroker.rest;

public interface Urls {

    interface StubBroker {
        String REDIRECT_FORM_URI = "/formPost/validateAuthenticationResponse";
        String REDIRECT_URI = "/authenticationCallback";
    }

    interface StubOp {
        String TOKEN_URI = "/token";
        String AUTHORISATION_ENDPOINT_URI = "/authorize";
        String USERINFO_URI = "/userinfo";
        String AUTHORISATION_ENDPOINT_FORM_URI = "/formPost/authorize";
        String REGISTER = "/register";
    }

    interface Directory {
        String REGISTERED_IDPS = "/organisation/idp";
    }
}
