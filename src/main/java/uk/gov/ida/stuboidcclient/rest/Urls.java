package uk.gov.ida.stuboidcclient.rest;

public interface Urls {

    interface StubClient {
        String REDIRECT_FORM_URI = "/formPost/validateAuthenticationResponse";
        String REDIRECT_URI = "/authenticationCallback";
    }

    interface StubOp {
        String TOKEN_URI = "/token";
        String AUTHORISATION_ENDPOINT_URI = "/authorize";
        String USERINFO_URI = "/userinfo";
        String AUTHORISATION_ENDPOINT_FORM_URI = "/formPost/authorize";
    }
}
