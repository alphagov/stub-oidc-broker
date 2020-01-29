package uk.gov.ida.stuboidcbroker.rest;

public interface Urls {

    interface StubBrokerClient {
        String REDIRECT_FORM_URI = "/formPost/validateAuthenticationResponseForService";
        String REDIRECT_URI = "/authenticationCallback";
        String USER_INFO = "/userinfo";
        String RESPONSE_FOR_BROKER = "/authorizeFormPost/response";
    }

    interface StubBrokerOPProvider {
        String AUTHORISATION_ENDPOINT_URI = "/authorize";
        String USERINFO_URI = "/userinfo";
        String TOKEN_URI = "/token";
        String AUTHORISATION_ENDPOINT_FORM_URI = "/authorizeFormPost/authorize";
    }

    interface Directory {
        String REGISTERED_IDPS = "/organisation/idp/";
        String REGISTERED_BROKERS = "/organisation/broker/";
        String VERIFY_CLIENT_TOKEN = "/verify-client-token";
    }

    interface Middleware {
        String REGISTRATION_URI = "/register";
    }

    interface IDP {
        String AUTHENTICATION_URI = "/authentication";
        String CREDENTIAL_URI = "/issue/jwt/credential";
    }
}
