package uk.gov.ida.verifystubclient.configuration;

import io.dropwizard.Configuration;

public class VerifyStubClientConfiguration extends Configuration {

    private String authorisationEndpointURI;
    private String redirectURI;
    private String providerTokenURI;
    private String providerUserInfoURI;

    public String getAuthorisationEndpointURI() {
        return authorisationEndpointURI;
    }

    public String getRedirectURI() {
        return redirectURI;
    }

    public String getProviderTokenURI() {
        return providerTokenURI;
    }

    public String getProviderUserInfoURI() {
        return providerUserInfoURI;
    }
}
