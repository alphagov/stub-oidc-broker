package uk.gov.ida.stuboidcclient.configuration;

import io.dropwizard.Configuration;

public class StubOidcClientConfiguration extends Configuration {

    private String authorisationEndpointURI;
    private String redirectURI;
    private String providerTokenURI;
    private String providerUserInfoURI;
    private String redisURI;
    private String redirectFormPostURI;
    private String authorisationEndpointFormPostURI;

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

    public String getRedisURI() {
        return redisURI;
    }

    public String getRedirectFormPostURI() {
        return redirectFormPostURI;
    }

    public String getAuthorisationEndpointFormPostURI() {
        return authorisationEndpointFormPostURI;
    }
}
