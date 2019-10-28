package uk.gov.ida.stuboidcclient.configuration;

import io.dropwizard.Configuration;

public class StubOidcClientConfiguration extends Configuration {

    private String stubOpURI;
    private String stubClientURI;
    private String redisURI;

    public String getStubOpURI() {
        return stubOpURI;
    }

    public String getStubClientURI() {
        return stubClientURI;
    }

    public String getRedisURI() {
        return redisURI;
    }
}
