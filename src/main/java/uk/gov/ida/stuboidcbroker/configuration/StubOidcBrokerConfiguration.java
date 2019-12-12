package uk.gov.ida.stuboidcbroker.configuration;

import io.dropwizard.Configuration;

public class StubOidcBrokerConfiguration extends Configuration {

    private String stubBrokerURI;
    private String redisURI;
    private boolean local;
    private String softwareID;
    private String stubTrustframeworkRP;
    private String directoryURI;
    private String middlewareURI;
    private String verifiableCredentialURI;
    private String scheme;
    private String redisDatabase;

    public String getStubBrokerURI() {
        return stubBrokerURI;
    }

    public String getRedisURI() {
        return redisURI;
    }

    public boolean isLocal() {
        return local;
    }

    public String getSoftwareID() {
        return softwareID;
    }

    public String getStubTrustframeworkRP() {
        return stubTrustframeworkRP;
    }

    public String getDirectoryURI() {
        return directoryURI;
    }

    public String getMiddlewareURI() {
        return middlewareURI;
    }

    public String getVerifiableCredentialURI() {
        return verifiableCredentialURI;
    }

    public String getScheme() {
        return scheme;
    }

    public String getRedisDatabase() {
        return redisDatabase;
    }
}
