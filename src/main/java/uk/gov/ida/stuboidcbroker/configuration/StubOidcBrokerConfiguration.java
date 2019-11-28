package uk.gov.ida.stuboidcbroker.configuration;

import io.dropwizard.Configuration;

public class StubOidcBrokerConfiguration extends Configuration {

    private String stubOpURI;
    private String stubBrokerURI;
    private String redisURI;
    private boolean local;
    private String softwareID;
    private String stubTrustframeworkRP;
    private String tokenURI;
    private String directoryURI;
    private String registrationURI;

    public String getStubOpURI() {
        return stubOpURI;
    }

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

    public String getTokenURI() {
        return tokenURI;
    }

    public String getDirectoryURI() {
        return directoryURI;
    }

    public String getRegistrationURI() {
        return registrationURI;
    }
}
