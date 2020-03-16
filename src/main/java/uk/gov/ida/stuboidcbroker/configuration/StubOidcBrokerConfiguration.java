package uk.gov.ida.stuboidcbroker.configuration;

import io.dropwizard.Configuration;

public class StubOidcBrokerConfiguration extends Configuration {

    private String stubBrokerURI;
    private String redisURI;
    private boolean local;
    private String softwareID;
    private String directoryURI;
    private String middlewareURI;
    private String idpURI;
    private String scheme;
    private String branding;
    private String orgID;
    private String atpURI;
    private String atp2URI;

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

    public String getDirectoryURI() {
        return directoryURI;
    }

    public String getMiddlewareURI() {
        return middlewareURI;
    }

    public String getIdpURI() {
        return idpURI;
    }

    public String getScheme() {
        return scheme;
    }

    public String getBranding() {
        return branding;
    }

    public String getOrgID() {
        return orgID;
    }

    public String getAtpURI() {
        return atpURI;
    }

    public String getAtp2URI() {
        return atp2URI;
    }
}
