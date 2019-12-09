package uk.gov.ida.stuboidcbroker.domain;

import javax.annotation.Nullable;

public class Organisation {

    private String name;

    private String type;

    private String domain;

    @Nullable
    private String loa;

    private String scheme;

    public String getName() {
        return name;
    }

    public String getType() {
        return type;
    }

    public String getDomain() {
        return domain;
    }

    public String getLoa() {
        return loa;
    }

    public String getScheme() {
        return scheme;
    }

    @Override
    public String toString() {
        return "Organisation{" +
                "name='" + name + '\'' +
                ", type='" + type + '\'' +
                ", domain='" + domain + '\'' +
                ", loa='" + loa + '\'' +
                ", scheme='" + scheme + '\'' +
                '}';
    }
}
