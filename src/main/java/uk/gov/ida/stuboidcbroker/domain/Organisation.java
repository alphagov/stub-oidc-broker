package uk.gov.ida.stuboidcbroker.domain;

import javax.annotation.Nullable;

public class Organisation {

    private String name;

    private String type;

    private String domain;

    @Nullable
    private String loa;

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

    @Override
    public String toString() {
        return "Organisation{" +
                "name='" + name + '\'' +
                ", type='" + type + '\'' +
                ", domain='" + domain + '\'' +
                ", loa='" + loa + '\'' +
                '}';
    }
}
