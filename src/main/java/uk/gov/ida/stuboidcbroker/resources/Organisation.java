package uk.gov.ida.stuboidcbroker.resources;


public class Organisation {
    private String name;

    private String type;

    private String domain;

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

    public void setName(String name) {
        this.name = name;
    }

    public void setType(String type) {
        this.type = type;
    }

    public void setDomain(String domain) {
        this.domain = domain;
    }

    public void setLoa(String loa) {
        this.loa = loa;
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