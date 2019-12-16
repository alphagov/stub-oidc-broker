package uk.gov.ida.stuboidcbroker.views;

import io.dropwizard.views.View;
import uk.gov.ida.stuboidcbroker.domain.Organisation;

import java.util.List;

public class PickerView extends View {
    private int index;
    private List<Organisation> idps;
    private List<Organisation> brokers;
    private String transactionID;
    private String scheme;

    public PickerView(List<Organisation> idps, List<Organisation> brokers,
                      String transactionID, String branding,
                      String scheme) {
        super(branding + "-picker.mustache");
        this.idps = idps;
        this.brokers = brokers;
        this.transactionID = transactionID;
        this.index = 0;
        this.scheme = scheme;
    }

    public String getTransactionID() {
        return transactionID;
    }

    public List<Organisation> getIdps() {
        return idps;
    }

    public List<Organisation> getBrokers() {
        return brokers;
    }

    public int getIndex() {
        ++index;
        return index;
    }

    public String getScheme() {
        return scheme;
    }

    public boolean isSchemeOne() {
        return scheme.equals("1");
    }

    public String getSchemeLogoClassName() {
        return scheme.equals("1") ? "scheme-2" : "scheme-1";
    }
}
