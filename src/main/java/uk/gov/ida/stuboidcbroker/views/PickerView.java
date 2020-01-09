package uk.gov.ida.stuboidcbroker.views;

import io.dropwizard.views.View;
import uk.gov.ida.stuboidcbroker.domain.Organisation;

import java.util.ArrayList;
import java.util.List;

import static java.lang.String.valueOf;

public class PickerView extends View {
    private int index;
    private List<Organisation> idps;
    private List<Organisation> brokers;
    private String transactionID;
    private String scheme;
    private String directoryUri;

    public PickerView(List<Organisation> idps, List<Organisation> brokers,
                      String transactionID, String branding,
                      String scheme, String directoryUri) {
        super(branding + "-picker.mustache");
        this.idps = idps;
        this.brokers = brokers;
        this.transactionID = transactionID;
        this.index = 0;
        this.scheme = scheme;
        this.directoryUri = directoryUri;
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

    public String getDirectoryUri() {
        return directoryUri;
    }

    public boolean isSchemeOne() {
        return scheme.equals("1");
    }

    public String getSchemeLogoClassName() {
        return scheme.equals("1") ? "scheme-2" : "scheme-1";
    }

    public List<String> getDummyBrokers() {
        int listSize = 8 - brokers.size();
        List<String> dummyList = new ArrayList<>();
        for (int j = 0; j < listSize; j++) {
            dummyList.add(valueOf(j));
        }
        return dummyList;
    }

    public boolean startNewRow() {
        return index % 2 == 0;
    }
}
