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
    private String redirectURI;
    private String claims;
    private String error;
    private String errorDescription;

    public PickerView(List<Organisation> idps, List<Organisation> brokers,
                      String transactionID, String branding,
                      String scheme, String directoryUri,
                      String redirectURI, String claims) {
        super(branding + "-picker.mustache");
        this.idps = idps;
        this.brokers = brokers;
        this.transactionID = transactionID;
        this.index = 0;
        this.scheme = scheme;
        this.directoryUri = directoryUri;
        this.redirectURI = redirectURI;
        this.claims = claims;
    }

    public PickerView(List<Organisation> idps, List<Organisation> brokers,
                      String transactionID, String branding,
                      String scheme, String directoryUri,
                      String redirectURI, String claims, String error,
                      String errorDescription) {
        this(idps, brokers, transactionID, branding, scheme, directoryUri, redirectURI, claims);
        this.error = error;
        this.errorDescription = errorDescription;
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

    public String getError() {
        return error;
    }

    public String getErrorDescription() {
        return errorDescription;
    }

    public boolean errorExists() {
        return error != null;
    }

    public String getRedirectURI() {
        return redirectURI;
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

    public String getClaims() {
        return claims;
    }
}
