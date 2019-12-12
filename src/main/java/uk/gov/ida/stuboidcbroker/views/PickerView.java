package uk.gov.ida.stuboidcbroker.views;

import io.dropwizard.views.View;
import uk.gov.ida.stuboidcbroker.domain.Organisation;

import java.util.List;

public class PickerView extends View {
    private int index;
    private List<Organisation> idps;
    private List<Organisation> brokers;
    private String transactionID;

    public PickerView(List<Organisation> idps, List<Organisation> brokers, String transactionID) {
        super("picker.mustache");
        this.idps = idps;
        this.brokers = brokers;
        this.transactionID = transactionID;
        this.index = 0;
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
        this.index = ++index;
        return index;
    }
}
