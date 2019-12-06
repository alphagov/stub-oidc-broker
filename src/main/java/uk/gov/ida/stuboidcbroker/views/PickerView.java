package uk.gov.ida.stuboidcbroker.views;

import io.dropwizard.views.View;
import uk.gov.ida.stuboidcbroker.domain.Organisation;

import java.util.List;

public class PickerView extends View {
    private int index;
    private List<Organisation> idps;
    private List<Organisation> brokers;

    public PickerView(List<Organisation> idps, List<Organisation> brokers) {
        super("picker.mustache");
        this.idps = idps;
        this.brokers = brokers;
        this.index = 0;
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
