package uk.gov.ida.stuboidcbroker.views;

import io.dropwizard.views.View;
import uk.gov.ida.stuboidcbroker.domain.Organisation;

import java.util.List;

public class PickerView extends View {
    private List<Organisation> orgList;

    public PickerView(List<Organisation> orgList) {
        super("picker.mustache");
        this.orgList = orgList;
    }

    public List<Organisation> getOrgList() {
        return orgList;
    }
}
