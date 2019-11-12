package uk.gov.ida.stuboidcbroker.views;

import io.dropwizard.views.View;

public class AuthenticationCallbackViewHttp extends View {

    public AuthenticationCallbackViewHttp() {
        super("authenticationCallbackHttp.mustache");

    }
}
