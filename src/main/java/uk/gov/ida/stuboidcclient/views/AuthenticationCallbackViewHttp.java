package uk.gov.ida.stuboidcclient.views;

import io.dropwizard.views.View;

public class AuthenticationCallbackViewHttp extends View {

    public AuthenticationCallbackViewHttp() {
        super("authenticationCallbackHttp.mustache");

    }
}
