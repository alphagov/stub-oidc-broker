package uk.gov.ida.verifystubclient.views;

import io.dropwizard.views.View;

import javax.ws.rs.core.Response;

public class AuthenticationCallbackView extends View {

        public AuthenticationCallbackView() {
            super("authenticationCallbackPage.mustache");
        }
}
