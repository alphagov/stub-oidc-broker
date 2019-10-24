package uk.gov.ida.stuboidcclient.views;

import io.dropwizard.views.View;

public class AuthenticationCallbackView extends View {

        public AuthenticationCallbackView() {
            super("authenticationCallbackPage.mustache");
        }
}
