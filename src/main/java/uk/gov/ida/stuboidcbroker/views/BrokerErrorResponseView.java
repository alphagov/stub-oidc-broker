package uk.gov.ida.stuboidcbroker.views;

import com.nimbusds.oauth2.sdk.id.State;
import io.dropwizard.views.View;

import java.net.URI;

public class BrokerErrorResponseView extends View {

    private final String error;
    private final String errorDescription;
    private final int httpStatusCode;
    private final State state;
    private final URI redirectURI;
    private final String transactionID;

    public BrokerErrorResponseView(String error, String errorDescription, int httpStatusCode, State state, URI redirectURI, String transactionID) {
        super("broker-error-response.mustache");

        this.error = error;
        this.errorDescription = errorDescription;
        this.httpStatusCode = httpStatusCode;
        this.state = state;
        this.redirectURI = redirectURI;
        this.transactionID = transactionID;
    }

    public String getError() {
        return error;
    }

    public String getErrorDescription() {
        return errorDescription;
    }

    public String getState() {
        if (state != null) {
            return state.getValue();
        }
        return null;
    }

    public String getRedirectURI() {
        return redirectURI.toString();
    }

    public String getHttpStatusCode() {
        return Integer.toString(httpStatusCode);
    }

    public String getTransactionID() {
        return transactionID;
    }
}
