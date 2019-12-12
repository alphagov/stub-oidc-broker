package uk.gov.ida.stuboidcbroker.views;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import io.dropwizard.views.View;

import java.net.URI;

public class BrokerResponseView extends View {

    private final State state;
    private final AuthorizationCode authCode;
    private final JWT idToken;
    private final URI redirectURI;
    private AccessToken accessToken;
    private String transactionID;

    public BrokerResponseView(State state, AuthorizationCode authCode, JWT idToken, URI redirectURI, String transactionID) {
        super("broker-response.mustache");

        this.state = state;
        this.authCode = authCode;
        this.idToken = idToken;
        this.redirectURI = redirectURI;
        this.transactionID = transactionID;
    }

    public BrokerResponseView(State state, AuthorizationCode authCode, JWT idToken, URI redirectURI, AccessToken accessToken, String transactionID) {

        this(state, authCode, idToken, redirectURI, transactionID);

        this.accessToken = accessToken;
    }

    public String getState() {
        return state.getValue();
    }

    public String getAuthCode() {
        return authCode.getValue();
    }

    public String getIdToken() {
        return idToken.serialize();
    }

    public String getRedirectURI() {
        return redirectURI.toString();
    }

    public String getAccessToken() {
        if (accessToken == null) {
            return null;
        }
        return accessToken.toString();
    }

    public String getTransactionID() {
        return transactionID;
    }
}
