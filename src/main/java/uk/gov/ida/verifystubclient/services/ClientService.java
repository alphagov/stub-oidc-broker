package uk.gov.ida.verifystubclient.services;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import uk.gov.ida.verifystubclient.configuration.VerifyStubClientConfiguration;

import java.io.IOException;
import java.net.URI;

public class ClientService {

    private static final ClientID CLIENT_ID = new ClientID("stub-client");
    private VerifyStubClientConfiguration configuration;

    public ClientService(VerifyStubClientConfiguration configuration) {
        this.configuration = configuration;
    }

    public AuthenticationRequest generateAuthenticationRequest(
            String requestUri,
            ClientID clientID,
            String redirectUri) {
        Scope scope = new Scope("openid");

        AuthenticationRequest authenticationRequest = new AuthenticationRequest(
                URI.create(requestUri),
                new ResponseType(ResponseType.Value.CODE, OIDCResponseTypeValue.ID_TOKEN),
                scope, clientID, URI.create(redirectUri), new State(), new Nonce());

        return authenticationRequest;
    }

    public OIDCTokens getTokens(AuthorizationCode authorizationCode) {
        ClientSecretBasic clientSecretBasic = new ClientSecretBasic(CLIENT_ID, new Secret());

        TokenRequest tokenRequest = new TokenRequest(
                URI.create(configuration.getProviderTokenURI()),
                clientSecretBasic,
                new AuthorizationCodeGrant(authorizationCode, URI.create(configuration.getRedirectURI())));

        HTTPResponse httpResponse = sendHTTPRequest(tokenRequest.toHTTPRequest());

        try {
            TokenResponse tokenResponse = OIDCTokenResponseParser.parse(httpResponse);

            if (!tokenResponse.indicatesSuccess()) {
                ErrorObject errorObject = tokenResponse.toErrorResponse().getErrorObject();
                throw new RuntimeException(
                        " ;ErrorCode:" + errorObject.getCode() +
                                " ;Error description:" + errorObject.getDescription() +
                                " ;HTTP Status Code:" + errorObject.getHTTPStatusCode());
            }
            return tokenResponse.toSuccessResponse().getTokens().toOIDCTokens();
        } catch (ParseException e) {
            throw new RuntimeException("Unable to parse HTTP Response to Token Response", e);
        }
    }

    public UserInfo getUserInfo(BearerAccessToken bearerAccessToken) {
        UserInfoRequest userInfoRequest = new UserInfoRequest(
                URI.create(configuration.getProviderUserInfoURI()),
                bearerAccessToken);

        HTTPResponse httpResonse = sendHTTPRequest(userInfoRequest.toHTTPRequest());

        try {
            UserInfoResponse userInfoResponse = UserInfoResponse.parse(httpResonse);
            return userInfoResponse.toSuccessResponse().getUserInfo();
        } catch (ParseException e) {
            throw new RuntimeException("Unable to parse HTTP Response to UserInfoResponse", e);
        }
    }

    private HTTPResponse sendHTTPRequest(HTTPRequest request) {

        try {
            HTTPResponse httpResponse = request.send();
            return httpResponse;
        } catch (IOException e) {
            throw new RuntimeException("Unable to send HTTP Request", e);
        }
    }
}
