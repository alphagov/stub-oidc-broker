package uk.gov.ida.stuboidcclient.services;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import uk.gov.ida.stuboidcclient.configuration.StubOidcClientConfiguration;
import uk.gov.ida.stuboidcclient.rest.Urls;

import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.net.URI;

public class TokenService {

    private final RedisService redisService;
    private final StubOidcClientConfiguration configuration;

    public TokenService(StubOidcClientConfiguration configuration, RedisService redisService) {
        this.configuration = configuration;
        this.redisService = redisService;
    }

    public OIDCTokens getTokens(AuthorizationCode authorizationCode, ClientID clientID) {
        ClientSecretBasic clientSecretBasic = new ClientSecretBasic(clientID, new Secret());
        URI redirectURI = UriBuilder.fromUri(configuration.getStubClientURI()).path(Urls.StubClient.REDIRECT_URI).build();
        URI tokenURI = UriBuilder.fromUri(configuration.getStubOpURI()).path(Urls.StubOp.TOKEN_URI).build();

        TokenRequest tokenRequest = new TokenRequest(
                tokenURI,
                clientSecretBasic,
                new AuthorizationCodeGrant(authorizationCode, redirectURI));

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
        URI userInfoURI = UriBuilder.fromUri(configuration.getStubOpURI()).path(Urls.StubOp.USERINFO_URI).build();
        UserInfoRequest userInfoRequest = new UserInfoRequest(
                userInfoURI,
                bearerAccessToken);

        HTTPResponse httpResonse = sendHTTPRequest(userInfoRequest.toHTTPRequest());

        try {
            UserInfoResponse userInfoResponse = UserInfoResponse.parse(httpResonse);
            return userInfoResponse.toSuccessResponse().getUserInfo();
        } catch (ParseException e) {
            throw new RuntimeException("Unable to parse HTTP Response to UserInfoResponse", e);
        }
    }

    public String getNonce(String state) {
        String nonce = redisService.get("state::" + state);
        if (nonce == null || nonce.length() < 1) {
            throw new RuntimeException("Nonce not found in data store");
        }
        return nonce;
    }

    public Long getNonceUsageCount(String nonce) {
        return redisService.incr("nonce::" + nonce);
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
