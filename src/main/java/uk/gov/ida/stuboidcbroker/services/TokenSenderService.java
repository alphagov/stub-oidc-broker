package uk.gov.ida.stuboidcbroker.services;

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
import uk.gov.ida.stuboidcbroker.configuration.StubOidcBrokerConfiguration;
import uk.gov.ida.stuboidcbroker.rest.Urls;

import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class TokenSenderService {

    private final RedisService redisService;
    private final StubOidcBrokerConfiguration configuration;

    public TokenSenderService(StubOidcBrokerConfiguration configuration, RedisService redisService) {
        this.configuration = configuration;
        this.redisService = redisService;
    }

    public OIDCTokens getTokens(AuthorizationCode authorizationCode, ClientID clientID, String idpDomain) {
        ClientSecretBasic clientSecretBasic = new ClientSecretBasic(clientID, new Secret());
        URI redirectURI = UriBuilder.fromUri(configuration.getStubBrokerURI()).path(Urls.StubBroker.REDIRECT_URI).build();
        URI tokenURI = UriBuilder.fromUri(configuration.getMiddlewareURI()).path(Urls.Middleware.TOKEN_URI).build();
        Map<String, List<String>> customParams = new HashMap<>();
        customParams.put("destination-url", Collections.singletonList(idpDomain));

        TokenRequest tokenRequest = new TokenRequest(
                tokenURI,
                clientSecretBasic,
                new AuthorizationCodeGrant(authorizationCode, redirectURI),
                null,
                null,
                customParams
        );

        HTTPRequest httpRequest = tokenRequest.toHTTPRequest();
        HTTPResponse httpResponse = sendHTTPRequest(httpRequest);

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

    public UserInfo getUserInfo(BearerAccessToken bearerAccessToken, String idpDomain) {
        URI userInfoURI = UriBuilder.fromUri(idpDomain).path(Urls.StubOp.USERINFO_URI).build();
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

    public String getVerifiableCredential(BearerAccessToken bearerAccessToken, String brokerDomain) {
        URI userInfoURI = UriBuilder.fromUri(brokerDomain)
                .path(Urls.StubBroker.USER_INFO).build();

        HttpRequest request = HttpRequest.newBuilder()
                .GET()
                .header("Authorization", bearerAccessToken.toAuthorizationHeader())
                .uri(userInfoURI)
                .build();

        HttpResponse<String> responseBody;
        try {
            responseBody = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }
        return responseBody.body();
    }
}
