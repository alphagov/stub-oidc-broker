package uk.gov.ida.stuboidcbroker.services.oidcclient;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponseParser;
import com.nimbusds.openid.connect.sdk.UserInfoRequest;
import com.nimbusds.openid.connect.sdk.UserInfoResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import net.minidev.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.ida.stuboidcbroker.configuration.StubOidcBrokerConfiguration;
import uk.gov.ida.stuboidcbroker.rest.Urls;
import uk.gov.ida.stuboidcbroker.services.shared.PKIService;
import uk.gov.ida.stuboidcbroker.services.shared.RedisService;

import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class TokenRequestService {

    private static final Logger LOG = LoggerFactory.getLogger(TokenRequestService.class);

    private final RedisService redisService;
    private final StubOidcBrokerConfiguration configuration;
    private final PKIService pkiService;

    public TokenRequestService(StubOidcBrokerConfiguration configuration, RedisService redisService, PKIService pkiService) {
        this.configuration = configuration;
        this.redisService = redisService;
        this.pkiService = pkiService;
    }

    public OIDCTokens getTokens(AuthorizationCode authorizationCode, ClientID clientID, String idpDomain) {
        URI redirectURI = UriBuilder.fromUri(configuration.getStubBrokerURI()).path(Urls.StubBrokerClient.REDIRECT_URI).build();
        URI tokenURI = UriBuilder.fromUri(idpDomain).path(Urls.StubBrokerOPProvider.TOKEN_URI).build();

        PrivateKeyJWT privateKeyJWT;
        try {
            PrivateKey privateKey = pkiService.getOrganisationPrivateKey();
            privateKeyJWT = new PrivateKeyJWT(clientID, tokenURI, JWSAlgorithm.RS256, (RSAPrivateKey) privateKey,null, null);
        } catch (JOSEException e) {
            throw new RuntimeException("Unable to create PrivateKeyJWT for TokenRequest", e);
        }
        Map<String, List<String>> customParams = new HashMap<>();
        customParams.put("destination-url", Collections.singletonList(idpDomain));

        TokenRequest tokenRequest = new TokenRequest(
                tokenURI,
                privateKeyJWT,
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

    public SignedJWT getUserInfoAsJWS(BearerAccessToken bearerAccessToken, String idpDomain) {
        URI userInfoURI = UriBuilder.fromUri(idpDomain).path(Urls.StubBrokerOPProvider.USERINFO_URI).build();
        UserInfoRequest userInfoRequest = new UserInfoRequest(
            userInfoURI,
            bearerAccessToken);

        HTTPResponse httpResponse = sendHTTPRequest(userInfoRequest.toHTTPRequest());

        try {
            JSONObject wrapped = httpResponse.getContentAsJSONObject();
            return SignedJWT.parse(wrapped.getAsString("jws"));
        } catch (Exception e) {
            LOG.error(e.getMessage());
            throw new RuntimeException("Unable to parse HTTP Response to UserInfoRequest", e);
        }
    }

    public UserInfo getUserInfo(BearerAccessToken bearerAccessToken, String idpDomain) {
        URI userInfoURI = UriBuilder.fromUri(idpDomain).path(Urls.StubBrokerOPProvider.USERINFO_URI).build();
        UserInfoRequest userInfoRequest = new UserInfoRequest(
                userInfoURI,
                bearerAccessToken);

        HTTPResponse httpResponse = sendHTTPRequest(userInfoRequest.toHTTPRequest());

        try {
            UserInfoResponse userInfoResponse = UserInfoResponse.parse(httpResponse);
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
            return request.send();
        } catch (IOException e) {
            throw new RuntimeException("Unable to send HTTP Request", e);
        }
    }

    public String getVerifiableCredentialFromIDP(BearerAccessToken bearerAccessToken, String brokerDomain) {
        URI userInfoURI = UriBuilder.fromUri(brokerDomain)
                .path(Urls.StubBrokerClient.USER_INFO).build();

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

    public BearerAccessToken getAccessTokenFromATP() {
        URI atpTokenURI = UriBuilder.fromUri(configuration.getAtpURI()).path("oauth2/token").build();
        PrivateKeyJWT privateKeyJWT;
        try {
            PrivateKey privateKey = pkiService.getOrganisationPrivateKey();
             privateKeyJWT = new PrivateKeyJWT(new ClientID(configuration.getOrgID()), atpTokenURI, JWSAlgorithm.RS256, (RSAPrivateKey) privateKey, null, null);
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }

        TokenRequest tokenRequest = new TokenRequest(
                atpTokenURI,
                privateKeyJWT,
                new AuthorizationCodeGrant(new AuthorizationCode("fssdxkjgd"), atpTokenURI),
                null);

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
            OIDCTokens oidcTokens = tokenResponse.toSuccessResponse().getTokens().toOIDCTokens();
            return oidcTokens.getBearerAccessToken();
        } catch (ParseException e) {
            throw new RuntimeException("Unable to parse HTTP Response to Token Response", e);
        }
    }
}
