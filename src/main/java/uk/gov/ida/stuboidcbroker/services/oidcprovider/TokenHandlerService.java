package uk.gov.ida.stuboidcbroker.services.oidcprovider;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.claims.AccessTokenHash;
import com.nimbusds.openid.connect.sdk.claims.CodeHash;
import com.nimbusds.openid.connect.sdk.claims.Gender;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import net.minidev.json.JSONObject;
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
import java.util.Collections;
import java.util.Date;
import java.util.Set;

public class TokenHandlerService {

    private static final String ISSUER = "stub-oidc-op";
    private RedisService redisService;
    private final StubOidcBrokerConfiguration configuration;
    private final PKIService pkiService;

    public TokenHandlerService(RedisService redisService, StubOidcBrokerConfiguration configuration, PKIService pkiService) {
        this.redisService = redisService;
        this.configuration = configuration;
        this.pkiService = pkiService;
    }

    public static final String SAMPLE_USER_SUBJECT_001 = "sample_user_id_001";

    public JWT generateAndGetIdToken(AuthorizationCode authCode, AuthenticationRequest authRequest, AccessToken accessToken) {
        CodeHash cHash = CodeHash.compute(authCode, JWSAlgorithm.RS256);
        AccessTokenHash aHash = AccessTokenHash.compute(accessToken, JWSAlgorithm.RS256);
        IDTokenClaimsSet idTokenClaimsSet = new IDTokenClaimsSet(
                new Issuer(ISSUER),
                new Subject(SAMPLE_USER_SUBJECT_001),
                Collections.singletonList(new Audience(authRequest.getClientID())),
                new Date(),
                new Date());
        idTokenClaimsSet.setCodeHash(cHash);
        idTokenClaimsSet.setNonce(authRequest.getNonce());
        idTokenClaimsSet.setAccessTokenHash(aHash);
        JWTClaimsSet jwtClaimsSet;
        try {
            jwtClaimsSet = idTokenClaimsSet.toJWTClaimsSet();
        } catch (ParseException e) {
            throw new RuntimeException("Unable to parse IDTokenClaimsSet to JWTClaimsSet", e);
        }

        JWSSigner signer = new RSASSASigner(pkiService.getOrganisationPrivateKey());
        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(configuration.getOrgID()).type(JOSEObjectType.JWT).build();
        SignedJWT idToken;

        try {
            idToken = new SignedJWT(jwsHeader, jwtClaimsSet);
            idToken.sign(signer);
        } catch (JOSEException e) {
            throw new RuntimeException();
        }

        storeTokens(idToken, accessToken, authCode);
        UserInfo info = generateUserInfo(authRequest);
        info.setIssuer(new Issuer(configuration.getOrgID()));
        try {
            JWTClaimsSet userInfoJWT = info.toJWTClaimsSet();
            SignedJWT userInfoSignedJWT = new SignedJWT(jwsHeader, userInfoJWT);
            userInfoSignedJWT.sign(signer);

            storeUserInfo(accessToken, userInfoSignedJWT);

        } catch (ParseException | JOSEException e) {
            throw new RuntimeException("Unable to generate userInfo JWT", e);
        }

        return idToken;
    }

    public UserInfo generateUserInfo(AuthenticationRequest request) {
        Set<String> claimNames = request.getClaims().getUserInfoClaimNames(false);
        Subject subject = new Subject(SAMPLE_USER_SUBJECT_001);
        UserInfo info = new UserInfo(subject);
        for (String claimName : claimNames) {
            switch (claimName) {
                case "name":
                    info.setName("Winnie the Pooh");
                    break;
                case "given_name":
                    info.setGivenName("Winnie");
                    break;
                case "middle_name":
                    info.setMiddleName("The");
                    break;
                case "family_name":
                    info.setFamilyName("Pooh");
                    break;
                case "birthdate":
                    info.setBirthdate("1926-01-01");
                    break;
                case "gender":
                    info.setGender(Gender.MALE);
                    break;
            }
        }
        return info;
    }

    public OIDCTokens getTokens(AuthorizationCode authCode) {

        String tokens = redisService.get(authCode.getValue());

        JSONObject jsonObject;
        try {
            jsonObject = new JSONObject(JSONObjectUtils.parse(tokens));
            return OIDCTokens.parse(jsonObject);
        } catch (java.text.ParseException | ParseException e) {
            throw new RuntimeException(e);
        }
    }

    public String getVerifiableCredential(AccessToken accessToken) {

        URI userInfoURI = UriBuilder.fromUri(configuration.getIdpURI())
                .path(Urls.IDP.CREDENTIAL_URI).build();

        HttpRequest request = HttpRequest.newBuilder()
                .GET()
                .header("Authorization", accessToken.toAuthorizationHeader())
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

    public String getUserInfoAsSignedJWT(AccessToken accessToken) {
        return redisService.get(accessToken.getValue());
    }

    private void storeTokens(JWT idToken, AccessToken accessToken, AuthorizationCode authCode) {

        OIDCTokens oidcTokens = new OIDCTokens(idToken, accessToken, null);

        redisService.set(authCode.getValue(), oidcTokens.toJSONObject().toJSONString());
    }

    public String getCertificateUrl(String clientID) {
        return redisService.get(clientID);
    }

    private void storeUserInfo(AccessToken accessToken, SignedJWT info) {
        redisService.set(accessToken.getValue(), info.serialize());
    }
}
