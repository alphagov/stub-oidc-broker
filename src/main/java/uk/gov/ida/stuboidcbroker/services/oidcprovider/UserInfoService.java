package uk.gov.ida.stuboidcbroker.services.oidcprovider;

import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.claims.AggregatedClaims;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import net.minidev.json.JSONObject;
import uk.gov.ida.stuboidcbroker.configuration.StubOidcBrokerConfiguration;
import uk.gov.ida.stuboidcbroker.services.oidcclient.AuthnResponseValidationService;
import uk.gov.ida.stuboidcbroker.services.oidcclient.TokenRequestService;
import uk.gov.ida.stuboidcbroker.services.shared.RedisService;

import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class UserInfoService {

    private final StubOidcBrokerConfiguration configuration;
    private final TokenRequestService tokenRequestService;
    private final AuthnResponseValidationService authnResponseValidationService;
    private final RedisService redisService;

    public UserInfoService(StubOidcBrokerConfiguration configuration,
                           TokenRequestService tokenRequestService,
                           AuthnResponseValidationService authnResponseValidationService,
                           RedisService redisService) {
        this.configuration = configuration;
        this.tokenRequestService = tokenRequestService;
        this.authnResponseValidationService = authnResponseValidationService;
        this.redisService = redisService;
    }

    public UserInfo createAggregatedUserInfoUsingVerifiableCredential(SignedJWT verifiableCredentialJwt, Set<String> userInfoClaimNames) {
        JWTClaimsSet identityClaimsSet;
        try {
            identityClaimsSet = verifiableCredentialJwt.getJWTClaimsSet();
        } catch (java.text.ParseException e) {
            throw new RuntimeException(e);
        }
        String sub  = identityClaimsSet.getSubject();
        Set<String> identityClaimName = new HashSet<>();
        identityClaimName.add("verified_claims");

        UserInfo aggregatingUserInfo = new UserInfo(new Subject(sub));
        aggregatingUserInfo.setIssuer(new Issuer(configuration.getOrgID()));
        AggregatedClaims identityClaims = new AggregatedClaims(identityClaimName, verifiableCredentialJwt);
        aggregatingUserInfo.addAggregatedClaims(identityClaims);

        //Check if we have the required attributes to call the API-based ATP and if it was requested from the RP
        if (ableToRetrieveAttributesFromATPApi(identityClaimsSet, userInfoClaimNames)) {
            SignedJWT atpJWT = retrieveAttributesFromATPApi(identityClaimsSet);
            Set<String> attributeClaimName = new HashSet<>();
            attributeClaimName.add("ho_positive_verification_notice");
            AggregatedClaims attributeClaims = new AggregatedClaims(attributeClaimName, atpJWT);
            aggregatingUserInfo.addAggregatedClaims(attributeClaims);
        }

        //Check if we should call the OIDC-based ATP (user-info)
        if (userInfoClaimNames.contains("bank_account_number")) {
            SignedJWT atpJWT = retrieveAttributesFromATPOIDC();
            Set<String> attributeClaimName = new HashSet<>();
            attributeClaimName.add("bank_account_number");
            AggregatedClaims attributeClaims = new AggregatedClaims(attributeClaimName, atpJWT);
            aggregatingUserInfo.addAggregatedClaims(attributeClaims);
        }

        return aggregatingUserInfo;
    }

    public UserInfo createAggregatedUserInfo(SignedJWT idpJWT, Set<String> userInfoClaimNames) {
        JWTClaimsSet identityClaimsSet;
        try {
            identityClaimsSet = idpJWT.getJWTClaimsSet();
        } catch (java.text.ParseException e) {
            throw new RuntimeException(e);
        }
        String sub  = identityClaimsSet.getSubject();
        Set<String> identityClaimName = new HashSet<>();
        for (Object claimName : identityClaimsSet.getClaims().keySet()) {
            if (userInfoClaimNames.contains(claimName)) {
                identityClaimName.add(claimName.toString());
            }
        }

        UserInfo aggregatingUserInfo = new UserInfo(new Subject(sub));
        aggregatingUserInfo.setIssuer(new Issuer(configuration.getOrgID()));
        AggregatedClaims identityClaims = new AggregatedClaims(identityClaimName, idpJWT);
        aggregatingUserInfo.addAggregatedClaims(identityClaims);

        //Check if we have the required attributes to call the API-based ATP and if it was requested from the RP
        if (ableToRetrieveAttributesFromATPApi(identityClaimsSet, userInfoClaimNames)) {
            SignedJWT atpJWT = retrieveAttributesFromATPApi(identityClaimsSet);
            Set<String> attributeClaimName = new HashSet<>();
            attributeClaimName.add("ho_positive_verification_notice");
            AggregatedClaims attributeClaims = new AggregatedClaims(attributeClaimName, atpJWT);
            aggregatingUserInfo.addAggregatedClaims(attributeClaims);
        }

        //Check if we should call the OIDC-based ATP (user-info)
        if (userInfoClaimNames.contains("bank_account_number")) {
            SignedJWT atpJWT = retrieveAttributesFromATPOIDC();
            Set<String> attributeClaimName = new HashSet<>();
            attributeClaimName.add("bank_account_number");
            AggregatedClaims attributeClaims = new AggregatedClaims(attributeClaimName, atpJWT);
            aggregatingUserInfo.addAggregatedClaims(attributeClaims);
        }

        return aggregatingUserInfo;
    }

    public String getUserInfoForRPResponse(String transactionID, Map<String, String> authenticationParams) {
        String brokerName = getBrokerName(transactionID);
        String brokerDomain = getBrokerDomain(transactionID);
        AuthorizationCode authorizationCode = authnResponseValidationService.handleAuthenticationResponse(authenticationParams, getClientID(brokerName));
        String userInfoInJson = retrieveTokenAndUserInfo(authorizationCode, brokerName, brokerDomain);

        return userInfoInJson;
    }

    public String retrieveTokenAndUserInfo(AuthorizationCode authCode, String brokerName, String brokerDomain) {

        OIDCTokens tokens = tokenRequestService.getTokens(authCode, getClientID(brokerName), brokerDomain);
//      UserInfo userInfo = tokenService.getUserInfo(tokens.getBearerAccessToken());
//      String userInfoToJson = userInfo.toJSONObject().toJSONString();

        return tokenRequestService.getVerifiableCredentialFromIDP(tokens.getBearerAccessToken(), brokerDomain);
    }

    private boolean ableToRetrieveAttributesFromATPApi(JWTClaimsSet identityClaimsSet, Set<String> userInfoClaimNames) {
        Map<String, Object> idpClaims = identityClaimsSet.getClaims();

        if (idpClaims.containsKey("given_name")
                && idpClaims.containsKey("family_name")
                && idpClaims.containsKey("birthdate")
                && userInfoClaimNames.contains("ho_positive_verification_notice")) {
            return true;
        }
        return false;
    }

    private SignedJWT retrieveAttributesFromATPApi(JWTClaimsSet identityClaimsSet) {
            Map<String, Object> idpClaims = identityClaimsSet.getClaims();
            String firstName = idpClaims.get("given_name").toString();
            String familyName = idpClaims.get("family_name").toString();
            String dateOfBirth = idpClaims.get("birthdate").toString();
            BearerAccessToken accessTokenFromATP = tokenRequestService.getAccessTokenFromATP();
            SignedJWT atpJWT = sentAttributeRequestToATPApi(firstName, familyName, dateOfBirth, accessTokenFromATP);

            return atpJWT;
    }

    private SignedJWT retrieveAttributesFromATPOIDC() {

        //BearerAccessToken accessTokenFromATP = tokenRequestService.getAccessTokenFromATP();
        SignedJWT atpJWT = sentAttributeRequestToATPOIDC();

        return atpJWT;
    }

    private SignedJWT sentAttributeRequestToATPApi(String firstName, String familyName, String dateOfBirth, BearerAccessToken accessToken) {
        URI atpURI = UriBuilder.fromUri(configuration.getAtpURI()).path("atp/ho/positive-verification-notice").build();
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("first_name", firstName);
        jsonObject.put("family_name", familyName);
        jsonObject.put("date_of_birth", dateOfBirth);

        HttpRequest request = HttpRequest.newBuilder()
                .POST(HttpRequest.BodyPublishers.ofString(jsonObject.toJSONString()))
                .header("Content-Type", "application/json")
                .headers("Authorization", accessToken.getValue())
                .uri(atpURI)
                .build();

        HttpResponse<String> responseBody;

        try {
            responseBody = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }
        return convertResponseBodyToJWT(responseBody.body());
    }

    private SignedJWT sentAttributeRequestToATPOIDC() {
        URI atpURI = UriBuilder.fromUri(configuration.getAtp2URI()).path("user_info").build();

        HttpRequest request = HttpRequest.newBuilder()
                .GET()
                .header("Content-Type", "application/json")
                //.headers("Authorization", accessToken.getValue())
                .uri(atpURI)
                .build();

        HttpResponse<String> responseBody;

        try {
            responseBody = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }
        return convertResponseBodyToJWT(responseBody.body());
    }

    private SignedJWT convertResponseBodyToJWT(String responseBody) {
        try {
            JSONObject responseFromATP = JSONObjectUtils.parse(responseBody);
            return SignedJWT.parse(responseFromATP.get("JWT").toString());
        } catch (java.text.ParseException e) {
            throw new RuntimeException(e);
        }
    }

    private String getBrokerName(String transactionID) {
        return redisService.get(transactionID + "-brokername");
    }

    private String getBrokerDomain(String transactionID) {
        return redisService.get(transactionID + "-brokerdomain");
    }

    private ClientID getClientID(String brokerName) {
        String client_id = redisService.get(brokerName);
        if (client_id != null) {
            return new ClientID(client_id);
        }
        return new ClientID();
    }
}
