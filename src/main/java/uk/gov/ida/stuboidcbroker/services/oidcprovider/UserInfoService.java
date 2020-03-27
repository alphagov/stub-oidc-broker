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
import org.apache.commons.lang3.time.DateUtils;
import uk.gov.ida.stuboidcbroker.configuration.StubOidcBrokerConfiguration;
import uk.gov.ida.stuboidcbroker.rest.Urls;
import uk.gov.ida.stuboidcbroker.services.oidcclient.AuthnResponseValidationService;
import uk.gov.ida.stuboidcbroker.services.oidcclient.TokenRequestService;
import uk.gov.ida.stuboidcbroker.services.shared.RedisService;

import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

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


    public JWTClaimsSet generateVerifiablePresentation(SignedJWT idpVerifiableCredentialJwt, Set<String> userInfoClaimsNames, String clientID) {
        //Check if we should call the OIDC-based ATP (user-info)
        List<String> serializedVCs = new ArrayList<>();
        serializedVCs.add(idpVerifiableCredentialJwt.serialize());
        if (userInfoClaimsNames.contains("bank_account_number")) {
            SignedJWT atpJWT = sentBankAccountNoRequestToATP(true);
            serializedVCs.add(atpJWT.serialize());
        }
        JSONObject idpClaimSet;
        try {
            idpClaimSet = (JSONObject) idpVerifiableCredentialJwt.getJWTClaimsSet().getClaims().get("vc");
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }

        if (ableToRetrieveAddressHistoryAttribute(idpClaimSet, userInfoClaimsNames)) {
            JSONObject credentialSubject = (JSONObject) idpClaimSet.get("credentialSubject");
            JSONObject address = (JSONObject) credentialSubject.get("address");
            SignedJWT addressHistoryJWT = retrieveAttributesFromAddressHistoryATP(address);
            serializedVCs.add(addressHistoryJWT.serialize());
        }

        JWTClaimsSet verifiablePresentationClaimSet = new JWTClaimsSet.Builder()
                .claim("@context", Collections.singletonList("https://www.w3.org/2018/credentials/v1"))
                .claim("type", "VerifiablePresentation")
                .claim("verifiableCredential", serializedVCs)
                .build();

        Date exp = new Date();
        DateUtils.addMinutes(exp, 30);

        return new JWTClaimsSet.Builder()
                .issuer(configuration.getOrgID())
                .jwtID(UUID.randomUUID().toString())
                .audience(clientID)
                .notBeforeTime(new Date())
                .issueTime(new Date())
                .expirationTime(exp)
                .claim("nonce", "fsgfdgfdgfd")
                .claim("vp", verifiablePresentationClaimSet.toJSONObject()).build();
    }

    public UserInfo createAggregatedUserInfoUsingVerifiableCredential(SignedJWT verifiableCredentialJwt, Set<String> userInfoClaimNames, String clientID) {
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
        Date exp = new Date();
        DateUtils.addMinutes(exp, 30);
        aggregatingUserInfo.setClaim("aud", clientID);
        aggregatingUserInfo.setClaim("iat", new Date().getTime()); //Because the OIDC lib is :S
        aggregatingUserInfo.setClaim("nbf", new Date().getTime());
        aggregatingUserInfo.setClaim("exp", exp.getTime());
        aggregatingUserInfo.setClaim("jti", UUID.randomUUID().toString());
        AggregatedClaims identityClaims = new AggregatedClaims(identityClaimName, verifiableCredentialJwt);
        aggregatingUserInfo.addAggregatedClaims(identityClaims);

        //Check if we have the required attributes to call the API-based ATP and if it was requested from the RP
        if (ableToRetrieveAttributesFromATPApi(identityClaimsSet, userInfoClaimNames)) {
            SignedJWT atpJWT = retrieveAttributesFromHoPositiveVerificationATP(identityClaimsSet);
            Set<String> attributeClaimName = new HashSet<>();
            attributeClaimName.add("ho_positive_verification_notice");
            AggregatedClaims attributeClaims = new AggregatedClaims(attributeClaimName, atpJWT);
            aggregatingUserInfo.addAggregatedClaims(attributeClaims);
        }

        //Check if we should call the OIDC-based ATP (user-info)
        if (userInfoClaimNames.contains("bank_account_number")) {
            SignedJWT atpJWT = sentBankAccountNoRequestToATP(false);
            Set<String> attributeClaimName = new HashSet<>();
            attributeClaimName.add("bank_account_number");
            AggregatedClaims attributeClaims = new AggregatedClaims(attributeClaimName, atpJWT);
            aggregatingUserInfo.addAggregatedClaims(attributeClaims);
        }

        return aggregatingUserInfo;
    }

    public UserInfo createAggregatedUserInfo(SignedJWT idpJWT, Set<String> userInfoClaimNames, String clientID) {
        JWTClaimsSet identityClaimsSet;
        try {
            identityClaimsSet = idpJWT.getJWTClaimsSet();
        } catch (java.text.ParseException e) {
            throw new RuntimeException(e);
        }
        String sub  = identityClaimsSet.getSubject();
        Set<String> identityClaimName = new HashSet<>();
        for (String claimName : identityClaimsSet.getClaims().keySet()) {
            if (userInfoClaimNames.contains(claimName)) {
                identityClaimName.add(claimName);
            }
        }

        UserInfo aggregatingUserInfo = new UserInfo(new Subject(sub));
        aggregatingUserInfo.setIssuer(new Issuer(configuration.getOrgID()));
        Date exp = new Date();
        DateUtils.addMinutes(exp, 30);
        aggregatingUserInfo.setClaim("aud", clientID);
        aggregatingUserInfo.setClaim("iat", new Date().getTime()); //Because the OIDC lib is :S
        aggregatingUserInfo.setClaim("nbf", new Date().getTime());
        aggregatingUserInfo.setClaim("exp", exp.getTime());
        aggregatingUserInfo.setClaim("jti", UUID.randomUUID().toString());
        AggregatedClaims identityClaims = new AggregatedClaims(identityClaimName, idpJWT);
        aggregatingUserInfo.addAggregatedClaims(identityClaims);

        //Check if we have the required attributes to call the API-based ATP and if it was requested from the RP
        if (ableToRetrieveAttributesFromATPApi(identityClaimsSet, userInfoClaimNames)) {
            SignedJWT atpJWT = retrieveAttributesFromHoPositiveVerificationATP(identityClaimsSet);
            Set<String> attributeClaimName = new HashSet<>();
            attributeClaimName.add("ho_positive_verification_notice");
            AggregatedClaims attributeClaims = new AggregatedClaims(attributeClaimName, atpJWT);
            aggregatingUserInfo.addAggregatedClaims(attributeClaims);
        }

        //Check if we should call the OIDC-based ATP (user-info)
        if (userInfoClaimNames.contains("bank_account_number")) {
            SignedJWT atpJWT = sentBankAccountNoRequestToATP(false);
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

        return retrieveTokenAndUserInfo(authorizationCode, brokerName, brokerDomain);
    }

    public String retrieveTokenAndUserInfo(AuthorizationCode authCode, String brokerName, String brokerDomain) {

        OIDCTokens tokens = tokenRequestService.getTokens(authCode, getClientID(brokerName), brokerDomain);
//      UserInfo userInfo = tokenService.getUserInfo(tokens.getBearerAccessToken());
//      String userInfoToJson = userInfo.toJSONObject().toJSONString();

        return tokenRequestService.getVerifiableCredentialFromIDP(tokens.getBearerAccessToken(), brokerDomain);
    }

    private boolean ableToRetrieveAttributesFromATPApi(JWTClaimsSet identityClaimsSet, Set<String> userInfoClaimNames) {
        Map<String, Object> idpClaims = identityClaimsSet.getClaims();

        return idpClaims.containsKey("given_name")
                && idpClaims.containsKey("family_name")
                && idpClaims.containsKey("birthdate")
                && userInfoClaimNames.contains("ho_positive_verification_notice");
    }

    private boolean ableToRetrieveAddressHistoryAttribute(JSONObject idpClaimSet, Set<String> userInfoClaimsNames) {
        JSONObject credentialSubject = (JSONObject) idpClaimSet.get("credentialSubject");
        JSONObject address = (JSONObject) credentialSubject.get("address");

        return address.containsKey("street")
                && address.containsKey("town")
                && address.containsKey("county")
                && address.containsKey("country")
                && address.containsKey("postCode")
                && userInfoClaimsNames.contains("5_year_address_history");
    }

    private SignedJWT retrieveAttributesFromHoPositiveVerificationATP(JWTClaimsSet identityClaimsSet) {
            JSONObject jsonObject = new JSONObject();

            jsonObject.put("first_name",identityClaimsSet.getClaims().get("given_name").toString());
            jsonObject.put("family_name",identityClaimsSet.getClaims().get("family_name").toString());
            jsonObject.put("date_of_birth", identityClaimsSet.getClaims().get("birthdate").toString());
            BearerAccessToken accessTokenFromATP = tokenRequestService.getAccessTokenFromATP();
            URI atpURI = UriBuilder.fromUri(configuration.getAtpURI()).path(Urls.ATP.DIRECT_ACCESS_HO_POSITIVE_VERIFICATION_NOTICE).build();

            return sendAttributeRequestToDirectAccessATP(jsonObject, atpURI, accessTokenFromATP);
    }

    private SignedJWT retrieveAttributesFromAddressHistoryATP(JSONObject claimSet) {
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("street", claimSet.get("street").toString());
        jsonObject.put("town", claimSet.get("town").toString());
        jsonObject.put("county", claimSet.get("county").toString());
        jsonObject.put("country", claimSet.get("country").toString());
        jsonObject.put("postCode", claimSet.get("postCode").toString());
        BearerAccessToken accessTokenFromATP = tokenRequestService.getAccessTokenFromATP();
        URI atpURI = UriBuilder.fromUri(configuration.getAtpURI()).path(Urls.ATP.DIRECT_ACCESS_ADDRESS_HISTORY).build();

        return sendAttributeRequestToDirectAccessATP(jsonObject, atpURI, accessTokenFromATP);
    }

    private SignedJWT sendAttributeRequestToDirectAccessATP(JSONObject jsonObject, URI atpURI, BearerAccessToken accessToken) {
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

    private SignedJWT sentBankAccountNoRequestToATP(boolean askedForVerifiableCredential) {
        URI atpURI;
        if (askedForVerifiableCredential) {
            atpURI = UriBuilder.fromUri(configuration.getAtp2URI()).path(Urls.ATP.BANK_ACCOUNT_ATTRIBUTE_VC).build();
        } else {
            atpURI = UriBuilder.fromUri(configuration.getAtp2URI()).path(Urls.ATP.BANK_ACCOUNT_ATTRIBUTE_STANDARD).build();
        }

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
