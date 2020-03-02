package uk.gov.ida.stuboidcbroker.resources.oidcprovider;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;
import com.nimbusds.openid.connect.sdk.claims.AggregatedClaims;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import net.minidev.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.ida.stuboidcbroker.services.oidcclient.AuthnResponseValidationService;
import uk.gov.ida.stuboidcbroker.services.oidcclient.TokenRequestService;
import uk.gov.ida.stuboidcbroker.services.oidcprovider.TokenHandlerService;
import uk.gov.ida.stuboidcbroker.services.shared.RedisService;

import javax.validation.constraints.NotNull;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static uk.gov.ida.stuboidcbroker.services.shared.QueryParameterHelper.splitQuery;

@Path("/")
public class UserInfoResource {

    public enum ExperimentalResponseFormats { VerifiableCredential, RegularClaims, AggregatedClaims }

    private static final Logger LOG = LoggerFactory.getLogger(UserInfoResource.class);
    private final TokenHandlerService tokenHandlerService;
    private final RedisService redisService;
    private final AuthnResponseValidationService authnResponseValidationService;
    private final TokenRequestService tokenRequestService;

    public UserInfoResource(TokenHandlerService tokenHandlerService, RedisService redisService, AuthnResponseValidationService authnResponseValidationService, TokenRequestService tokenRequestService) {
        this.tokenHandlerService = tokenHandlerService;
        this.redisService = redisService;
        this.authnResponseValidationService = authnResponseValidationService;
        this.tokenRequestService = tokenRequestService;
    }

    public static final ExperimentalResponseFormats RESPONSE_FORMAT = ExperimentalResponseFormats.AggregatedClaims;

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/userinfo")
    public Response getUserInfo(
            @HeaderParam("Authorization") @NotNull String authorizationHeader,
            @HeaderParam("transactionID") String transactionID) {

        try {
            LOG.info("Received request to get User Info");
            //This will need to be used to get the user info but we're not using it for now
            AccessToken accessToken = AccessToken.parse(authorizationHeader);

            String responseBody = redisService.get(transactionID + "response-from-broker");

            boolean passThrough = responseBody != null;

            switch (RESPONSE_FORMAT) {
                case VerifiableCredential:
                    String verifiableCredential = getVerifiableCredentialFor(passThrough, responseBody, accessToken, transactionID);
                    return Response.ok(verifiableCredential).build();

                case RegularClaims:
                    String regularClaims = getRegularClaimsFor(passThrough, responseBody, accessToken, transactionID);
                    return Response.ok(regularClaims).build();

                case AggregatedClaims:
                    String aggregatedClaims = aggregateClaimsFor(passThrough, responseBody, accessToken, transactionID);
                    return Response.ok(aggregatedClaims).build();

                default:
                    throw new IllegalStateException("Unrecognised response format: " + RESPONSE_FORMAT.name());
            }

        } catch (ParseException e) {
            throw new RuntimeException("Unable to parse authorization header: " + authorizationHeader + " to access token", e);
        }
    }

    private String getRegularClaimsFor(boolean passThrough, String responseBody, AccessToken accessToken, String transactionID) {
        if (passThrough) {
            // pass through - we're a broker
            String brokerName = getBrokerName(transactionID);
            String brokerDomain = getBrokerDomain(transactionID);

            Map<String, String> authenticationParams = splitQuery(responseBody);
            AuthorizationCode authorizationCode = authnResponseValidationService.handleAuthenticationResponse(authenticationParams, getClientID(brokerName));
            return retrieveTokenAndUserInfoAsVerifiableCredential(authorizationCode, brokerName, brokerDomain);

        } else {
            // we are the IDP, respond with the claims -- in a JWT?
            return generateClaimsAsSignedJwt(accessToken);
        }
    }

    private String aggregateClaimsFor(boolean passThrough, String responseBody, AccessToken accessToken, String transactionID) {
        if (passThrough) {
            // we're a broker - we need to accept regular claims from the IDP and aggregate them
            String serialisedRequest = redisService.get(transactionID);

            AuthenticationRequest authenticationRequest;
            try {
                authenticationRequest = AuthenticationRequest.parse(serialisedRequest);
            } catch (ParseException e) {
                throw new RuntimeException("Unable to parse authentication request", e);
            }
            ClaimsRequest claimRequest = authenticationRequest.getClaims();
            Set<String> userInfoClaimNames = claimRequest.getUserInfoClaimNames(false);

            String brokerName = getBrokerName(transactionID);
            String brokerDomain = getBrokerDomain(transactionID);

            Map<String, String> authenticationParams = splitQuery(responseBody);
            AuthorizationCode authorizationCode = authnResponseValidationService.handleAuthenticationResponse(authenticationParams, getClientID(brokerName));

            // fetch the user info from the IDP as a JWT
            SignedJWT idpJWT = retrieveUserInfoFromIDP(authorizationCode, brokerName, brokerDomain);
            UserInfo aggregatedUserInfo = createAggregatedClaims(idpJWT, userInfoClaimNames);

            // sign the aggregated UserInfo
            SignedJWT aggregatedUserInfoSignedJWT;
            try {
                RSAKey signingKey = createSigningKey();
                JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(signingKey.getKeyID()).build();
                JWTClaimsSet aggregatedUserInfoJWT = aggregatedUserInfo.toJWTClaimsSet();
                JWSSigner signer = new RSASSASigner(signingKey);
                aggregatedUserInfoSignedJWT = new SignedJWT(jwsHeader, aggregatedUserInfoJWT);
                aggregatedUserInfoSignedJWT.sign(signer);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            // wrap the aggregated, signed, UserInfo in JSON
            JSONObject userInfoJWSAsJSON = new JSONObject();
            userInfoJWSAsJSON.put("jws", aggregatedUserInfoSignedJWT.serialize());
            return userInfoJWSAsJSON.toJSONString();

        } else {
            // we are the IDP, always respond with regular claims
            return generateClaimsAsSignedJwt(accessToken);
            //return generateClaimsAsSignedJwt(accessToken);
        }
    }

    private UserInfo createAggregatedClaims(SignedJWT idpJWT, Set<String> userInfoClaimNames) {
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
        AggregatedClaims identityClaims = new AggregatedClaims(identityClaimName, idpJWT);
        aggregatingUserInfo.addAggregatedClaims(identityClaims);

        //Check if we have the required attributes to call the atp and if it was requested from the RP
        Optional<SignedJWT> atpJWT = checkAndRetrieveAttributes(identityClaimsSet, userInfoClaimNames);

        atpJWT.ifPresent(jwt -> {
            Set<String> attributeClaimName = new HashSet<>();
            attributeClaimName.add("ho_positive_verification_notice");
            AggregatedClaims attributeClaims = new AggregatedClaims(attributeClaimName, jwt);
            aggregatingUserInfo.addAggregatedClaims(attributeClaims);
        });
        return aggregatingUserInfo;
    }

    private Optional<SignedJWT> checkAndRetrieveAttributes(JWTClaimsSet identityClaimsSet, Set<String> userInfoClaimNames) {
        Map<String, Object> idpClaims = identityClaimsSet.getClaims();

        if (idpClaims.containsKey("given_name") && idpClaims.containsKey("family_name") && idpClaims.containsKey("birthdate") && userInfoClaimNames.contains("ho_positive_verification_notice")) {
            String firstName = idpClaims.get("given_name").toString();
            String familyName = idpClaims.get("family_name").toString();
            String dateOfBirth = idpClaims.get("birthdate").toString();
            SignedJWT signedJWT = retrieveAttributesJWT(firstName, familyName, dateOfBirth);
            return Optional.of(signedJWT);
        }
        return Optional.empty();
    }

    private RSAKey createSigningKey() {
        try {
            return new RSAKeyGenerator(2048).keyID("123").generate();
        } catch (JOSEException e) {
            throw new RuntimeException("Unable to create RSA key");
        }
    }

    private String generateClaimsAsSignedJwt(AccessToken accessToken) {
        String userInfoSignedJWT = tokenHandlerService.getUserInfoAsSignedJWT(accessToken);
        JSONObject userInfoJWSAsJSON = new JSONObject();
        userInfoJWSAsJSON.put("jws", userInfoSignedJWT);
        return userInfoJWSAsJSON.toJSONString();
    }

    private String getVerifiableCredentialFor(boolean passThrough, String responseBody, AccessToken accessToken, String transactionID) {
        if (!passThrough) {
            // fetch user info - we're an IDP
            return tokenHandlerService.getVerifiableCredential(accessToken);

        } else {
            // pass through - we're a broker
            String brokerName = getBrokerName(transactionID);
            String brokerDomain = getBrokerDomain(transactionID);

            Map<String, String> authenticationParams = splitQuery(responseBody);
            AuthorizationCode authorizationCode = authnResponseValidationService.handleAuthenticationResponse(authenticationParams, getClientID(brokerName));

            return retrieveTokenAndUserInfoAsVerifiableCredential(authorizationCode, brokerName, brokerDomain);
        }
    }

    private String getBrokerName(String transactionID) {
        return redisService.get(transactionID + "-brokername");
    }

    private ClientID getClientID(String brokerName) {
        String client_id = redisService.get(brokerName);
        if (client_id != null) {
            return new ClientID(client_id);
        }
        return new ClientID();
    }

    private String getBrokerDomain(String transactionID) {
        return redisService.get(transactionID + "-brokerdomain");
    }

    private UserInfo retrieveUserInfo(AuthorizationCode authCode, String brokerName, String brokerDomain) {
        OIDCTokens tokens = tokenRequestService.getTokens(authCode, getClientID(brokerName), brokerDomain);
        return tokenRequestService.getUserInfo(tokens.getBearerAccessToken(), brokerDomain);
    }

    private SignedJWT retrieveUserInfoFromIDP(AuthorizationCode authCode, String brokerName, String brokerDomain) {
        OIDCTokens tokens = tokenRequestService.getTokens(authCode, getClientID(brokerName), brokerDomain);
        return tokenRequestService.getUserInfoAsJWS(tokens.getBearerAccessToken(), brokerDomain);
    }

    private SignedJWT retrieveAttributesJWT(String firstName, String familyName, String dateOfBirth) {
        return tokenRequestService.getAttributesFromATP(firstName, familyName, dateOfBirth);
    }

    private String retrieveTokenAndUserInfoAsVerifiableCredential(AuthorizationCode authCode, String brokerName, String brokerDomain) {
        OIDCTokens tokens = tokenRequestService.getTokens(authCode, getClientID(brokerName), brokerDomain);
        return tokenRequestService.getVerifiableCredentialFromIDP(tokens.getBearerAccessToken(), brokerDomain);
    }
}
