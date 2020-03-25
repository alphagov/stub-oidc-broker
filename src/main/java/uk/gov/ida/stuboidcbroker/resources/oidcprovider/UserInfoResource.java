package uk.gov.ida.stuboidcbroker.resources.oidcprovider;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.ClaimsRequest;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import net.minidev.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.ida.stuboidcbroker.configuration.StubOidcBrokerConfiguration;
import uk.gov.ida.stuboidcbroker.services.oidcclient.AuthnResponseValidationService;
import uk.gov.ida.stuboidcbroker.services.oidcclient.TokenRequestService;
import uk.gov.ida.stuboidcbroker.services.oidcprovider.TokenHandlerService;
import uk.gov.ida.stuboidcbroker.services.oidcprovider.UserInfoService;
import uk.gov.ida.stuboidcbroker.services.shared.PKIService;
import uk.gov.ida.stuboidcbroker.services.shared.RedisService;

import javax.validation.constraints.NotNull;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.security.PrivateKey;
import java.util.Map;
import java.util.Set;

import static uk.gov.ida.stuboidcbroker.services.shared.QueryParameterHelper.splitQuery;

@Path("/")
public class UserInfoResource {

    private static final Logger LOG = LoggerFactory.getLogger(UserInfoResource.class);
    private final TokenHandlerService tokenHandlerService;
    private final RedisService redisService;
    private final AuthnResponseValidationService authnResponseValidationService;
    private final TokenRequestService tokenRequestService;
    private final UserInfoService userInfoService;
    private final PKIService pkiService;
    private final StubOidcBrokerConfiguration configuration;

    public UserInfoResource(
            TokenHandlerService tokenHandlerService,
            RedisService redisService,
            AuthnResponseValidationService authnResponseValidationService,
            TokenRequestService tokenRequestService,
            UserInfoService userInfoService,
            PKIService pkiService,
            StubOidcBrokerConfiguration configuration) {
        this.tokenHandlerService = tokenHandlerService;
        this.redisService = redisService;
        this.authnResponseValidationService = authnResponseValidationService;
        this.tokenRequestService = tokenRequestService;
        this.userInfoService = userInfoService;
        this.pkiService = pkiService;
        this.configuration = configuration;
    }

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

            switch (configuration.getClaimType()) {
                case "VerifiableCredential":
                    String verifiableCredentialString = getVerifiableCredentialFor(passThrough, responseBody, accessToken, transactionID);
                    if (passThrough) {
                        SignedJWT verifiableCredentialJwt = createSignedJWTFromVC(verifiableCredentialString);
                        AuthenticationRequest authRequestFromTransactionID = getAuthRequestFromTransactionID(transactionID);
                        String aggregatedClaimsWithVC = aggregateClaimsForVC(verifiableCredentialJwt, authRequestFromTransactionID);
                        return Response.ok(aggregatedClaimsWithVC).build();
                    }
                    return Response.ok(verifiableCredentialString).build();
                case "VerifiablePresentation":
                    String verifiableCredential = getVerifiableCredentialFor(passThrough, responseBody, accessToken, transactionID);
                    if (passThrough) {
                        SignedJWT verifiableCredentialJwt = createSignedJWTFromVC(verifiableCredential);
                        AuthenticationRequest authRequestFromTransactionID = getAuthRequestFromTransactionID(transactionID);
                        String verifiablePresentationString = createVerifiablePresentation(verifiableCredentialJwt, authRequestFromTransactionID);
                        return Response.ok(verifiablePresentationString).build();
                    }
                    return Response.ok(verifiableCredential).build();
                case "RegularClaims":
                    String regularClaims = getRegularClaimsFor(passThrough, responseBody, accessToken, transactionID);
                    return Response.ok(regularClaims).build();

                case "AggregatedClaims":
                    String aggregatedClaims = aggregateClaimsFor(passThrough, responseBody, accessToken, transactionID);
                    return Response.ok(aggregatedClaims).build();

                default:
                    throw new IllegalStateException("Unrecognised response format: " + configuration.getClaimType());
            }

        } catch (ParseException e) {
            throw new RuntimeException("Unable to parse authorization header: " + authorizationHeader + " to access token", e);
        }
    }

    private AuthenticationRequest getAuthRequestFromTransactionID(String transactionID) {
        String serialisedRequest = redisService.get(transactionID);

        AuthenticationRequest authenticationRequest;
        try {
            return AuthenticationRequest.parse(serialisedRequest);
        } catch (ParseException e) {
            throw new RuntimeException("Unable to parse authentication request", e);
        }
    }

    private String getRegularClaimsFor(boolean passThrough, String responseBody, AccessToken accessToken, String transactionID) {
        if (passThrough) {
            // pass through - we're a broker
            String brokerName = getBrokerName(transactionID);
            String brokerDomain = getBrokerDomain(transactionID);

            Map<String, String> authenticationParams = splitQuery(responseBody);
            AuthorizationCode authorizationCode = authnResponseValidationService.handleAuthenticationResponse(authenticationParams, getClientID(brokerName));
            return userInfoService.retrieveTokenAndUserInfo(authorizationCode, brokerName, brokerDomain);

        } else {
            // we are the IDP, respond with the claims -- in a JWT?
            return generateClaimsAsSignedJwt(accessToken);
        }
    }

    private SignedJWT createSignedJWTFromVC(String verifiableCredentialString) {
        SignedJWT verifiableCredentialJwt;
        try {
            String verifiableCredentialJson = JSONObjectUtils.parse(verifiableCredentialString).get("jws").toString();
            return SignedJWT.parse(verifiableCredentialJson);
        } catch (java.text.ParseException e) {
            throw new RuntimeException(e);
        }
    }

    private String createVerifiablePresentation(SignedJWT verifiableCredentialJwt, AuthenticationRequest authenticationRequest) {
        Set<String> userInfoClaimsNames = createUserInfoClaimsNames(authenticationRequest);
        String clientID = authenticationRequest.getClientID().toString();

        JWTClaimsSet jwtClaimsSet = userInfoService.generateVerifiablePresentation(verifiableCredentialJwt, userInfoClaimsNames, clientID);

        SignedJWT signedJWT = generateAndSignJWT(jwtClaimsSet);

        JSONObject jsonResponse = new JSONObject();
        jsonResponse.put("jws", signedJWT.serialize());

        return jsonResponse.toJSONString();
    }

    private String aggregateClaimsForVC(SignedJWT verifiableCredentialJwt, AuthenticationRequest authenticationRequest) {
        Set<String> userInfoClaimsNames = createUserInfoClaimsNames(authenticationRequest);
        String clientID = authenticationRequest.getClientID().toString();
        UserInfo aggregatedUserInfo = userInfoService.createAggregatedUserInfoUsingVerifiableCredential(verifiableCredentialJwt, userInfoClaimsNames, clientID);

        SignedJWT aggregatedJWT;
        try {
            aggregatedJWT = generateAndSignJWT(aggregatedUserInfo.toJWTClaimsSet());
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }

        JSONObject userInfoJWSAsJSON = new JSONObject();
        userInfoJWSAsJSON.put("jws", aggregatedJWT.serialize());
        return userInfoJWSAsJSON.toJSONString();
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
            Set<String> userInfoClaimNames = createUserInfoClaimsNames(authenticationRequest);

            String brokerName = getBrokerName(transactionID);
            String brokerDomain = getBrokerDomain(transactionID);

            Map<String, String> authenticationParams = splitQuery(responseBody);
            AuthorizationCode authorizationCode = authnResponseValidationService.handleAuthenticationResponse(authenticationParams, getClientID(brokerName));
            String clientID = authenticationRequest.getClientID().toString();

            // fetch the user info from the IDP as a JWT
            SignedJWT idpJWT = retrieveUserInfoFromIDP(authorizationCode, brokerName, brokerDomain);
            UserInfo aggregatedUserInfo = userInfoService. createAggregatedUserInfo(idpJWT, userInfoClaimNames, clientID);

            SignedJWT aggregatedJWT;
            try {
                aggregatedJWT = generateAndSignJWT(aggregatedUserInfo.toJWTClaimsSet());
            } catch (ParseException e) {
                throw new RuntimeException(e);
            }

            JSONObject userInfoJWSAsJSON = new JSONObject();
            userInfoJWSAsJSON.put("jws", aggregatedJWT.serialize());
            return userInfoJWSAsJSON.toJSONString();

        } else {
            // we are the IDP, always respond with regular claims
            return generateClaimsAsSignedJwt(accessToken);
        }
    }

    private Set<String> createUserInfoClaimsNames(AuthenticationRequest authenticationRequest) {
        ClaimsRequest claimRequest = authenticationRequest.getClaims();
        Set<String> userInfoClaimNames = claimRequest.getUserInfoClaimNames(false);

        return userInfoClaimNames;
    }

    private SignedJWT generateAndSignJWT(JWTClaimsSet aggregatedUserInfoJWT) {
        PrivateKey privateKey = pkiService.getOrganisationPrivateKey();

        SignedJWT aggregatedUserInfoSignedJWT;
        try {
            JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .type(JOSEObjectType.JWT)
                    .keyID(configuration.getOrgID())
                    .build();
            JWSSigner signer = new RSASSASigner(privateKey);
            aggregatedUserInfoSignedJWT = new SignedJWT(jwsHeader, aggregatedUserInfoJWT);
            aggregatedUserInfoSignedJWT.sign(signer);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return aggregatedUserInfoSignedJWT;
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

            return userInfoService.retrieveTokenAndUserInfo(authorizationCode, brokerName, brokerDomain);
        }
    }

    private UserInfo retrieveUserInfo(AuthorizationCode authCode, String brokerName, String brokerDomain) {
        OIDCTokens tokens = tokenRequestService.getTokens(authCode, getClientID(brokerName), brokerDomain);
        return tokenRequestService.getUserInfo(tokens.getBearerAccessToken(), brokerDomain);
    }

    private SignedJWT retrieveUserInfoFromIDP(AuthorizationCode authCode, String brokerName, String brokerDomain) {
        OIDCTokens tokens = tokenRequestService.getTokens(authCode, getClientID(brokerName), brokerDomain);
        return tokenRequestService.getUserInfoAsJWS(tokens.getBearerAccessToken(), brokerDomain);
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
}
