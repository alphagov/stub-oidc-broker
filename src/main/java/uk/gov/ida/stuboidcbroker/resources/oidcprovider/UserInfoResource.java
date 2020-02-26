package uk.gov.ida.stuboidcbroker.resources.oidcprovider;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
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
import java.util.Map;

import static uk.gov.ida.stuboidcbroker.services.shared.QueryParameterHelper.splitQuery;

@Path("/")
public class UserInfoResource {

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

    public static boolean RESPOND_WITH_VERIFIABLE_CREDENTIAL = false;

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

            // choose between VC or Claims + AggregatedClaims
            if (RESPOND_WITH_VERIFIABLE_CREDENTIAL) {
                String verifiableCredential = getVerifiableCredentialFor(passThrough, responseBody, accessToken, transactionID);
                return Response.ok(verifiableCredential).build();

            } else {
                if (passThrough) {
                    // we are the broker, fetch the claims from the IDP and aggregate them
                    //fetchAndAggregateUserInfo();
                    // pass through - we're a broker
                    String brokerName = getBrokerName(transactionID);
                    String brokerDomain = getBrokerDomain(transactionID);

                    Map<String, String> authenticationParams = splitQuery(responseBody);
                    AuthorizationCode authorizationCode = authnResponseValidationService.handleAuthenticationResponse(authenticationParams, getClientID(brokerName));
                    String result = retrieveTokenAndUserInfo(authorizationCode, brokerName, brokerDomain);
                    return Response.ok(result).build();

                } else {
                    // we are the IDP, respond with the claims -- in a JWT?
                    String userInfoSignedJWT = tokenHandlerService.getUserInfoAsSignedJWT(accessToken);
                    JSONObject userInfoJWSAsJSON = new JSONObject();
                    userInfoJWSAsJSON.put("jws", userInfoSignedJWT);
                    return Response.ok(userInfoJWSAsJSON.toJSONString()).build();
                }
            }

        } catch (ParseException e) {
            throw new RuntimeException("Unable to parse authorization header: " + authorizationHeader + " to access token", e);
        }
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

            return retrieveTokenAndUserInfo(authorizationCode, brokerName, brokerDomain);
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

    private String retrieveTokenAndUserInfo(AuthorizationCode authCode, String brokerName, String brokerDomain) {

        OIDCTokens tokens = tokenRequestService.getTokens(authCode, getClientID(brokerName), brokerDomain);

//      UserInfo userInfo = tokenService.getUserInfo(tokens.getBearerAccessToken());
//      String userInfoToJson = userInfo.toJSONObject().toJSONString();

        return tokenRequestService.getVerifiableCredentialFromIDP(tokens.getBearerAccessToken(), brokerDomain);
    }
}
