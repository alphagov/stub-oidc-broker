package uk.gov.ida.verifystubclient.resources;

import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import net.minidev.json.JSONObject;
import uk.gov.ida.verifystubclient.configuration.VerifyStubClientConfiguration;
import uk.gov.ida.verifystubclient.services.AuthnRequestService;
import uk.gov.ida.verifystubclient.services.AuthnResponseService;
import uk.gov.ida.verifystubclient.services.TokenService;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.UnsupportedEncodingException;
import java.util.Map;

import static uk.gov.ida.verifystubclient.services.QueryParameterHelper.splitQuery;

@Path("/formPost")
public class StubClientFormPostResource {

    private static final ClientID CLIENT_ID = new ClientID("verify-stub-client");
    private final VerifyStubClientConfiguration stubClientConfiguration;
    private final TokenService tokenService;
    private final AuthnRequestService authnRequestService;

    public StubClientFormPostResource(
            VerifyStubClientConfiguration stubClientConfiguration,
            TokenService tokenService,
            AuthnRequestService authnRequestService) {
        this.stubClientConfiguration = stubClientConfiguration;
        this.tokenService = tokenService;
        this.authnRequestService = authnRequestService;
    }

    @GET
    @Path("/serviceAuthenticationRequest")
    @Produces(MediaType.APPLICATION_JSON)
    public Response formPostAuthenticationRequest() {

        return Response
                .status(302)
                .location(authnRequestService.generateFormPostAuthenticationRequest(
                        stubClientConfiguration.getAuthorisationEndpointFormPostURI(),
                        CLIENT_ID,
                        stubClientConfiguration.getRedirectFormPostURI()).toURI())
                        .build();
    }

    @POST
    @Path("/validateAuthenticationResponse")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response validateAuthenticationResponse(String postBody) throws UnsupportedEncodingException, java.text.ParseException, ParseException {
        //TODO: Validate the signature of the ID token

        Map<String, String> authenticationParams = splitQuery(postBody);

        String authCode = authenticationParams.get("code");
        AuthorizationCode authorizationCode = new AuthorizationCode(authCode);

        String id_token = authenticationParams.get("id_token");
        SignedJWT signedJWT = SignedJWT.parse(id_token);
        JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();
        IDTokenClaimsSet idToken = new IDTokenClaimsSet(jwtClaimsSet);

        AuthnResponseService authResponseReceiverService = new AuthnResponseService(idToken);

        authResponseReceiverService.validateCHash(authorizationCode);

        String stringAccessToken = authenticationParams.get("access_token");
        if (stringAccessToken != null && stringAccessToken.length() > 0) {
            JSONObject accessTokenJson = JSONObjectUtils.parse(stringAccessToken);
            authResponseReceiverService.validateAccessTokenHash(AccessToken.parse(accessTokenJson));
        }

        String state = authenticationParams.get("state");
        String nonce = tokenService.getNonce(state);
        authResponseReceiverService.validateNonce(nonce);
        authResponseReceiverService.validateNonceUsageCount(tokenService.getNonceUsageCount(nonce));

        authResponseReceiverService.validateIssuer();

        authResponseReceiverService.validateAudience(CLIENT_ID);

        authResponseReceiverService.validateIDTokenSignature(signedJWT);

        String userInfoInJson = retrieveTokenAndUserInfo(authorizationCode);

        return Response.ok(userInfoInJson).build();
    }


    public String retrieveTokenAndUserInfo(AuthorizationCode authCode) {

            OIDCTokens tokens = tokenService.getTokens(authCode, CLIENT_ID);
            UserInfo userInfo = tokenService.getUserInfo(tokens.getBearerAccessToken());

            String userInfoToJson = userInfo.toJSONObject().toJSONString();
            return userInfoToJson;
    }
}
