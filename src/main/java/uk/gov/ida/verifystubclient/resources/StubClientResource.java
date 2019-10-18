package uk.gov.ida.verifystubclient.resources;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import io.dropwizard.views.View;
import uk.gov.ida.verifystubclient.configuration.VerifyStubClientConfiguration;
import uk.gov.ida.verifystubclient.services.AuthnRequestService;
import uk.gov.ida.verifystubclient.services.TokenService;
import uk.gov.ida.verifystubclient.services.AuthnResponseService;
import uk.gov.ida.verifystubclient.views.AuthenticationCallbackView;
import uk.gov.ida.verifystubclient.views.StartPageView;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import java.io.UnsupportedEncodingException;
import java.util.Map;

import static uk.gov.ida.verifystubclient.services.QueryParameterHelper.splitQuery;

@Path("/")
public class StubClientResource {

    private static final ClientID CLIENT_ID = new ClientID("verify-stub-client");
    private final VerifyStubClientConfiguration stubClientConfiguration;
    private final TokenService tokenService;
    private final AuthnRequestService authnRequestService;

    public StubClientResource(
            VerifyStubClientConfiguration stubClientConfiguration,
            TokenService tokenService,
            AuthnRequestService authnRequestService) {
        this.stubClientConfiguration = stubClientConfiguration;
        this.tokenService = tokenService;
        this.authnRequestService = authnRequestService;
    }

    @GET
    @Path("/")
    public View startPage() {
        return new StartPageView();
    }

    @GET
    @Path("/serviceAuthenticationRequest")
    @Produces(MediaType.APPLICATION_JSON)
    public Response serviceAuthenticationRequest() {

        return Response
                .status(302)
                .location(authnRequestService.generateAuthenticationRequest(
                        stubClientConfiguration.getAuthorisationEndpointURI(),
                        CLIENT_ID,
                        stubClientConfiguration.getRedirectURI()).toURI())
                        .build();
    }

    @GET
    @Path("/formPostAuthenticationRequest")
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

    @GET
    @Path("/authenticationCallback")
    public View authenticationCallback() {
        return new AuthenticationCallbackView();
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
            authResponseReceiverService.validateAccessTokenHash(new BearerAccessToken(stringAccessToken));
        }

        String state = authenticationParams.get("state");
        String nonce = tokenService.getNonce(state);
        authResponseReceiverService.validateNonce(nonce);
        authResponseReceiverService.validateNonceUsageCount(tokenService.getNonceUsageCount(nonce));

        authResponseReceiverService.validateIssuer();

        authResponseReceiverService.validateAudience(CLIENT_ID);

        authResponseReceiverService.validateIDTokenSignature(signedJWT);

        return Response.ok(authCode).build();
    }

    @GET
    @Path("/retrieveTokenAndUserInfo")
    @Produces(MediaType.APPLICATION_JSON)
    public Response retrieveTokenAndUserInfo(@Context UriInfo uriInfo) throws UnsupportedEncodingException {

            String query = uriInfo.getRequestUri().getQuery();
            Map<String, String> authenticationParams = splitQuery(query);
            String authCode = authenticationParams.get("code");

            OIDCTokens tokens = tokenService.getTokens(new AuthorizationCode(authCode), CLIENT_ID);
            UserInfo userInfo = tokenService.getUserInfo(tokens.getBearerAccessToken());

            String userInfoToJson = userInfo.toJSONObject().toJSONString();
            return Response.ok(userInfoToJson).build();
    }

}
