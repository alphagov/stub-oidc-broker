package uk.gov.ida.verifystubclient.resources;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import io.dropwizard.views.View;
import uk.gov.ida.verifystubclient.configuration.VerifyStubClientConfiguration;
import uk.gov.ida.verifystubclient.services.AuthnRequestService;
import uk.gov.ida.verifystubclient.services.ClientService;
import uk.gov.ida.verifystubclient.services.AuthnResponseReceiverService;
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
import java.net.URLDecoder;
import java.util.LinkedHashMap;
import java.util.Map;

@Path("/")
public class AuthenticationRequestResource {

    private static final ClientID CLIENT_ID = new ClientID("verify-stub-client");
    private final VerifyStubClientConfiguration stubClientConfiguration;
    private final ClientService clientService;
    private final AuthnRequestService authnRequestService;

    public AuthenticationRequestResource(
            VerifyStubClientConfiguration stubClientConfiguration,
            ClientService clientService,
            AuthnRequestService authnRequestService) {
        this.stubClientConfiguration = stubClientConfiguration;
        this.clientService = clientService;
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
    @Path("/authenticationCallback")
    public View authenticationCallback() {
        return new AuthenticationCallbackView();
    }

    @POST
    @Path("/validateAuthenticationResponse")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response validateAuthenticationResponse(String postBody) throws UnsupportedEncodingException, java.text.ParseException, ParseException {
        //TODO: Validate that the ID token contains the correct nonce
        //TODO: Validate the signature of the ID token


        Map<String, String> authenticationParams = splitQuery(postBody);

        String authCode = authenticationParams.get("code");
        AuthorizationCode authorizationCode = new AuthorizationCode(authCode);

        String id_token = authenticationParams.get("id_token");
        SignedJWT signedJWT = SignedJWT.parse(id_token);
        JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();
        IDTokenClaimsSet idToken = new IDTokenClaimsSet(jwtClaimsSet);

        AuthnResponseReceiverService authResponseReveiverService = new AuthnResponseReceiverService(idToken);

        authResponseReveiverService.validateCHash(authorizationCode);

        String state = authenticationParams.get("state");
        String nonce = clientService.getNonce(state);
        authResponseReveiverService.validateNonce(nonce);
        authResponseReveiverService.validateNonceUsageCount(clientService.getNonceUsageCount(nonce));

        authResponseReveiverService.validateIssuer();

        authResponseReveiverService.validateAudience(CLIENT_ID);

        authResponseReveiverService.validateIDTokenSignature(signedJWT);

        return Response.ok(authCode).build();
    }

    @GET
    @Path("/retrieveTokenAndUserInfo")
    @Produces(MediaType.APPLICATION_JSON)
    public Response retrieveTokenAndUserInfo(@Context UriInfo uriInfo) throws UnsupportedEncodingException {

            String query = uriInfo.getRequestUri().getQuery();
            Map<String, String> authenticationParams = splitQuery(query);
            String authCode = authenticationParams.get("code");

            OIDCTokens tokens = clientService.getTokens(new AuthorizationCode(authCode), CLIENT_ID);
            UserInfo userInfo = clientService.getUserInfo(tokens.getBearerAccessToken());

            String userInfoToJson = userInfo.toJSONObject().toJSONString();
            return Response.ok(userInfoToJson).build();
    }

    private static Map<String, String> splitQuery(String query) throws UnsupportedEncodingException {
        Map<String, String> query_pairs = new LinkedHashMap<>();
        String[] pairs = query.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf("=");
            query_pairs.put(URLDecoder.decode(pair.substring(0, idx), "UTF-8"), URLDecoder.decode(pair.substring(idx + 1), "UTF-8"));
        }
        return query_pairs;
    }
}
