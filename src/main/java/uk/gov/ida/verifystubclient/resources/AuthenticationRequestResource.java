package uk.gov.ida.verifystubclient.resources;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.AuthenticationResponse;
import com.nimbusds.openid.connect.sdk.AuthenticationResponseParser;
import com.nimbusds.openid.connect.sdk.claims.CodeHash;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import com.sun.net.httpserver.HttpContext;
import io.dropwizard.views.View;
import uk.gov.ida.verifystubclient.configuration.VerifyStubClientConfiguration;
import uk.gov.ida.verifystubclient.services.ClientService;
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
import java.net.URI;
import java.net.URL;
import java.net.URLDecoder;
import java.util.LinkedHashMap;
import java.util.Map;

@Path("/")
public class AuthenticationRequestResource {

    private final VerifyStubClientConfiguration stubClientConfiguration;
    private final ClientService clientService;

    public AuthenticationRequestResource(
            VerifyStubClientConfiguration stubClientConfiguration,
            ClientService clientService) {
        this.stubClientConfiguration = stubClientConfiguration;
        this.clientService = clientService;
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

        ClientID clientID = new ClientID("stub-client");

        return Response
                .status(302)
                .location(clientService.generateAuthenticationRequest(
                        stubClientConfiguration.getAuthorisationEndpointURI(),
                        clientID,
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

        String id_token = authenticationParams.get("id_token");
        String authCode = authenticationParams.get("code");

        AuthorizationCode authorizationCode = new AuthorizationCode(authCode);
        CodeHash authCodeHash = CodeHash.compute(authorizationCode, JWSAlgorithm.RS256);

        SignedJWT signedJWT = SignedJWT.parse(id_token);
        JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();
        IDTokenClaimsSet idTokenClaimsSet = new IDTokenClaimsSet(jwtClaimsSet);
        CodeHash idTokencodeHash = idTokenClaimsSet.getCodeHash();

        if (!authCodeHash.equals(idTokencodeHash)) {
            throw new RuntimeException("CodeHashes are not equal");
        }

        return Response.ok(authCode).build();
    }

    @GET
    @Path("/retrieveTokenAndUserInfo")
    @Produces(MediaType.APPLICATION_JSON)
    public Response retrieveTokenAndUserInfo(@Context UriInfo uriInfo) throws UnsupportedEncodingException {

            String query = uriInfo.getRequestUri().getQuery();
            Map<String, String> authenticationParams = splitQuery(query);

            String authCode = authenticationParams.get("code");

            UserInfo userInfo = getClaims(new AuthorizationCode(authCode));
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

    private UserInfo getClaims(AuthorizationCode authorizationCode) {
        //Gets the ID token and Access token from the OpenID Provider
        OIDCTokens tokens = clientService.getTokens(authorizationCode);

        //Get the user info from the OpenID Provider using the Access Token/Bearer Token
        UserInfo userInfo = clientService.getUserInfo(tokens.getBearerAccessToken());


        return userInfo;
    }

}
