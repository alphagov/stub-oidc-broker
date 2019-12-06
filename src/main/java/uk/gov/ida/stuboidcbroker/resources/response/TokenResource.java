package uk.gov.ida.stuboidcbroker.resources.response;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.ida.stuboidcbroker.services.TokenGeneratorService;

import javax.validation.constraints.NotNull;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

@Path("/")
public class TokenResource {

    private TokenGeneratorService tokenService;
    private static final Logger LOG = LoggerFactory.getLogger(TokenResource.class);


    public TokenResource(TokenGeneratorService tokenService) {
        this.tokenService = tokenService;
    }

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/token")
    public Response getProviderTokens(
            @FormParam("code") @NotNull AuthorizationCode authCode) {
        LOG.info("Token end point");
        OIDCTokenResponse response = new OIDCTokenResponse(tokenService.getTokens(authCode));
        return Response.ok(response.toJSONObject()).build();
    }

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/userinfo")
    public Response getUserInfo(@HeaderParam("Authorization") @NotNull String authorizationHeader) {
        try {
            LOG.info("Received request to get User Info");
            //This will need to be used to get the user info but we're not using it for now
            AccessToken accessToken = AccessToken.parse(authorizationHeader);

//            UserInfo userInfo = tokenService.getUserInfo(accessToken);
            String verifiableCredential = tokenService.getVerifiableCredential(accessToken);
            return Response.ok(verifiableCredential).build();
        } catch (ParseException e) {
            throw new RuntimeException("Unable to parse authorization header: " + authorizationHeader + " to access token", e);
        }
    }
}
