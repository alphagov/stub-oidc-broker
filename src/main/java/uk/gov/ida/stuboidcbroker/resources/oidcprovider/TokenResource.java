package uk.gov.ida.stuboidcbroker.resources.oidcprovider;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.ida.stuboidcbroker.services.oidcprovider.TokenHandlerService;

import javax.validation.constraints.NotNull;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

@Path("/")
public class TokenResource {

    private TokenHandlerService tokenHandlerService;
    private static final Logger LOG = LoggerFactory.getLogger(TokenResource.class);

    public TokenResource(TokenHandlerService tokenHandlerService) {
        this.tokenHandlerService = tokenHandlerService;
    }

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/token")
    public Response getProviderTokens(
            @FormParam("code") @NotNull AuthorizationCode authCode) {
        LOG.info("Token end point");
        OIDCTokenResponse response = new OIDCTokenResponse(tokenHandlerService.getTokens(authCode));
        return Response.ok(response.toJSONObject()).build();
    }
}
