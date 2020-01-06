package uk.gov.ida.stuboidcbroker.resources.oidcprovider;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import io.dropwizard.views.View;
import uk.gov.ida.stuboidcbroker.services.oidcprovider.AuthnResponseGeneratorService;
import uk.gov.ida.stuboidcbroker.views.BrokerResponseView;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;

@Path("/authorizeFormPost")
public class AuthorizationResponseProviderResource {

    private final AuthnResponseGeneratorService generatorService;

    public AuthorizationResponseProviderResource(AuthnResponseGeneratorService generatorService) {
        this.generatorService = generatorService;
    }

    @GET
    @Path("/response")
    @Produces(MediaType.TEXT_HTML)
    public View authorizeResponseHandler(@QueryParam("transaction-id") String transactionID) throws ParseException {
        AuthenticationSuccessResponse successResponse = generatorService.handleAuthenticationRequestResponse(transactionID);
        return new BrokerResponseView(
                successResponse.getState(),
                successResponse.getAuthorizationCode(),
                successResponse.getIDToken(),
                successResponse.getRedirectionURI(),
                successResponse.getAccessToken(),
                transactionID);
    }
}
