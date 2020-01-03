package uk.gov.ida.stuboidcbroker.resources.oidcprovider;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.AuthenticationSuccessResponse;
import io.dropwizard.views.View;
import uk.gov.ida.stuboidcbroker.services.AuthnRequestValidationService;
import uk.gov.ida.stuboidcbroker.views.BrokerResponseView;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;

@Path("/authorizeFormPost")
public class AuthorizationResponseProviderResource {

    private final AuthnRequestValidationService validationService;

    public AuthorizationResponseProviderResource(AuthnRequestValidationService validationService) {
        this.validationService = validationService;
    }

    @GET
    @Path("/response")
    @Produces(MediaType.TEXT_HTML)
    public View authorizeResponseHandler(@QueryParam("transaction-id") String transactionID) throws ParseException {
        AuthenticationSuccessResponse successResponse = validationService.handleAuthenticationRequestResponse(transactionID);
        return new BrokerResponseView(
                successResponse.getState(),
                successResponse.getAuthorizationCode(),
                successResponse.getIDToken(),
                successResponse.getRedirectionURI(),
                successResponse.getAccessToken(),
                transactionID);
    }
}
