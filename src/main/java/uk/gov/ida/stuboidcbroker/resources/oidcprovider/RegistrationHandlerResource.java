package uk.gov.ida.stuboidcbroker.resources.oidcprovider;

import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import uk.gov.ida.stuboidcbroker.configuration.StubOidcBrokerConfiguration;
import uk.gov.ida.stuboidcbroker.rest.Urls;
import uk.gov.ida.stuboidcbroker.services.oidcprovider.RegistrationHandlerService;

import javax.validation.constraints.NotNull;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import java.net.URI;
import java.net.http.HttpResponse;

@Path("/")
public class RegistrationHandlerResource {

    private final RegistrationHandlerService registrationHandlerService;

    private final StubOidcBrokerConfiguration configuration;

    public RegistrationHandlerResource(RegistrationHandlerService registrationHandlerService, StubOidcBrokerConfiguration configuration) {
        this.registrationHandlerService = registrationHandlerService;
        this.configuration = configuration;
    }

    @POST
    @Path("/register")
    @Produces(MediaType.APPLICATION_JSON)
    public Response register(
            String requestBody,
            @HeaderParam("Authorization") @NotNull String authorizationHeader) {

        if (!isClientAuthenticated(authorizationHeader)) {
            return Response.status(Response.Status.FORBIDDEN).entity("Org ID not found in Directory. Probably because the client token sent in the registration request is invalid").build();
        }

        String registrationResponse = registrationHandlerService.parseRegistrationRequest(requestBody);

        return Response.ok(registrationResponse).build();
    }

    private boolean isClientAuthenticated(String authorizationHeader) {
        URI directoryURI = UriBuilder.fromUri(configuration.getDirectoryURI())
                .path(Urls.Directory.VERIFY_CLIENT_TOKEN)
                .build();
        HttpResponse<String> directoryResponse = registrationHandlerService.sendHttpRegistrationRequest(directoryURI, authorizationHeader);

        String orgId;
        try {
            orgId = JSONObjectUtils.parse(directoryResponse.body()).getAsString("organisation_id");
        } catch (com.nimbusds.oauth2.sdk.ParseException e) {
            throw new RuntimeException("Unable to parse client token response from the Directory to retrieve orgId" ,e);
        }

        if (orgId == null) {
            return false;
        }
        return true;
    }
}
