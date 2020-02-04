package uk.gov.ida.stuboidcbroker.resources.oidcprovider;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import net.minidev.json.JSONObject;
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
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.text.ParseException;

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
    public Response register(String requestBody, @HeaderParam("Authorization") @NotNull String authorizationHeader) throws ParseException, com.nimbusds.oauth2.sdk.ParseException {

        HttpResponse<String> directoryResponse = sendHttpRequest(UriBuilder.fromUri(configuration.getDirectoryURI()).path(Urls.Directory.VERIFY_CLIENT_TOKEN).build(), authorizationHeader);

        String orgId = JSONObjectUtils.parse(directoryResponse.body()).getAsString("organisation_id");

        if (orgId == null) {
            return Response.status(Response.Status.FORBIDDEN).entity("Org ID not found in Directory. Probably because the client token sent in the registration request is invalid").build();
        }

        // Maybe validate against the orgId in the SSA

        JSONObject jwtObject = JSONObjectUtils.parse(requestBody);
        String signedJwt = jwtObject.get("signed-jwt").toString();
        SignedJWT signedJWT = SignedJWT.parse(signedJwt);
        String response = registrationHandlerService.processHTTPRequest(signedJWT);

        return Response.ok(response).build();
    }

    private HttpResponse<String> sendHttpRequest(URI uri, String clientToken) {

        JSONObject json = new JSONObject();
        json.put("client_token", clientToken);

        HttpRequest request = HttpRequest.newBuilder()
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json.toJSONString()))
                .uri(uri)
                .build();

        try {
            return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }
    }
}
