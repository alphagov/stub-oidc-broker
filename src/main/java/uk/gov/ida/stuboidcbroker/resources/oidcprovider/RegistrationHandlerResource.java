package uk.gov.ida.stuboidcbroker.resources.oidcprovider;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import net.minidev.json.JSONObject;
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

    public RegistrationHandlerResource(RegistrationHandlerService registrationHandlerService) {
        this.registrationHandlerService = registrationHandlerService;
    }

    private final HttpClient httpClient = HttpClient.newBuilder()
            .build();

    @POST
    @Path("/register")
    @Produces(MediaType.APPLICATION_JSON)
    public Response register(String requestBody, @HeaderParam("Authorization") @NotNull String authorizationHeader) throws ParseException, com.nimbusds.oauth2.sdk.ParseException {

        HttpResponse<String> directoryResponse = sendHttpRequest(UriBuilder.fromUri("http://localhost:3000/verify-client-token").build(), authorizationHeader);

        String orgId = JSONObjectUtils.parse(directoryResponse.body()).getAsString("organisation_id");

        if (orgId == null) {
            return Response.status(Response.Status.FORBIDDEN).build();
        }

        JSONObject jwtObject = JSONObjectUtils.parse(requestBody);
        String signedJwt = jwtObject.get("signed-jwt").toString();
        SignedJWT signedJWT = SignedJWT.parse(signedJwt);
        String response = registrationHandlerService.processHTTPRequest(signedJWT);

        return Response.ok(response).build();
    }

    private HttpResponse<String> sendHttpRequest(URI uri, String clientToken) {

        HttpRequest request = HttpRequest.newBuilder()
                .POST(HttpRequest.BodyPublishers.ofString(("client_token=" + clientToken)))
                .uri(uri)
                .build();

        try {
            return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }
    }
}
