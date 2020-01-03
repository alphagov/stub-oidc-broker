package uk.gov.ida.stuboidcbroker.resources.oidcprovider;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import net.minidev.json.JSONObject;
import uk.gov.ida.stuboidcbroker.services.RegistrationHandlerService;

import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.text.ParseException;

@Path("/")
public class RegistrationHandlerResource {

    private final RegistrationHandlerService registrationHandlerService;

    public RegistrationHandlerResource(RegistrationHandlerService registrationHandlerService) {
        this.registrationHandlerService = registrationHandlerService;
    }

    @POST
    @Path("/register")
    @Produces(MediaType.APPLICATION_JSON)
    public Response register(String requestBody) throws ParseException, com.nimbusds.oauth2.sdk.ParseException {
        JSONObject jwtObject = JSONObjectUtils.parse(requestBody);
        String signedJwt = jwtObject.get("signed-jwt").toString();
        SignedJWT signedJWT = SignedJWT.parse(signedJwt);
        String response = registrationHandlerService.processHTTPRequest(signedJWT);

        return Response.ok(response).build();
    }
}
