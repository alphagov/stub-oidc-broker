package uk.gov.ida.stuboidcbroker.resources.registration;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import net.minidev.json.JSONObject;
import uk.gov.ida.stuboidcbroker.services.RedisService;
import uk.gov.ida.stuboidcbroker.services.RegistrationHandlerService;
import uk.gov.ida.stuboidcbroker.services.RegistrationSenderService;

import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.text.ParseException;

@Path("/")
public class StubOidcBrokerRegistrationResource {

    private final RegistrationSenderService registrationSenderService;
    private final RegistrationHandlerService registrationHandlerService;
    private final RedisService redisService;

    public StubOidcBrokerRegistrationResource(RegistrationSenderService registrationSenderService, RegistrationHandlerService registrationHandlerService, RedisService redisService) {
        this.registrationSenderService = registrationSenderService;
        this.registrationHandlerService = registrationHandlerService;
        this.redisService = redisService;
    }

    @POST
    @Path("/sendRegistrationRequest")
    @Produces(MediaType.APPLICATION_JSON)
    public Response sendRegistrationRequest(@FormParam("ssa") String ssa, @FormParam("privateKey") String privateKey, @FormParam("brokerDomain") String brokerDomain) throws JOSEException, java.text.ParseException, IOException {
        // get ssa for this broker from directory
        // get private key for this broker directory

        String responseString = registrationSenderService.sendRegistrationRequest(ssa, privateKey, brokerDomain);

        return Response.ok(responseString).build();
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

    @GET
    @Path("/resetClientID")
    public void clientReset() {
        redisService.delete("CLIENT_ID");
    }

}
