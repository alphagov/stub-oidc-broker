package uk.gov.ida.stuboidcbroker.resources.registration;

import com.nimbusds.jose.JOSEException;
import uk.gov.ida.stuboidcbroker.services.RedisService;
import uk.gov.ida.stuboidcbroker.services.RegistrationService;

import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;

@Path("/")
public class StubOidcBrokerRegistrationResource {

    private final RegistrationService registrationService;
    private final RedisService redisService;

    public StubOidcBrokerRegistrationResource(RegistrationService registrationService, RedisService redisService) {
        this.registrationService = registrationService;
        this.redisService = redisService;
    }

    @POST
    @Path("/sendRegistrationRequest")
    @Produces(MediaType.APPLICATION_JSON)
    public Response sendRegistrationRequest(@FormParam("ssa") String ssa, @FormParam("privateKey") String privateKey) throws JOSEException, java.text.ParseException, IOException {

        String responseString = registrationService.sendRegistrationRequest(ssa, privateKey);

        return Response.ok(responseString).build();
    }

    @GET
    @Path("/resetClientID")
    public void clientReset() {
        redisService.delete("CLIENT_ID");
    }

}
