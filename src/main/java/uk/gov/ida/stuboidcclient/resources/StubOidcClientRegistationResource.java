package uk.gov.ida.stuboidcclient.resources;

import com.nimbusds.jose.JOSEException;
import uk.gov.ida.stuboidcclient.services.RedisService;
import uk.gov.ida.stuboidcclient.services.RegistationService;

import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;

@Path("/")
public class StubOidcClientRegistationResource {

    private final RegistationService registationService;
    private final RedisService redisService;

    public StubOidcClientRegistationResource(RegistationService registationService, RedisService redisService) {
        this.registationService = registationService;
        this.redisService = redisService;
    }

    @POST
    @Path("/sendRegistrationRequest")
    @Produces(MediaType.APPLICATION_JSON)
    public Response sendRegistationRequest(@FormParam("ssa") String ssa, @FormParam("privateKey") String privateKey) throws JOSEException, java.text.ParseException, IOException {

        String responseString = registationService.sendRegistationRequest(ssa, privateKey);

        return Response.ok(responseString).build();
    }

    @GET
    @Path("/resetClientID")
    public void clientReset() {
        redisService.delete("CLIENT_ID");
    }


    private void parseSSA() {
        //Seperate the claim and the header by searching for the dot
        //Base64 decode the header and base64 decode the claims
    }
}
