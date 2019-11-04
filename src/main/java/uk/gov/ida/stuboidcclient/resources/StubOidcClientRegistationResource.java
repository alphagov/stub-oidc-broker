package uk.gov.ida.stuboidcclient.resources;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.ParseException;
import uk.gov.ida.stuboidcclient.services.RegistationService;

import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

@Path("/")
public class StubOidcClientRegistationResource {

    private final RegistationService registationService;

    public StubOidcClientRegistationResource(RegistationService registationService) {
        this.registationService = registationService;
    }

    @POST
    @Path("/sendRegistrationRequest")
    @Produces(MediaType.APPLICATION_JSON)
    public Response sendRegistationRequest(@FormParam("ssa") String ssa, @FormParam("privateKey") String privateKey) throws JOSEException, ParseException {
        //Create JWT

        String responseString = registationService.sendRegistationRequest(ssa, privateKey);


        return Response.ok(responseString).build();
    }

    private void parseSSA() {
        //Seperate the claim and the header by searching for the dot
        //Base64 decode the header and base64 decode the claims
    }
}
