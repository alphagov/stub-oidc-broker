package uk.gov.ida.stuboidcbroker.resources.oidcclient;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;
import uk.gov.ida.stuboidcbroker.rest.Urls;
import uk.gov.ida.stuboidcbroker.services.oidcclient.AuthnRequestGeneratorService;

import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import java.net.URI;
import java.util.Arrays;
import java.util.List;

@Path("/formPost")
public class AuthorizationRequestClientResource {

    private final AuthnRequestGeneratorService authnRequestGeneratorService;

    public AuthorizationRequestClientResource(
            AuthnRequestGeneratorService authnRequestGeneratorService) {
        this.authnRequestGeneratorService = authnRequestGeneratorService;
    }

    @POST
    @Path("/serviceAuthenticationRequest")
    @Produces(MediaType.APPLICATION_JSON)
    public Response formPostAuthenticationRequest
            (@FormParam("brokerDomain") String domain,
             @FormParam("transactionID") String transactionID,
             @FormParam("redirectURI") String redirectURI) {

        URI redirectUri = URI.create(redirectURI);
        List<String> orgList = Arrays.asList(domain.split(","));
        String brokerDomain = orgList.get(0);
        String brokerName = orgList.get(1);
        authnRequestGeneratorService.storeBrokerNameAndDomain(transactionID, brokerName, brokerDomain);
        URI authorisationURI = UriBuilder.fromUri(brokerDomain).path(Urls.StubBrokerOPProvider.AUTHORISATION_ENDPOINT_FORM_URI).build();

        return Response
                .status(302)
                .location(authnRequestGeneratorService.generateAuthenticationRequest(
                        authorisationURI,
                        authnRequestGeneratorService.getClientIDByBrokerName(brokerName),
                        redirectUri,
                        new ResponseType(ResponseType.Value.CODE, OIDCResponseTypeValue.ID_TOKEN, ResponseType.Value.TOKEN),
                        transactionID)
                        .toURI())
                .build();
    }
}
