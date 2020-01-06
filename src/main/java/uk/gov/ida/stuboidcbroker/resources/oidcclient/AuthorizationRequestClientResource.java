package uk.gov.ida.stuboidcbroker.resources.oidcclient;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.OIDCResponseTypeValue;
import uk.gov.ida.stuboidcbroker.configuration.StubOidcBrokerConfiguration;
import uk.gov.ida.stuboidcbroker.rest.Urls;
import uk.gov.ida.stuboidcbroker.services.oidcclient.AuthnRequestGeneratorService;
import uk.gov.ida.stuboidcbroker.services.shared.RedisService;

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
    private final RedisService redisService;
    private URI redirectUri;

    public AuthorizationRequestClientResource(
            StubOidcBrokerConfiguration configuration,
            AuthnRequestGeneratorService authnRequestGeneratorService,
            RedisService redisService) {
        this.authnRequestGeneratorService = authnRequestGeneratorService;
        this.redisService = redisService;
        redirectUri = UriBuilder.fromUri(configuration.getStubBrokerURI()).path(Urls.StubBrokerClient.REDIRECT_FORM_URI).build();
    }

    @POST
    @Path("/serviceAuthenticationRequest")
    @Produces(MediaType.APPLICATION_JSON)
    public Response formPostAuthenticationRequest(@FormParam("brokerDomain") String domain, @FormParam("transactionID") String transactionID) {
        List<String> orgList = Arrays.asList(domain.split(","));
        String brokerDomain = orgList.get(0);
        String brokerName = orgList.get(1);
        storeBrokerNameAndDomain(transactionID, brokerName, brokerDomain);
        URI authorisationURI = UriBuilder.fromUri(brokerDomain).path(Urls.StubBrokerOPProvider.AUTHORISATION_ENDPOINT_FORM_URI).build();
        return Response
                .status(302)
                .location(authnRequestGeneratorService.generateFormPostAuthenticationRequest(
                        authorisationURI,
                        getClientID(brokerName),
                        redirectUri,
                        new ResponseType(ResponseType.Value.CODE, OIDCResponseTypeValue.ID_TOKEN, ResponseType.Value.TOKEN),
                        brokerName,
                        transactionID)
                        .toURI())
                .build();
    }

    private void storeBrokerNameAndDomain(String transactionID, String brokerName, String brokerDomain) {
        redisService.set(transactionID + "-brokername", brokerName);
        redisService.set(transactionID + "-brokerdomain", brokerDomain);
    }

    private ClientID getClientID(String brokerName) {
        String client_id = redisService.get(brokerName);
        if (client_id != null) {
            return new ClientID(client_id);
        }
        return new ClientID();
    }
}
