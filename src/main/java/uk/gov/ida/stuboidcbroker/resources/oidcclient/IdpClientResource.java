package uk.gov.ida.stuboidcbroker.resources.oidcclient;

import uk.gov.ida.stuboidcbroker.configuration.StubOidcBrokerConfiguration;
import uk.gov.ida.stuboidcbroker.rest.Urls;
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
public class IdpClientResource {

    private final RedisService redisService;
    private final StubOidcBrokerConfiguration configuration;

    public IdpClientResource(RedisService redisService, StubOidcBrokerConfiguration configuration) {
        this.redisService = redisService;
        this.configuration = configuration;
    }

    @POST
    @Path("/idpAuthenticationRequest")
    @Produces(MediaType.APPLICATION_JSON)
    public Response sendIdpAuthenticationRequest(@FormParam("idpDomain") String domain, @FormParam("transactionID") String transactionID) {
        List<String> orgList = Arrays.asList(domain.split(","));
        String idpDomain = orgList.get(0);
        String idpName = orgList.get(1);

        URI idpUri = UriBuilder.fromUri(idpDomain).path(Urls.IDP.AUTHENTICATION_URI)
                .queryParam("transaction-id", transactionID)
                .queryParam("redirect-path", Urls.StubBrokerClient.RESPONSE_FOR_BROKER)
                .build();

        return Response
                .status(302)
                .location(idpUri)
                .build();
    }
}
