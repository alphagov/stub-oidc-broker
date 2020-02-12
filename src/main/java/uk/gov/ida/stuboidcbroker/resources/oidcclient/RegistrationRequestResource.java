package uk.gov.ida.stuboidcbroker.resources.oidcclient;

import io.dropwizard.views.View;
import uk.gov.ida.stuboidcbroker.configuration.StubOidcBrokerConfiguration;
import uk.gov.ida.stuboidcbroker.domain.Organisation;
import uk.gov.ida.stuboidcbroker.rest.Urls;
import uk.gov.ida.stuboidcbroker.services.shared.RedisService;
import uk.gov.ida.stuboidcbroker.services.oidcclient.RegistrationRequestService;
import uk.gov.ida.stuboidcbroker.views.RegistrationView;

import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import java.net.URI;
import java.net.http.HttpResponse;
import java.util.Arrays;
import java.util.List;

@Path("/")
public class RegistrationRequestResource {

    private final RegistrationRequestService registrationRequestService;
    private final RedisService redisService;
    private final StubOidcBrokerConfiguration configuration;

    public RegistrationRequestResource(RegistrationRequestService registrationRequestService, RedisService redisService, StubOidcBrokerConfiguration configuration) {
        this.registrationRequestService = registrationRequestService;
        this.redisService = redisService;
        this.configuration = configuration;
    }

    @GET
    @Path("/")
    public View registrationPage() {
        String scheme = configuration.getScheme();
        URI brokerRequestURI = UriBuilder.fromUri(configuration.getDirectoryURI()).path(Urls.Directory.REGISTERED_BROKERS + scheme)
                .build();

        HttpResponse<String> registeredBrokers = registrationRequestService.getRegisteredBrokersFromDirectory(brokerRequestURI);
        List<Organisation> listOfRegisteredBrokers = registrationRequestService.getListOfBrokersFromResponse(registeredBrokers);

        return new RegistrationView(listOfRegisteredBrokers);
    }

    @POST
    @Path("/sendRegistrationRequest")
    @Produces(MediaType.APPLICATION_JSON)
    public Response sendRegistrationRequest(
            @FormParam("ssa") String ssa,
            @FormParam("privateKey") String privateKey,
            @FormParam("brokerDomain") String brokerDomain,
            @FormParam("clientToken") String clientToken) {
        // get ssa for this broker from directory
        // get private key for this broker directory
        List<String> orgList = Arrays.asList(brokerDomain.split(","));
        String domain = orgList.get(0).trim();
        String brokerName = orgList.get(1).trim();
        String responseString = registrationRequestService.sendRegistrationRequest(ssa, privateKey, domain, brokerName, clientToken);

        return Response.ok(responseString).build();
    }

    @GET
    @Path("/resetClientID")
    public void resetClientID() {
        redisService.delete("CLIENT_ID");
    }

}
