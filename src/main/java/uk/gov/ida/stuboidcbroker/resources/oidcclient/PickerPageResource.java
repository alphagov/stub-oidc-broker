package uk.gov.ida.stuboidcbroker.resources.oidcclient;

import com.nimbusds.oauth2.sdk.id.ClientID;
import io.dropwizard.views.View;
import uk.gov.ida.stuboidcbroker.configuration.StubOidcBrokerConfiguration;
import uk.gov.ida.stuboidcbroker.domain.Organisation;
import uk.gov.ida.stuboidcbroker.rest.Urls;
import uk.gov.ida.stuboidcbroker.services.shared.PickerService;
import uk.gov.ida.stuboidcbroker.services.shared.RedisService;
import uk.gov.ida.stuboidcbroker.views.PickerView;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.UriBuilder;
import java.net.URI;
import java.util.List;
import java.util.stream.Collectors;

@Path("/")
public class PickerPageResource {
    private final StubOidcBrokerConfiguration configuration;
    private final RedisService redisService;
    private final PickerService pickerService;

    public PickerPageResource(StubOidcBrokerConfiguration configuration, RedisService redisService, PickerService pickerService) {
        this.configuration = configuration;
        this.redisService = redisService;
        this.pickerService = pickerService;
    }

    @GET
    @Path("/picker")
    public View pickerPage(@QueryParam("response-uri") String rpURI) {

        String transactionId = new ClientID().toString();
        URI rpResponseURI = UriBuilder.fromUri(rpURI).build();
        storeRpResponseUri(transactionId + "response-uri", rpResponseURI.toString());
        String scheme = configuration.getScheme();

        URI idpRequestURI = UriBuilder.fromUri(configuration.getDirectoryURI()).path(Urls.Directory.REGISTERED_IDPS + scheme)
                .build();
        URI brokerRequestURI = UriBuilder.fromUri(configuration.getDirectoryURI()).path(Urls.Directory.REGISTERED_BROKERS + scheme)
                .build();

        List<Organisation> idps = pickerService.getOrganisationsFromDirectory(idpRequestURI);
        List<Organisation> brokers = pickerService.getOrganisationsFromDirectory(brokerRequestURI);

        List<Organisation> registeredBrokers = brokers.stream()
                .filter(org -> redisService.get(org.getName()) != null)
                .collect(Collectors.toList());

        String redirectUri = UriBuilder.fromUri(configuration.getStubBrokerURI())
                .path(Urls.StubBrokerClient.REDIRECT_FOR_SERVICE_URI)
                .build().toString();


        return new PickerView(idps, registeredBrokers,
                transactionId, configuration.getBranding(),
                scheme, configuration.getDirectoryURI(),
                redirectUri);
    }

    private void storeRpResponseUri(String transactionID, String rpResponsePath) {
        redisService.set(transactionID, rpResponsePath);
    }
}
