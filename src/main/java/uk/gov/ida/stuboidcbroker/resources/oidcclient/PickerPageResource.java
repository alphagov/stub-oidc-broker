package uk.gov.ida.stuboidcbroker.resources.oidcclient;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.id.ClientID;
import io.dropwizard.views.View;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.ida.stuboidcbroker.configuration.StubOidcBrokerConfiguration;
import uk.gov.ida.stuboidcbroker.domain.Organisation;
import uk.gov.ida.stuboidcbroker.rest.Urls;
import uk.gov.ida.stuboidcbroker.services.shared.RedisService;
import uk.gov.ida.stuboidcbroker.views.PickerView;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Path("/")
public class PickerPageResource {
    private final StubOidcBrokerConfiguration configuration;
    private final RedisService redisService;

    private static final Logger LOG = LoggerFactory.getLogger(PickerPageResource.class);


    public PickerPageResource(StubOidcBrokerConfiguration configuration, RedisService redisService) {
        this.configuration = configuration;
        this.redisService = redisService;
    }

    @GET
    @Path("/picker")
    public View pickerPage(@QueryParam("response-uri") String rpURI) throws IOException {

        String transactionId = new ClientID().toString();

        URI uri = UriBuilder.fromUri(rpURI).build();

        storeTransactionID(transactionId + "response-uri", uri.toString());

        String scheme = configuration.getScheme();
        URI idpRequestURI = UriBuilder.fromUri(configuration.getDirectoryURI()).path(Urls.Directory.REGISTERED_IDPS + scheme)
                .build();
        URI brokerRequestURI = UriBuilder.fromUri(configuration.getDirectoryURI()).path(Urls.Directory.REGISTERED_BROKERS + scheme)
                .build();

        HttpResponse<String> idpsResponse = getOrganisations(idpRequestURI);
        HttpResponse<String> brokersResponse = getOrganisations(brokerRequestURI);

        List<Organisation> idps = getOrganisationsFromResponse(idpsResponse);
        List<Organisation> brokers = getOrganisationsFromResponse(brokersResponse);
        List<Organisation> registeredBrokers = brokers.stream()
                .filter(org -> redisService.get(org.getName()) != null)
                .collect(Collectors.toList());

        String redirectUri = UriBuilder.fromUri(configuration.getStubBrokerURI())
                .path(Urls.StubBrokerClient.REDIRECT_FOR_SERVICE_URI)
                .build().toString();

        return new PickerView(idps, registeredBrokers, transactionId, configuration.getBranding(), configuration.getScheme(), configuration.getDirectoryURI(), redirectUri);
    }

    private List<Organisation> getOrganisationsFromResponse(HttpResponse<String> responseBody) throws IOException {
        JSONParser parser = new JSONParser(JSONParser.MODE_JSON_SIMPLE);
        JSONArray jsonarray;
        try {
            jsonarray = (JSONArray) parser.parse(responseBody.body());
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }

        List<Organisation> orgList = new ArrayList<>();

        for (Object obj : jsonarray) {
            JSONObject jsonObj = (JSONObject) obj;
            ObjectMapper objectMapper = new ObjectMapper();
            Organisation org = objectMapper.readValue(jsonObj.toJSONString(), Organisation.class);
            orgList.add(org);
        }
        return orgList;
    }

    private HttpResponse<String> getOrganisations(URI uri) {
        HttpRequest request = HttpRequest.newBuilder()
                .GET()
                .uri(uri)
                .build();

        try {
            return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    private void storeTransactionID(String transactionID, String rpResponsePath) {

        redisService.set(transactionID, rpResponsePath);
    }
}
