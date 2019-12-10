package uk.gov.ida.stuboidcbroker.resources.picker;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.dropwizard.views.View;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;
import uk.gov.ida.stuboidcbroker.configuration.StubOidcBrokerConfiguration;
import uk.gov.ida.stuboidcbroker.domain.Organisation;
import uk.gov.ida.stuboidcbroker.rest.Urls;
import uk.gov.ida.stuboidcbroker.services.RedisService;
import uk.gov.ida.stuboidcbroker.views.PickerView;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
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
public class StubOidcBrokerPickerResource {
    private final StubOidcBrokerConfiguration configuration;
    private final RedisService redisService;

    public StubOidcBrokerPickerResource(StubOidcBrokerConfiguration configuration, RedisService redisService) {
        this.configuration = configuration;
        this.redisService = redisService;
    }

    @GET
    @Path("/picker")
    public View pickerPage() throws IOException {
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

        return new PickerView(idps, registeredBrokers);
    }

    private List<Organisation> getOrganisationsFromResponse(HttpResponse<String> responseBody) throws IOException {
        JSONParser parser = new JSONParser(JSONParser.MODE_JSON_SIMPLE);
        JSONArray jsonarray;
        try {
            jsonarray = (JSONArray) parser.parse(responseBody.body());
        } catch (ParseException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }

        List<Organisation> orgList = new ArrayList<>();
        for(int i = 0; i < jsonarray.size(); i++) {
            JSONObject obj = (JSONObject) jsonarray.get(i);
            ObjectMapper objectMapper = new ObjectMapper();
            Organisation org = objectMapper.readValue(obj.toJSONString(), Organisation.class);
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
}
