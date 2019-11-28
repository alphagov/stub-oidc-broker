package uk.gov.ida.stuboidcbroker.resources;

import io.dropwizard.views.View;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.ida.stuboidcbroker.configuration.StubOidcBrokerConfiguration;
import uk.gov.ida.stuboidcbroker.rest.Urls;
import uk.gov.ida.stuboidcbroker.views.PickerView;

import javax.ws.rs.*;
import javax.ws.rs.core.*;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;

@Path("/")
public class StubOidcBrokerPickerResource {
    private static final Logger LOG = LoggerFactory.getLogger(StubOidcBrokerPickerResource.class);
    private final StubOidcBrokerConfiguration configuration;

    public StubOidcBrokerPickerResource(StubOidcBrokerConfiguration configuration) {
        this.configuration = configuration;
    }

    @GET
    @Path("/picker")
    public View pickerPage() throws URISyntaxException, IOException {
        URI directoryRequestURI = UriBuilder.fromUri(
                configuration.getDirectoryURI()).path(Urls.Directory.REGISTERED_IDPS)
                .build();

        HttpRequest request = HttpRequest.newBuilder()
                .GET()
                .uri(directoryRequestURI)
                .build();

        HttpResponse<String> responseBody;
        try {
            responseBody = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }

        JSONParser parser = new JSONParser();
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
            Organisation org = new Organisation();
            org.setName(obj.get("name").toString());
            org.setDomain(obj.get("domain").toString());
            org.setType(obj.get("type").toString());
            if(obj.get("loa") != null) {
                org.setLoa(obj.get("loa").toString());
            }
            orgList.add(org);
        }

        return new PickerView(orgList);
    }
}
