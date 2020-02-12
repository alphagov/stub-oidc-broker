package uk.gov.ida.stuboidcbroker.services.shared;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import net.minidev.json.parser.ParseException;
import uk.gov.ida.stuboidcbroker.domain.Organisation;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.stream.Collectors;

public class PickerService {

    public List<Organisation> getOrganisationsFromDirectory(URI uri) {

        HttpResponse<String> organisations = getOrganisations(uri);
        JSONParser parser = new JSONParser(JSONParser.MODE_JSON_SIMPLE);
        JSONArray jsonarray;
        try {
            jsonarray = (JSONArray) parser.parse(organisations.body());
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }

        List<Organisation> orgList = jsonarray
                .stream()
                .map(this::createOrganisationObject)
                .collect(Collectors.toList());

        return orgList;
    }

    private Organisation createOrganisationObject(Object obj) {
        JSONObject jsonObj = (JSONObject) obj;
        ObjectMapper objectMapper = new ObjectMapper();
        Organisation org;
        try {
            org = objectMapper.readValue(jsonObj.toJSONString(), Organisation.class);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return org;
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
