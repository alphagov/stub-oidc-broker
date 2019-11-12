package uk.gov.ida.stuboidcclient.views;

import io.dropwizard.views.View;
import java.net.URI;

public class ResponseView extends View {

    private final URI responseURI;
    private final String jsonResponse;

    public ResponseView(URI responseURI, String jsonResponse) {
        super("response.mustache");
        this.responseURI = responseURI;
        this.jsonResponse = jsonResponse;
    }

    public URI getResponseURI() {
        return responseURI;
    }

    public String getJsonResponse() {
        return jsonResponse;
    }
}
