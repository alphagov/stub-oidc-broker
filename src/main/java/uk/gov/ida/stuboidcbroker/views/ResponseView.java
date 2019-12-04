package uk.gov.ida.stuboidcbroker.views;

import io.dropwizard.views.View;
import org.apache.http.HttpStatus;

import java.net.URI;

public class ResponseView extends View {

    private final URI responseURI;
    private final String jsonResponse;
    private final String httpStatus;

    public ResponseView(URI responseURI, String jsonResponse, String httpStatus) {
        super("response.mustache");
        this.responseURI = responseURI;
        this.jsonResponse = jsonResponse;
        this.httpStatus = httpStatus;
    }

    public URI getResponseURI() {
        return responseURI;
    }

    public String getJsonResponse() {
        return jsonResponse;
    }

    public String getHttpStatus() {
        return httpStatus;
    }
}
