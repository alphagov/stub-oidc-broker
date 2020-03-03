package uk.gov.ida.stuboidcbroker.services.shared;

import com.nimbusds.jose.util.JSONObjectUtils;
import net.minidev.json.JSONObject;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import uk.gov.ida.stuboidcbroker.configuration.StubOidcBrokerConfiguration;

import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;

public class PKIService {

    private final StubOidcBrokerConfiguration configuration;

    public PKIService(StubOidcBrokerConfiguration configuration) {
        this.configuration = configuration;
    }

    //For testing purposes
    public PrivateKey getOrganisationPrivateKey() {
        Security.addProvider(new BouncyCastleProvider());

        URI directoryURI = UriBuilder.fromUri(configuration.getDirectoryURI()).path("keys").path(configuration.getOrgID()).build();
        HttpRequest request = HttpRequest.newBuilder()
                .GET()
                .uri(directoryURI)
                .build();

        JSONObject jsonResponse;

        try {
            HttpResponse<String> httpResponse = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
            jsonResponse = JSONObjectUtils.parse(httpResponse.body());
        } catch (IOException | InterruptedException | java.text.ParseException e) {
            throw new RuntimeException(e);
        }

        String responseString = jsonResponse.get("signing").toString();
        responseString = responseString.replaceAll("\\n", "").replace("-----BEGIN RSA PRIVATE KEY-----", "").replace("-----END RSA PRIVATE KEY-----", "").replaceAll("\\s+", "");
        String anotherString = "-----BEGIN RSA PRIVATE KEY-----\n" + responseString + "\n-----END RSA PRIVATE KEY-----";
        PEMParser pemParser = new PEMParser(new StringReader(anotherString));
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        KeyPair kp;

        try {
            Object object = pemParser.readObject();
            kp = converter.getKeyPair((PEMKeyPair) object);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        return kp.getPrivate();
    }

    public PrivateKey convertStringToPrivateKey(String privateKeyString) {
        Security.addProvider(new BouncyCastleProvider());

        privateKeyString = privateKeyString.replaceAll("\\n", "").replace("-----BEGIN RSA PRIVATE KEY-----", "").replace("-----END RSA PRIVATE KEY-----", "");
        String someString = privateKeyString.replaceAll("\\s+", "");

        String anotherString = "-----BEGIN RSA PRIVATE KEY-----\n" + someString + "\n-----END RSA PRIVATE KEY-----";

        PEMParser pemParser = new PEMParser(new StringReader(anotherString));
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        KeyPair kp;
        try {
            Object object = pemParser.readObject();
            kp = converter.getKeyPair((PEMKeyPair) object);
        } catch (IOException e) {
           throw new RuntimeException(e);
        }

        return kp.getPrivate();
    }
}
