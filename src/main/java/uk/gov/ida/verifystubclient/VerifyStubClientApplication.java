package uk.gov.ida.verifystubclient;

import io.dropwizard.Application;
import io.dropwizard.setup.Environment;
import uk.gov.ida.verifystubclient.configuration.VerifyStubClientConfiguration;
import uk.gov.ida.verifystubclient.resources.AuthenticationRequestResource;
import uk.gov.ida.verifystubclient.services.ClientService;

public class VerifyStubClientApplication extends Application<VerifyStubClientConfiguration> {

    public static void main(String[] args) throws Exception {
        new VerifyStubClientApplication().run(args);
    }

    @Override
    public void run(VerifyStubClientConfiguration configuration, Environment environment) {
        environment.jersey().register(new AuthenticationRequestResource(configuration, new ClientService(configuration)));
    }
}
