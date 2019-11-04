package uk.gov.ida.stuboidcclient;

import io.dropwizard.Application;
import io.dropwizard.configuration.EnvironmentVariableSubstitutor;
import io.dropwizard.configuration.SubstitutingSourceProvider;
import io.dropwizard.jersey.jackson.JsonProcessingExceptionMapper;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import io.dropwizard.views.ViewBundle;
import uk.gov.ida.stuboidcclient.configuration.StubOidcClientConfiguration;
import uk.gov.ida.stuboidcclient.resources.StubOidcClientFormPostResource;
import uk.gov.ida.stuboidcclient.resources.StubOidcClientRegistationResource;
import uk.gov.ida.stuboidcclient.resources.StubOidcClientResource;
import uk.gov.ida.stuboidcclient.services.AuthnRequestService;
import uk.gov.ida.stuboidcclient.services.AuthnResponseService;
import uk.gov.ida.stuboidcclient.services.RegistationService;
import uk.gov.ida.stuboidcclient.services.TokenService;
import uk.gov.ida.stuboidcclient.services.RedisService;

public class StubOidcClientApplication extends Application<StubOidcClientConfiguration> {

    public static void main(String[] args) throws Exception {
        new StubOidcClientApplication().run(args);
    }

    @Override
    public void run(StubOidcClientConfiguration configuration, Environment environment) {
        RedisService redisService = new RedisService(configuration);

        TokenService tokenService = new TokenService(configuration, redisService);
        AuthnRequestService authnRequestService = new AuthnRequestService(redisService);
        AuthnResponseService authResponseService = new AuthnResponseService(tokenService);

        environment.jersey().register(new StubOidcClientResource(configuration, tokenService, authnRequestService, authResponseService));
        environment.jersey().register(new StubOidcClientFormPostResource(configuration, tokenService, authnRequestService, authResponseService));
        environment.jersey().register(new JsonProcessingExceptionMapper(true));
        environment.jersey().register(new StubOidcClientRegistationResource(new RegistationService()));
    }

    @Override
    public void initialize(final Bootstrap<StubOidcClientConfiguration> bootstrap) {
        bootstrap.addBundle(new ViewBundle<>());
        bootstrap.setConfigurationSourceProvider(
                new SubstitutingSourceProvider(
                        bootstrap.getConfigurationSourceProvider(),
                        new EnvironmentVariableSubstitutor(false)));
    }

}
