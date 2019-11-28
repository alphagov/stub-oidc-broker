package uk.gov.ida.stuboidcbroker;

import io.dropwizard.Application;
import io.dropwizard.configuration.EnvironmentVariableSubstitutor;
import io.dropwizard.configuration.SubstitutingSourceProvider;
import io.dropwizard.jersey.jackson.JsonProcessingExceptionMapper;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import io.dropwizard.views.ViewBundle;
import uk.gov.ida.stuboidcbroker.configuration.StubOidcBrokerConfiguration;
import uk.gov.ida.stuboidcbroker.resources.StubOidcBrokerFormPostResource;
import uk.gov.ida.stuboidcbroker.resources.StubOidcBrokerPickerResource;
import uk.gov.ida.stuboidcbroker.resources.StubOidcBrokerRegistrationResource;
import uk.gov.ida.stuboidcbroker.resources.StubOidcBrokerResource;
import uk.gov.ida.stuboidcbroker.services.AuthnRequestService;
import uk.gov.ida.stuboidcbroker.services.AuthnResponseService;
import uk.gov.ida.stuboidcbroker.services.RegistrationService;
import uk.gov.ida.stuboidcbroker.services.TokenService;
import uk.gov.ida.stuboidcbroker.services.RedisService;

public class StubOidcBrokerApplication extends Application<StubOidcBrokerConfiguration> {

    public static void main(String[] args) throws Exception {
        new StubOidcBrokerApplication().run(args);
    }

    @Override
    public void run(StubOidcBrokerConfiguration configuration, Environment environment) {
        RedisService redisService = new RedisService(configuration);

        TokenService tokenService = new TokenService(configuration, redisService);
        AuthnRequestService authnRequestService = new AuthnRequestService(redisService);
        AuthnResponseService authResponseService = new AuthnResponseService(tokenService);

        environment.jersey().register(new StubOidcBrokerResource(configuration, tokenService, authnRequestService, authResponseService, redisService));
        environment.jersey().register(new StubOidcBrokerFormPostResource(configuration, tokenService, authnRequestService, authResponseService, redisService));
        environment.jersey().register(new JsonProcessingExceptionMapper(true));
        environment.jersey().register(new StubOidcBrokerRegistrationResource(new RegistrationService(redisService, configuration), redisService));
        environment.jersey().register(new StubOidcBrokerPickerResource(configuration));
    }

    @Override
    public void initialize(final Bootstrap<StubOidcBrokerConfiguration> bootstrap) {
        bootstrap.addBundle(new ViewBundle<>());
        bootstrap.setConfigurationSourceProvider(
                new SubstitutingSourceProvider(
                        bootstrap.getConfigurationSourceProvider(),
                        new EnvironmentVariableSubstitutor(false)));
    }

}
