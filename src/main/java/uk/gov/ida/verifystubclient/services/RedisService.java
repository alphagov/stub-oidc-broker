package uk.gov.ida.verifystubclient.services;

import io.lettuce.core.RedisClient;
import io.lettuce.core.api.sync.RedisCommands;
import uk.gov.ida.verifystubclient.configuration.VerifyStubClientConfiguration;

public class RedisService {

    private RedisCommands<String, String> commands;

    public RedisService(VerifyStubClientConfiguration config) {
        startup(config);
    }

    public void startup(VerifyStubClientConfiguration config) {
        RedisClient client = RedisClient.create("redis://" + config.getRedisURI());
        commands = client.connect().sync();
    }

    public void set(String key, String value) {
        commands.set(key, value);
    }

    public String get(String key) {
        return commands.get(key);
    }

    public Long incr(String key) {
        return commands.incr(key);
    }
}
