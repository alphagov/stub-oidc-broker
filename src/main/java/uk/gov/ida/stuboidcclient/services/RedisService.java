package uk.gov.ida.stuboidcclient.services;

import io.lettuce.core.RedisClient;
import io.lettuce.core.api.sync.RedisCommands;
import uk.gov.ida.stuboidcclient.configuration.StubOidcClientConfiguration;

public class RedisService {

    private RedisCommands<String, String> commands;

    public RedisService(StubOidcClientConfiguration config) {
        startup(config);
    }

    public void startup(StubOidcClientConfiguration config) {
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
