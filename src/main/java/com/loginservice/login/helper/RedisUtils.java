package com.loginservice.login.helper;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import redis.clients.jedis.Jedis;

public class RedisUtils {

    private static final Logger logger = LogManager.getLogger(RedisUtils.class);

    Jedis jedis;

    public RedisUtils (String redisHost, String redisPort) {
        jedis = new Jedis(redisHost, Integer.parseInt(redisPort));
    }

    public void addUserToken(String email, String authToken) {
        try {
            if (jedis != null) {
                jedis.set(email, authToken);
                jedis.set(authToken, email);

                jedis.expire(email,120);
                jedis.expire(authToken,120);
            }
        } catch (Exception e) {
            // TODO
        }

    }

    public String getValue (String key) {
        String value = "";

        if(jedis!=null) {
            value = jedis.get(key);
        }

        return value;
    }

    public boolean keyExists (String key) {

        boolean isKey = false;

        if(jedis!=null) {
                isKey = jedis.exists(key);
        }
        return isKey;
    }

    public long authTtl(String key) {
        long ttl = 0;
        if(keyExists (key)) {
           ttl = jedis.ttl(key);
        }
        return ttl;
    }

    public void delete (String key) {
        if(keyExists(key)) {
            jedis.del(key);
        }
    }

}
