package uk.gov.ida.stuboidcbroker.services.shared;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

public class QueryParameterHelper {

    private static final Logger LOG = LoggerFactory.getLogger(QueryParameterHelper.class);

    public static Map<String, String> splitQuery(String query) {
        try {
            Map<String, String> query_pairs = new LinkedHashMap<>();
            String[] pairs = query.split("&");
            for (String pair : pairs) {
                int idx = pair.indexOf("=");
                query_pairs.put(URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8), URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8));
            }
            return query_pairs;
        } catch (RuntimeException e) {
            LOG.warn("Query string passed to splitQuery: " + query);
            LOG.error(e.getMessage());
            throw e;
        }
    }
}
