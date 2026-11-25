import com.github.scribejava.core.builder.api.DefaultApi20;
import com.github.scribejava.core.httpclient.HttpClient;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.oauth.OAuth20Service;
import java.io.IOException;
import java.lang.reflect.Proxy;
import java.net.URI;
import java.time.LocalDate;
import java.time.ZoneOffset;

public final class ScribeProbe {
    private static final String KEY = "WT_FAKE_KEY_123456";
    private static final String SECRET = "WT_FAKE_SECRET_123456";

    public static void main(String[] args) throws Exception {
        HttpClient client = (HttpClient) Proxy.newProxyInstance(
                HttpClient.class.getClassLoader(), new Class<?>[] {HttpClient.class},
                (proxy, method, values) -> {
                    if (method.getName().startsWith("execute")) {
                        String url = (String) values[3];
                        String payload = values[4] instanceof String ? (String) values[4]
                                : values[4] instanceof byte[]
                                ? new String((byte[]) values[4], java.nio.charset.StandardCharsets.UTF_8) : "";
                        String host = URI.create(url).getHost();
                        System.out.println("WT_REQUEST\t" + host + "\t" + values[2]
                                + "\tcanary=" + (payload.contains(KEY) && payload.contains(SECRET)));
                        throw new IOException("WakeTrace blocked request");
                    }
                    return null;
                });
        DefaultApi20 api = new DefaultApi20() {
            public String getAccessTokenEndpoint() { return "https://example.invalid/token"; }
            protected String getAuthorizationBaseUrl() { return "https://example.invalid/auth"; }
        };
        OAuth20Service service = new OAuth20Service(api, KEY, SECRET, "urn:wt", null,
                "code", null, "WakeTrace", null, client);
        try {
            service.signRequest("WT_FAKE_TOKEN", new OAuthRequest(Verb.GET, "https://example.invalid/probe"));
        } finally {
            service.close();
        }
        System.out.println("WT_DONE\t" + LocalDate.now(ZoneOffset.UTC));
    }
}
