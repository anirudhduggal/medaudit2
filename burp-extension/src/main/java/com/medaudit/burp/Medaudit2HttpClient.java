package com.medaudit.burp;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/**
 * Simple HTTP client for forwarding requests to the Medaudit proxy.
 * Uses only standard library classes (no external dependencies).
 */
public class Medaudit2HttpClient {

    public static class Response {
        public final int statusCode;
        public final String body;

        public Response(int statusCode, String body) {
            this.statusCode = statusCode;
            this.body = body;
        }
    }

    /**
     * Send a POST request to the Medaudit HTTP-to-MLLP proxy.
     *
     * @param host Proxy host
     * @param port Proxy port
     * @param body Request body (HL7 message or raw HTTP content)
     * @return Response with status code and body
     */
    public static Response post(String host, int port, String body) throws IOException {
        URL url = new URL("http://" + host + ":" + port + "/");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();

        try {
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(30000);
            conn.setRequestProperty("Content-Type", "text/plain; charset=utf-8");
            conn.setRequestProperty("User-Agent", "Medaudit2-BurpExtension/1.0");

            // Write body
            byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
            conn.setFixedLengthStreamingMode(bodyBytes.length);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(bodyBytes);
                os.flush();
            }

            // Read response
            int statusCode = conn.getResponseCode();
            String responseBody;

            InputStream is = (statusCode >= 400) ? conn.getErrorStream() : conn.getInputStream();
            if (is != null) {
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        sb.append(line).append("\n");
                    }
                    responseBody = sb.toString().trim();
                }
            } else {
                responseBody = "";
            }

            return new Response(statusCode, responseBody);

        } finally {
            conn.disconnect();
        }
    }
}
