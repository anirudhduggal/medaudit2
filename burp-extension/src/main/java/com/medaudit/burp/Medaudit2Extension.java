package com.medaudit.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Medaudit2 Burp Suite Extension
 *
 * Forwards HTTP requests from Burp Proxy/Repeater to the Medaudit
 * HTTP-to-MLLP converter, which translates them into HL7 messages
 * and sends them to the target medical device.
 */
public class Medaudit2Extension implements BurpExtension {

    private MontoyaApi api;
    private Medaudit2ConfigTab configTab;
    private Medaudit2ResponsePanel responsePanel;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Medaudit2");

        this.configTab = new Medaudit2ConfigTab();
        this.responsePanel = new Medaudit2ResponsePanel();

        // Register the config + response UI tab
        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.addTab("Configuration", configTab.getPanel());
        tabbedPane.addTab("Response Log", responsePanel.getPanel());

        api.userInterface().registerSuiteTab("Medaudit2", tabbedPane);

        // Register right-click context menu
        api.userInterface().registerContextMenuItemsProvider(new ContextMenuItemsProvider() {
            @Override
            public List<Component> provideMenuItems(ContextMenuEvent event) {
                List<Component> items = new ArrayList<>();

                JMenuItem menuItem = new JMenuItem("Send to Medaudit2");
                menuItem.addActionListener(e -> handleContextMenu(event));
                items.add(menuItem);

                return items;
            }
        });

        api.logging().logToOutput("Medaudit2 extension loaded successfully");
        api.logging().logToOutput("Configure the Medaudit proxy host/port in the Medaudit2 tab");
    }

    private void handleContextMenu(ContextMenuEvent event) {
        // Try selectedRequestResponses first (works for Proxy history, Target sitemap)
        List<HttpRequestResponse> selected = event.selectedRequestResponses();
        if (selected != null && !selected.isEmpty()) {
            for (HttpRequestResponse reqRes : selected) {
                if (reqRes.request() != null) {
                    forwardRequest(reqRes.request());
                }
            }
            return;
        }

        // Fall back to messageEditorRequestResponse (works for Repeater, Inspector)
        if (event.messageEditorRequestResponse().isPresent()) {
            HttpRequest req = event.messageEditorRequestResponse().get().requestResponse().request();
            if (req != null) {
                forwardRequest(req);
                return;
            }
        }

        api.logging().logToOutput("[Medaudit2] No request found in selection");
        SwingUtilities.invokeLater(() -> {
            responsePanel.addEntry("--", "(no request)", 0, "No HTTP request found in the current selection.");
        });
    }

    /**
     * Forward an HTTP request to the Medaudit HTTP-to-MLLP proxy.
     */
    private void forwardRequest(HttpRequest request) {
        final String host = configTab.getProxyHost();
        final int port = configTab.getProxyPort();

        api.logging().logToOutput("[Medaudit2] Forwarding request to " + host + ":" + port);

        new Thread(() -> {
            try {
                // Extract the request body using bodyToString()
                String requestBody = request.bodyToString();

                // If body is empty (e.g. GET request), send the full HTTP request
                if (requestBody == null || requestBody.trim().isEmpty()) {
                    requestBody = request.toByteArray().toString();
                }

                // Final safety check
                if (requestBody == null || requestBody.trim().isEmpty()) {
                    requestBody = request.url() + "\n" + request.httpVersion();
                }

                final String body = requestBody;
                api.logging().logToOutput("[Medaudit2] Sending " + body.length() + " bytes");

                Medaudit2HttpClient.Response response = Medaudit2HttpClient.post(host, port, body);

                api.logging().logToOutput("[Medaudit2] Response: HTTP " + response.statusCode);

                SwingUtilities.invokeLater(() -> {
                    responsePanel.addEntry(host + ":" + port, body, response.statusCode, response.body);
                });

            } catch (Exception ex) {
                final String error = "Connection error: " + ex.getClass().getSimpleName() + " - " + ex.getMessage();
                api.logging().logToError("[Medaudit2] " + error);

                SwingUtilities.invokeLater(() -> {
                    responsePanel.addEntry(host + ":" + port, "(failed)", 0, error);
                });
            }
        }).start();
    }
}
