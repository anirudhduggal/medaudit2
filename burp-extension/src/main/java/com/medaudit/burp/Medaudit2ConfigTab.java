package com.medaudit.burp;

import javax.swing.*;
import java.awt.*;

/**
 * Configuration tab for the Medaudit2 extension.
 * Allows setting the Medaudit HTTP proxy host and port.
 */
public class Medaudit2ConfigTab {

    private final JPanel panel;
    private final JTextField hostField;
    private final JTextField portField;
    private final JLabel statusLabel;

    public Medaudit2ConfigTab() {
        panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(8, 8, 8, 8);
        gbc.anchor = GridBagConstraints.WEST;

        // Title
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 2;
        JLabel title = new JLabel("Medaudit2 - HTTP to HL7 Proxy Configuration");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 16f));
        panel.add(title, gbc);

        // Description
        gbc.gridy = 1;
        JLabel desc = new JLabel(
            "<html>Configure the Medaudit HTTP-to-MLLP proxy address.<br>" +
            "Right-click any request in Proxy/Repeater and select <b>\"Send to Medaudit2\"</b><br>" +
            "to forward it to your medical device via HL7/MLLP.</html>"
        );
        desc.setFont(desc.getFont().deriveFont(Font.PLAIN, 12f));
        panel.add(desc, gbc);

        // Separator
        gbc.gridy = 2; gbc.fill = GridBagConstraints.HORIZONTAL;
        panel.add(new JSeparator(), gbc);
        gbc.fill = GridBagConstraints.NONE;

        // Host label
        gbc.gridy = 3; gbc.gridwidth = 1; gbc.gridx = 0;
        panel.add(new JLabel("Medaudit Proxy Host:"), gbc);

        // Host field
        gbc.gridx = 1;
        hostField = new JTextField("localhost", 20);
        panel.add(hostField, gbc);

        // Port label
        gbc.gridy = 4; gbc.gridx = 0;
        panel.add(new JLabel("Medaudit Proxy Port:"), gbc);

        // Port field
        gbc.gridx = 1;
        portField = new JTextField("8080", 20);
        panel.add(portField, gbc);

        // Test button
        gbc.gridy = 5; gbc.gridx = 0; gbc.gridwidth = 2;
        gbc.anchor = GridBagConstraints.CENTER;
        JButton testBtn = new JButton("Test Connection");
        testBtn.addActionListener(e -> testConnection());
        panel.add(testBtn, gbc);

        // Status
        gbc.gridy = 6;
        statusLabel = new JLabel(" ");
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.ITALIC, 12f));
        panel.add(statusLabel, gbc);

        // Spacer to push everything to top
        gbc.gridy = 7; gbc.weighty = 1.0; gbc.fill = GridBagConstraints.VERTICAL;
        panel.add(Box.createVerticalGlue(), gbc);
    }

    public JPanel getPanel() {
        return panel;
    }

    public String getProxyHost() {
        String host = hostField.getText().trim();
        return host.isEmpty() ? "localhost" : host;
    }

    public int getProxyPort() {
        try {
            return Integer.parseInt(portField.getText().trim());
        } catch (NumberFormatException e) {
            return 8080;
        }
    }

    private void testConnection() {
        statusLabel.setText("Testing...");
        statusLabel.setForeground(Color.GRAY);

        new Thread(() -> {
            try {
                Medaudit2HttpClient.Response resp = Medaudit2HttpClient.post(
                    getProxyHost(), getProxyPort(), "MSH|^~\\&|TEST|TEST|TEST|TEST|||ACK|TEST|P|2.5"
                );

                SwingUtilities.invokeLater(() -> {
                    if (resp.statusCode > 0) {
                        statusLabel.setText("Connected (HTTP " + resp.statusCode + ")");
                        statusLabel.setForeground(new Color(0, 128, 0));
                    } else {
                        statusLabel.setText("Connection failed");
                        statusLabel.setForeground(Color.RED);
                    }
                });
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    statusLabel.setText("Error: " + ex.getMessage());
                    statusLabel.setForeground(Color.RED);
                });
            }
        }).start();
    }
}
