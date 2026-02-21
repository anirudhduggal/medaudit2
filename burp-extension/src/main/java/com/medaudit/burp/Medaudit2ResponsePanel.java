package com.medaudit.burp;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;

/**
 * Response log panel showing history of forwarded requests and their HL7 responses.
 */
public class Medaudit2ResponsePanel {

    private final JPanel panel;
    private final DefaultTableModel tableModel;
    private final JTextArea detailArea;

    public Medaudit2ResponsePanel() {
        panel = new JPanel(new BorderLayout());

        // Table for response history
        String[] columns = {"Time", "Target", "Status", "Response Preview"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };

        JTable table = new JTable(tableModel);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.getColumnModel().getColumn(0).setPreferredWidth(80);
        table.getColumnModel().getColumn(1).setPreferredWidth(150);
        table.getColumnModel().getColumn(2).setPreferredWidth(60);
        table.getColumnModel().getColumn(3).setPreferredWidth(400);

        // Detail area for full response
        detailArea = new JTextArea();
        detailArea.setEditable(false);
        detailArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        detailArea.setLineWrap(true);
        detailArea.setWrapStyleWord(true);

        // When a row is selected, show full response in detail area
        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = table.getSelectedRow();
                if (row >= 0 && row < responses.size()) {
                    ResponseEntry entry = responses.get(row);
                    detailArea.setText(
                        "=== REQUEST ===\n" + entry.request +
                        "\n\n=== RESPONSE (HTTP " + entry.statusCode + ") ===\n" + entry.response
                    );
                    detailArea.setCaretPosition(0);
                }
            }
        });

        JSplitPane splitPane = new JSplitPane(
            JSplitPane.VERTICAL_SPLIT,
            new JScrollPane(table),
            new JScrollPane(detailArea)
        );
        splitPane.setResizeWeight(0.4);

        // Header with clear button
        JPanel header = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton clearBtn = new JButton("Clear Log");
        clearBtn.addActionListener(e -> {
            tableModel.setRowCount(0);
            responses.clear();
            detailArea.setText("");
        });
        header.add(clearBtn);

        panel.add(header, BorderLayout.NORTH);
        panel.add(splitPane, BorderLayout.CENTER);
    }

    private final java.util.List<ResponseEntry> responses = new java.util.ArrayList<>();

    public JPanel getPanel() {
        return panel;
    }

    /**
     * Add a response entry to the log.
     */
    public void addEntry(String target, String request, int statusCode, String response) {
        String time = LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
        String preview = response.length() > 100 ? response.substring(0, 100) + "..." : response;

        responses.add(new ResponseEntry(request, statusCode, response));
        tableModel.addRow(new Object[]{time, target, statusCode > 0 ? statusCode : "ERR", preview});
    }

    private static class ResponseEntry {
        final String request;
        final int statusCode;
        final String response;

        ResponseEntry(String request, int statusCode, String response) {
            this.request = request;
            this.statusCode = statusCode;
            this.response = response;
        }
    }
}
