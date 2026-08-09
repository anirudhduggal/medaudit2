# Medaudit2 Burp Suite Extension

A Java extension for Burp Suite that forwards HTTP requests to the Medaudit HTTP-to-MLLP proxy for HL7 medical device security testing.

Source code is fully included in this directory (`burp-extension/`) so you can inspect, modify, and build the extension on your own.

## How It Works

1. Right-click any request in Burp **Proxy**, **Repeater**, or **Target**
2. Select **"Send to Medaudit2"**
3. The request body is forwarded to the Medaudit HTTP-to-MLLP proxy
4. The proxy converts it to HL7/MLLP and sends it to the target medical device
5. The HL7 response is displayed in the **Medaudit2 > Response Log** tab

## Building from Source

### Prerequisites
- Java JDK 17 or higher
- Gradle (or standard IDE Java build tools)
- Burp Suite Professional or Community Edition

### Build Steps

```bash
cd burp-extension
gradle jar
# Output artifact: build/libs/medaudit2-burp-extension-1.0.0.jar
```

## Installing in Burp Suite

1. In Burp Suite: **Extensions > Installed > Add**
2. Select **Extension type: Java**
3. Select the compiled JAR file (`burp-extension/build/libs/medaudit2-burp-extension-1.0.0.jar`)
4. Click **Next** -- the extension loads

## Usage & Configuration

1. Go to the **Medaudit2** tab in Burp Suite
2. Set the **Medaudit Proxy Host** (default: `localhost`)
3. Set the **Medaudit Proxy Port** (default: `8080`)
4. Click **Test Connection** to verify

### Start Medaudit Proxy
```bash
# Start the HL7 server (target)
python -m medaudit.hl7server start --port 2575

# Start the HTTP-to-MLLP proxy
python -m medaudit proxy --port 8080 --hl7-host localhost --hl7-port 2575
```
