# Medaudit2 Burp Suite Extension

A Burp Suite extension that forwards HTTP requests to the Medaudit HTTP-to-MLLP proxy for HL7 medical device security testing.

## How It Works

1. Right-click any request in Burp **Proxy**, **Repeater**, or **Target**
2. Select **"Send to Medaudit2"**
3. The request body is forwarded to the Medaudit HTTP-to-MLLP proxy
4. The proxy converts it to HL7/MLLP and sends it to the target medical device
5. The HL7 response is displayed in the **Medaudit2 > Response Log** tab

## Setup

### Prerequisites
- Burp Suite Professional or Community Edition
- Medaudit 2.0 running with the HTTP-to-MLLP proxy enabled

### Install the Extension
1. Download `medaudit2-burp-extension-1.0.0.jar` from the [Releases](https://github.com/anirudhduggal/medaudit2/releases) page
2. In Burp Suite: **Extensions > Installed > Add**
3. Select **Extension type: Java**
4. Select the downloaded JAR file
5. Click **Next** -- the extension loads

### Configure
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

## Building from Source

```bash
cd burp-extension
./gradlew jar
# Output: build/libs/medaudit2-burp-extension-1.0.0.jar
```

Requires Java 17+.
