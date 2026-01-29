
if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='HTTP-to-HL7 Proxy Server')
    parser.add_argument('--host', default='localhost', help='Host for the HTTP proxy server')
    parser.add_argument('--port', type=int, default=8080, help='Port for the HTTP proxy server')
    parser.add_argument('--hl7-host', default='localhost', help='Hostname of the target HL7 server')
    parser.add_argument('--hl7-port', type=int, default=2575, help='Port of the target HL7 server')
    args = parser.parse_args()

    start_proxy(
        http_host=args.host,
        http_port=args.port,
        hl7_host=args.hl7_host,
        hl7_port=args.hl7_port
    )
