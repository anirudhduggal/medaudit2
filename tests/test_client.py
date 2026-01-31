from medaudit.hl7server.hl7_client import HL7Client
import sys

def main():
    client = HL7Client()
    if client.connect():
        try:
            response = client.send_adt_message()
            if response:
                print("Server response:")
                print(response)
            else:
                print("No response from server.", file=sys.stderr)
        except Exception as e:
            print(f"An error occurred: {e}", file=sys.stderr)
        finally:
            client.disconnect()
    else:
        print("Could not connect to server.", file=sys.stderr)

if __name__ == "__main__":
    main()