"""
Standalone Sender Client for NTP-SCTAP.

Runs independently from the Flask dashboard and sends encrypted
messages to a remote NTP-SCTAP receiver.

No existing project files are modified.
"""

from crypto.engine import CryptoEngine
from sender.manager import SenderManager


def main():
    print("=" * 55)
    print("      NTP-SCTAP Remote Sender Client")
    print("=" * 55)

    host = input("Receiver IP : ").strip()

    port_input = input("Receiver Port [9124] : ").strip()
    port = int(port_input) if port_input else 9124

    password = input("Password : ").strip()

    message = input("Message : ").strip()

    if not host:
        print("Receiver IP cannot be empty.")
        return

    if not password:
        print("Password cannot be empty.")
        return

    if not message:
        print("Message cannot be empty.")
        return

    try:
        crypto = CryptoEngine(password=password)

        sender = SenderManager(
            crypto_engine=crypto,
            target_host=host,
            target_port=port,
        )

        message_id = sender.send_message(message)

        print("\n===================================")
        print("✓ Message Sent Successfully")
        print(f"Message ID : {message_id}")
        print("===================================\n")

    except Exception as e:
        print("\nFailed to send message.")
        print(e)


if __name__ == "__main__":
    main()