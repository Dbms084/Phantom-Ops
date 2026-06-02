import random
import threading
from scapy.all import IP, TCP, send, sniff

MAGIC_TSECR = 0x4D5347  # "MSG" in ASCII/hex: 0x4D5347

def send_ack_via_tcp_timestamp(message_id: int, sender_ip: str, sender_port: int = 9999):
    """
    Sends an ACK for a message by hiding the message ID in the TCP Timestamp option.
    Crafts a TCP packet with TSval set to message_id and TSecr set to MAGIC_TSECR.
    """
    # Ensure message_id is within 32-bit unsigned int bounds
    tsval = message_id & 0xFFFFFFFF
    
    # TCP options: ('Timestamp', (TSval, TSecr))
    tcp_options = [('Timestamp', (tsval, MAGIC_TSECR))]
    
    # Create IP and TCP headers
    # Using a random source port in ephemeral range
    src_port = random.randint(49152, 65535)
    
    packet = IP(dst=sender_ip) / TCP(
        sport=src_port,
        dport=sender_port,
        flags="S",  # SYN packet
        options=tcp_options
    )
    
    # Send packet
    send(packet, verbose=False)
    print(f"[Covert Sender] Sent TCP Timestamp ACK for message {message_id} to {sender_ip}:{sender_port}")
    return True

def start_covert_listener(port: int = 9999):
    """
    Starts a background thread to sniff for TCP Timestamp ACK packets.
    """
    def packet_callback(packet):
        if TCP in packet:
            tcp_layer = packet[TCP]
            options = tcp_layer.options
            for opt in options:
                if opt[0] == 'Timestamp':
                    tsval, tsecr = opt[1]
                    if tsecr == MAGIC_TSECR:
                        message_id = tsval
                        print(f"[Covert Listener] Detected stego TCP Timestamp ACK. Message ID: {message_id}")
                        _mark_message_as_destroyed(message_id)

    def sniff_thread():
        print(f"[Covert Listener] Sniffing for covert TCP packets on port {port}...")
        try:
            import os
            from scapy.all import conf
            # On Windows, sniffing on default interface doesn't capture loopback traffic.
            # We explicitly specify loopback interface if running on NT.
            if os.name == 'nt':
                sniff(filter=f"tcp port {port}", prn=packet_callback, store=0, iface=conf.loopback_name)
            else:
                sniff(filter=f"tcp port {port}", prn=packet_callback, store=0)
        except Exception as e:
            print(f"[Covert Listener] Sniffing failed or interrupted: {e}")

    thread = threading.Thread(target=sniff_thread, daemon=True)
    thread.start()
    return thread


def _mark_message_as_destroyed(message_id: int):
    """
    Looks up the message by ID and marks it destroyed in the database.
    """
    try:
        from ..database import SessionLocal
        from ..models import Message
        
        db = SessionLocal()
        try:
            message = db.query(Message).filter(Message.id == message_id).first()
            if message:
                if not message.is_destroyed:
                    message.is_destroyed = True
                    db.commit()
                    print(f"[Covert Listener] Marked message {message_id} as destroyed in database.")
                else:
                    print(f"[Covert Listener] Message {message_id} is already marked destroyed.")
            else:
                print(f"[Covert Listener] Warning: Message ID {message_id} not found in database.")
        except Exception as db_err:
            print(f"[Covert Listener] Database update error: {db_err}")
        finally:
            db.close()
    except Exception as imp_err:
        print(f"[Covert Listener] Import or database connection error: {imp_err}")
