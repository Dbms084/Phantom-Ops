from typing import Tuple
from .lsb import extract_ack_from_image, hide_ack_in_image
from .spread_spectrum import extract_ack_spread_spectrum, hide_ack_spread_spectrum
from .tcp_timestamp import send_ack_via_tcp_timestamp

class ACKHidingManager:
    @staticmethod
    def hide_ack(message_id: int, sensitivity: str, cover_path: str = None, key: str = None, sender_ip: str = "127.0.0.1") -> Tuple[str, str]:
        """
        Selects the appropriate steganography method based on sensitivity.
        Returns a tuple of (stego_image_path, method_used).
        For 'high' sensitivity, it triggers TCP Timestamp stego directly and returns (None, "tcp_timestamp").
        """
        sensitivity = sensitivity.lower()
        if sensitivity == "low":
            # For low sensitivity, we don't necessarily need a key.
            # Using the existing LSB implementation.
            return hide_ack_in_image(message_id, cover_path), "lsb"
        elif sensitivity == "medium":
            if not key:
                raise ValueError("Key is required for medium sensitivity (Spread Spectrum).")
            return hide_ack_spread_spectrum(message_id, cover_path, key), "spread_spectrum"
        elif sensitivity == "high":
            # High sensitivity triggers TCP Timestamp steganography
            send_ack_via_tcp_timestamp(message_id, sender_ip)
            return None, "tcp_timestamp"
        else:
            # Default to LSB
            return hide_ack_in_image(message_id, cover_path), "lsb"

    @staticmethod
    def extract_ack(stego_data_path: str, method: str, key: str = None) -> int:
        """
        Routes the extraction to the correct decoder based on the method.
        """
        method = method.lower()
        if method == "lsb":
            return extract_ack_from_image(stego_data_path)
        elif method == "spread_spectrum":
            if not key:
                raise ValueError("Key is required for Spread Spectrum extraction.")
            return extract_ack_spread_spectrum(stego_data_path, key)
        elif method == "tcp_timestamp":
            raise NotImplementedError(
                "High sensitivity (TCP Timestamp) ACK extraction is performed asynchronously "
                "by the background sniffer listener thread."
            )
        else:
            raise ValueError(f"Unknown stego method: {method}")

