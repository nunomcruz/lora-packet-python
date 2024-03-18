def reverse_buffer(buffer: bytes) -> bytes:
    return bytes(reversed(buffer))

def as_hex_string(buffer: bytes) -> str:
    return buffer.hex().upper()