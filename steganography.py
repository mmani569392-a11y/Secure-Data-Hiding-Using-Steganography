"""
LSB image steganography.

A small header is stored before the encrypted payload:
    MAGIC (4 bytes) + payload length (4 bytes, big-endian) + payload

Each bit is placed in the least-significant bit of each RGB channel.
PNG is recommended for encoded images because lossy JPEG compression can
change pixel values and destroy hidden bits.
"""

from PIL import Image


MAGIC = b"SDH1"
HEADER_SIZE = 8


def _bytes_to_bits(data: bytes):
    for byte in data:
        for shift in range(7, -1, -1):
            yield (byte >> shift) & 1


def _bits_to_bytes(bits):
    result = bytearray()
    byte = 0
    count = 0

    for bit in bits:
        byte = (byte << 1) | bit
        count += 1
        if count == 8:
            result.append(byte)
            byte = 0
            count = 0

    if count:
        raise ValueError("Incomplete hidden data.")
    return bytes(result)


def capacity_bytes(image_path: str) -> int:
    image = Image.open(image_path).convert("RGB")
    total_channels = image.width * image.height * 3
    return max(0, total_channels // 8 - HEADER_SIZE)


def encode_message(input_path: str, payload: str, output_path: str):
    image = Image.open(input_path).convert("RGB")
    pixels = list(image.getdata())

    payload_bytes = payload.encode("utf-8")
    header = MAGIC + len(payload_bytes).to_bytes(4, "big")
    data = header + payload_bytes
    bits = list(_bytes_to_bits(data))

    if len(bits) > len(pixels) * 3:
        raise ValueError(
            f"Message is too large for this image. "
            f"Approximate capacity: {capacity_bytes(input_path)} bytes."
        )

    new_pixels = []
    bit_index = 0

    for pixel in pixels:
        channels = list(pixel)
        for channel_index in range(3):
            if bit_index < len(bits):
                channels[channel_index] = (
                    channels[channel_index] & 0xFE
                ) | bits[bit_index]
                bit_index += 1
        new_pixels.append(tuple(channels))

    encoded = Image.new("RGB", image.size)
    encoded.putdata(new_pixels)
    encoded.save(output_path, "PNG")


def decode_message(image_path: str) -> str:
    image = Image.open(image_path).convert("RGB")
    pixels = list(image.getdata())

    # First recover the fixed-size header.
    header_bits = []
    for pixel in pixels:
        for channel in pixel[:3]:
            header_bits.append(channel & 1)
            if len(header_bits) == HEADER_SIZE * 8:
                break
        if len(header_bits) == HEADER_SIZE * 8:
            break

    header = _bits_to_bytes(header_bits)

    if header[:4] != MAGIC:
        raise ValueError("No Secure Data Hiding payload was found in this image.")

    payload_length = int.from_bytes(header[4:8], "big")
    total_bits = (HEADER_SIZE + payload_length) * 8

    if total_bits > len(pixels) * 3:
        raise ValueError("Hidden payload length is invalid or the image is corrupted.")

    all_bits = []
    for pixel in pixels:
        for channel in pixel[:3]:
            all_bits.append(channel & 1)
            if len(all_bits) == total_bits:
                break
        if len(all_bits) == total_bits:
            break

    data = _bits_to_bytes(all_bits)
    payload = data[HEADER_SIZE:].decode("utf-8")
    return payload
