import json
import random

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


BYTE_MASK = 0xFF
ROTATE_MASK = 0x07
BYTE_BITS = 8
FRAGMENT_SIZE = 8
MODULUS = 257
MODULAR_EXPONENT = 255
SEPARATORS = (",", ":")

GLOBAL_SEED = 0x9F
SELECTOR_TABLE = (0x19, 0xDA, 0xCD, 0xFC)

OFFSET_TABLE = bytes(range(FRAGMENT_SIZE))
XOR_TABLE = bytes((
    0x00, 0x0B, 0x16, 0x21,
    0x2C, 0x37, 0x42, 0x4D,
))

SELECTOR_COEFFICIENT = 3
INDEX_COEFFICIENT = 7

MOD_COEFFICIENT = 5
MOD_INDEX_COEFFICIENT = 13

CGO_SELECTOR_COEFFICIENT = 2
CGO_INDEX_COEFFICIENT = 11

KEY_CGO_SEED = 0x9C
IV_CGO_SEED = 0x8F

C2_IMMEDIATE = 0x3CDA9C71B0E82D0C


INV_SBOX = bytes.fromhex(
    """
    52 09 6A D5 30 36 A5 38 BF 40 A3 9E 81 F3 D7 FB
    7C E3 39 82 9B 2F FF 87 34 8E 43 44 C4 DE E9 CB
    54 7B 94 32 A6 C2 23 3D EE 4C 95 0B 42 FA C3 4E
    08 2E A1 66 28 D9 24 B2 76 5B A2 49 6D 8B D1 25
    72 F8 F6 64 86 68 98 16 D4 A4 5C CC 5D 65 B6 92
    6C 70 48 50 FD ED B9 DA 5E 15 46 57 A7 8D 9D 84
    90 D8 AB 00 8C BC D3 0A F7 E4 58 05 B8 B3 45 06
    D0 2C 1E 8F CA 3F 0F 02 C1 AF BD 03 01 13 8A 6B
    3A 91 11 41 4F 67 DC EA 97 F2 CF CE F0 B4 E6 73
    96 AC 74 22 E7 AD 35 85 E2 F9 37 E8 1C 75 DF 6E
    47 F1 1A 71 1D 29 C5 89 6F B7 62 0E AA 18 BE 1B
    FC 56 3E 4B C6 D2 79 20 9A DB C0 FE 78 CD 5A F4
    1F DD A8 33 88 07 C7 31 B1 12 10 59 27 80 EC 5F
    60 51 7F A9 19 B5 4A 0D 2D E5 7A 9F 93 C9 9C EF
    A0 E0 3B 4D AE 2A F5 B0 C8 EB BB 3C 83 53 99 61
    17 2B 04 7E BA 77 D6 26 E1 69 14 63 55 21 0C 7D
    """
)


KEY_MATERIALS = (
    bytes.fromhex("1954F748772F7425"),
    bytes.fromhex("C39FA4CD35BA7AF8"),
    bytes.fromhex("28A37251753240AA"),
    C2_IMMEDIATE.to_bytes(FRAGMENT_SIZE, "little"),
)

IV_MATERIALS = (
    bytes.fromhex("21E4B165A9397076"),
    bytes.fromhex("187D12AA09FCFCFA"),
)

KEY_RAW_MATERIALS = (
    bytes.fromhex("F6 79 D5 41 60 82 22 6A"),
    bytes.fromhex("29 73 D1 8B 80 0D 9D 53"),
    bytes.fromhex("68 40 E2 80 58 DE C9 59"),
    bytes.fromhex("B8 43 B1 AD 84 7C 00 CD"),
)

IV_RAW_MATERIALS = (
    bytes.fromhex("2C CA 67 57 4E 0B DE C6"),
    bytes.fromhex("AE 3E A3 1A 9E 2A D0 00"),
)


def rotate_right(value, bits):
    bits &= ROTATE_MASK

    return (
        (value >> bits)
        | (value << (BYTE_BITS - bits))
    ) & BYTE_MASK


def fold_selector(selector, index):
    return (
        BYTE_MASK
        - selector
        - index
    ) & BYTE_MASK


def expand_selector(selector, index):
    return (
        SELECTOR_COEFFICIENT * selector
        + INDEX_COEFFICIENT * index
    ) & BYTE_MASK


def derive_selectors():
    return tuple(
        (byte - GLOBAL_SEED) & BYTE_MASK
        for byte in SELECTOR_TABLE
    )


SEL_KEY0, SEL_KEY1, SEL_IV0, SEL_KEY3 = derive_selectors()


def inverse_mod_257(value):
    value %= MODULUS

    if value == 0:
        value = 1

    return pow(
        value,
        MODULAR_EXPONENT,
        MODULUS,
    )


def inverse_multiply(value, selector, index):
    multiplier = (
        MOD_COEFFICIENT * selector
        + MOD_INDEX_COEFFICIENT * index
    ) % MODULUS

    if multiplier == 0:
        multiplier = 1

    return (
        (
            value
            * inverse_mod_257(multiplier)
        )
        % MODULUS
    ) & BYTE_MASK


def pcoh(material, selector):
    chunk = bytearray(material)

    for index in range(FRAGMENT_SIZE):
        chunk[index] ^= fold_selector(
            selector,
            index,
        )

    shift = selector & ROTATE_MASK

    if shift:
        for index in range(FRAGMENT_SIZE):
            chunk[index] = rotate_right(
                chunk[index],
                shift,
            )

    for index in range(FRAGMENT_SIZE):
        chunk[index] ^= expand_selector(
            selector,
            index,
        )

    return bytes(chunk)


def cgo_chunk(material, seed):
    shift = seed & ROTATE_MASK
    xor_base = (seed * 2) & BYTE_MASK

    return bytes(
        rotate_right(
            (
                material[index]
                + OFFSET_TABLE[index]
                + seed
            ) & BYTE_MASK,
            shift,
        )
        ^ (
            (
                XOR_TABLE[index]
                + xor_base
            ) & BYTE_MASK
        )
        for index in range(FRAGMENT_SIZE)
    )


def decode_pcoh(material, selector):
    chunk = bytearray(
        INV_SBOX[byte]
        for byte in material
    )

    for index in range(FRAGMENT_SIZE):
        chunk[index] = inverse_multiply(
            chunk[index],
            selector,
            index,
        )

    for index in range(FRAGMENT_SIZE):
        chunk[index] ^= fold_selector(
            selector,
            index,
        )

    shift = selector & ROTATE_MASK

    if shift:
        for index in range(FRAGMENT_SIZE):
            chunk[index] = rotate_right(
                chunk[index],
                shift,
            )

    for index in range(FRAGMENT_SIZE):
        chunk[index] ^= expand_selector(
            selector,
            index,
        )

    return bytes(chunk)


def decode_cgo_chunk(material, seed):
    shift = seed & ROTATE_MASK
    chunk = bytearray()

    for index, byte in enumerate(material):
        value = inverse_multiply(
            INV_SBOX[byte],
            seed,
            index,
        )

        value = (
            value
            + index
            + seed
        ) & BYTE_MASK

        value = rotate_right(
            value,
            shift,
        )

        value ^= (
            CGO_SELECTOR_COEFFICIENT * seed
            + CGO_INDEX_COEFFICIENT * index
        ) & BYTE_MASK

        chunk.append(value)

    return bytes(chunk)


def recover_fragments(
    key_materials,
    iv_materials,
    pcoh_decoder,
    cgo_decoder,
):
    key = (
        pcoh_decoder(
            key_materials[0],
            SEL_KEY0,
        )
        + pcoh_decoder(
            key_materials[1],
            SEL_KEY1,
        )
        + cgo_decoder(
            key_materials[2],
            KEY_CGO_SEED,
        )
        + pcoh_decoder(
            key_materials[3],
            SEL_KEY3,
        )
    )

    iv = (
        pcoh_decoder(
            iv_materials[0],
            SEL_IV0,
        )
        + cgo_decoder(
            iv_materials[1],
            IV_CGO_SEED,
        )
    )

    return key, iv


def recover_key_and_iv():
    return recover_fragments(
        KEY_MATERIALS,
        IV_MATERIALS,
        pcoh,
        cgo_chunk,
    )


def recover_key_and_iv_v2():
    return recover_fragments(
        KEY_RAW_MATERIALS,
        IV_RAW_MATERIALS,
        decode_pcoh,
        decode_cgo_chunk,
    )


def encrypt(payload, key, iv):
    if isinstance(payload, str):
        plaintext = payload.encode("utf-8")
    else:
        plaintext = json.dumps(
            payload,
            ensure_ascii=False,
            separators=SEPARATORS,
        ).encode("utf-8")

    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv,
    )

    return cipher.encrypt(
        pad(
            plaintext,
            AES.block_size,
        )
    ).hex().upper()


def decrypt(ciphertext, key, iv):
    cipher = AES.new(
        key,
        AES.MODE_CBC,
        iv,
    )

    plaintext = unpad(
        cipher.decrypt(ciphertext),
        AES.block_size,
    )

    return json.loads(
        plaintext.decode("utf-8")
    )

def box(title):
    width = 50
    print()
    print("▓" * width)
    print("▓" + " " * (width-2) + "▓")
    
    padding = (width - 2 - len(title)) // 2
    print("▓" + " " * padding + title + " " * (width-2-len(title)-padding) + "▓")
    
    print("▓" + " " * (width-2) + "▓")
    print("▓" * width)
    print()

def info(message):
    print("─" * 60)
    print(message)
    print("─" * 60)

def main():
    box("TscanPlus Keygen")
    
    key1, iv1 = recover_key_and_iv()
    key2, iv2 = recover_key_and_iv_v2()
    
    payload = { 
        "poc_id": "23117", 
        "level": "5", 
        "poc_vip_time": random.randint(1801440000, 1802649599), 
        "checktime": 0, 
        "uuid": "144", 
        "key": "204", 
        "desc": "Reverse 版" 
    }
    
    encrypted = encrypt(payload, key1, iv1)
    
    info(f"A key has been generated automatically. Please paste it into the input field, then click “Offline Auth”:\n{encrypted}")
    
    machine_code = input("Please enter the MachineCode generated by TscanPlus:\n")
    
    decrypted = decrypt(
        bytes.fromhex(machine_code), 
        key1, 
        iv1
    )
    
    payload.update({
        "poc_vip_time": decrypted["poc_vip_time"],
        "checktime": decrypted["checktime"],
        "uuid": decrypted["uuid"],
        "key": decrypted["key"],
    })
    
    encrypted_inner = encrypt(payload, key2, iv2)
    encrypted = encrypt(encrypted_inner, key1, iv1)
    
    info(f"Please enter the generated Offline Auth Code into the input field, then click “Confirm”:\n{encrypted}")
    input("Enjoy reverse engineering!\n\nPress ENTER to exit...")

if __name__ == "__main__":
    main()
