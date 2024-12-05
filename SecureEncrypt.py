import bcrypt
import argparse
import os
import logging
import hmac
import hashlib
import re
import stat
import sys
from getpass import getpass
from typing import Tuple
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

LOG_FILE = "operations.log"
BLOCK_SIZE = AES.block_size
HMAC_KEY_LENGTH = 32
HMAC_DIGEST_LENGTH = 32
DEFAULT_KEY_FILE = "encryption_key.bin"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
os.chmod(LOG_FILE, stat.S_IRUSR | stat.S_IWUSR)
logger = logging.getLogger()

HARDCODED_PASSWORD = "password"
HARDCODED_HASH = bcrypt.hashpw(HARDCODED_PASSWORD.encode(), bcrypt.gensalt())

def check_password(password: str) -> bool:
    return bcrypt.checkpw(password.encode(), HARDCODED_HASH)

def login():
    attempts = 3
    while attempts > 0:
        password = getpass("Enter password to unlock: ") 
        if check_password(password):
            print("Login successful.")
            logger.info("User logged in successfully.")
            return True
        else:
            attempts -= 1
            logger.warning(f"Failed login attempt. {attempts} attempt(s) remaining.")
            print(f"Incorrect password. {attempts} attempt(s) remaining.")
    
    print("Maximum login attempts exceeded.")
    logger.warning("Maximum login attempts exceeded. Access denied.")
    sys.exit(1)

def zero_memory(data: bytearray):
    for i in range(len(data)):
        data[i] = 0

def pad_pkcs(msg: bytes, bl: int = BLOCK_SIZE) -> bytes:
    return pad(msg, bl)

def unpad_pkcs(padded: bytes, bl: int = BLOCK_SIZE) -> bytes:
    return unpad(padded, bl)

def validate_iv(iv: bytes):
    if len(iv) != BLOCK_SIZE:
        raise ValueError("Initialization Vector (IV) must be exactly 16 bytes for AES.")
    
def sanitize_iv(iv: str) -> bytes:
    if not re.fullmatch(r'[0-9a-fA-F]{32}', iv):
        raise ValueError("Invalid IV. The IV must be a 32-character hexadecimal string (16 bytes).")
    iv_bytes = bytes.fromhex(iv)
    validate_iv(iv_bytes)
    return iv_bytes

def restrict_filename(filename: str) -> str:
    sanitized = os.path.basename(filename)
    sanitized = re.sub(r'[^a-zA-Z0-9._-]', '', sanitized)
    return sanitized

def generate_key(keyfile: str) -> Tuple[bytearray, bytearray]:
    key = bytearray(get_random_bytes(32))
    hmac_key = bytearray(get_random_bytes(HMAC_KEY_LENGTH))
    with open(keyfile, "wb") as f:
        f.write(key + hmac_key)
    print(f"Generated and saved new key to {keyfile}")
    return key, hmac_key

def load_key(keyfile: str) -> Tuple[bytearray, bytearray]:
    if not os.path.exists(keyfile):
        raise FileNotFoundError(f"Key file '{keyfile}' does not exist.")
    with open(keyfile, "rb") as f:
        content = f.read()
    if len(content) != 64:
        raise ValueError("Invalid key file. Expected 64 bytes for AES and HMAC keys.")
    return bytearray(content[:32]), bytearray(content[32:])

def add_hmac(data: bytes, hmac_key: bytes) -> bytes:
    hmac_obj = hmac.new(hmac_key, data, hashlib.sha256)
    return hmac_obj.digest()

def verify_hmac(data: bytes, received_hmac: bytes, hmac_key: bytes):
    expected_hmac = add_hmac(data, hmac_key)
    if not hmac.compare_digest(expected_hmac, received_hmac):
        raise ValueError("Data integrity check failed (HMAC does not match).")

def encrypt(msg: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad_pkcs(msg))

def decrypt(ct: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad_pkcs(cipher.decrypt(ct))

def encrypt_file(input_file: str, output_file: str, key: bytes, hmac_key: bytes) -> bool:
    try:
        with open(input_file, "rb") as f:
            plaintext = f.read()

        original_filename = restrict_filename(os.path.basename(input_file)).encode()
        filename_length = len(original_filename)
        filename_header = filename_length.to_bytes(1, 'big') + original_filename

        iv = get_random_bytes(BLOCK_SIZE)
        ciphertext = encrypt(filename_header + plaintext, key, iv)
        hmac_tag = add_hmac(iv + ciphertext, hmac_key)

        with open(output_file, "wb") as f:
            f.write(iv + hmac_tag + ciphertext)
        return True
    except PermissionError:
        print(f"Error: Permission denied when trying to write to '{output_file}'.")
        return False
    except OSError as e:
        print(f"Error: Unable to write to '{output_file}'. {e}")
        return False

def decrypt_file(input_file: str, output_file: str, key: bytes, hmac_key: bytes) -> bool:
    try:
        with open(input_file, "rb") as f:
            data = f.read()

        minimum_size = BLOCK_SIZE + HMAC_DIGEST_LENGTH + BLOCK_SIZE
        if len(data) < minimum_size:
            raise ValueError("Invalid encrypted file. File is too small to contain required components (IV, HMAC, ciphertext).")

        iv = data[:BLOCK_SIZE]
        hmac_tag = data[BLOCK_SIZE:BLOCK_SIZE + HMAC_DIGEST_LENGTH]
        ciphertext = data[BLOCK_SIZE + HMAC_DIGEST_LENGTH:]

        validate_iv(iv)
        verify_hmac(iv + ciphertext, hmac_tag, hmac_key)
        plaintext = decrypt(ciphertext, key, iv)

        filename_length = plaintext[0]
        if filename_length + 1 > len(plaintext):
            raise ValueError("Corrupted file. Embedded filename length exceeds actual data length.")
        
        original_filename = plaintext[1:1 + filename_length].decode()
        file_content = plaintext[1 + filename_length:]

        final_output_file = output_file
        if output_file == "original":
            final_output_file = restrict_filename(original_filename)
        elif os.path.isdir(output_file):
            final_output_file = os.path.join(output_file, restrict_filename(original_filename))

        with open(final_output_file, "wb") as f:
            f.write(file_content)
        return True
    except PermissionError:
        print(f"Error: Permission denied when trying to write to '{final_output_file}'.")
        return False
    except OSError as e:
        print(f"Error: Unable to write to '{final_output_file}'. {e}")
        return False

def secure_delete(filepath: str, passes: int = 3) -> bool:
    try:
        if not os.path.isfile(filepath):
            print(f"Error: File '{filepath}' does not exist or is not a file.")
            return False

        length = os.path.getsize(filepath)

        with open(filepath, "r+b") as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(length))
                f.flush()
                os.fsync(f.fileno())

        with open(filepath, "r+b") as f:
            f.seek(0)
            f.write(b'\x00' * length)
            f.flush()
            os.fsync(f.fileno())

        os.remove(filepath)
        logger.info(f"Securely deleted file: {filepath} with {passes} passes.")
        print(f"Securely deleted file: {filepath} with {passes} passes.")
        return True
    except PermissionError:
        print(f"Error: Permission denied when trying to delete '{filepath}'.")
        return False
    except OSError as e:
        print(f"Error: Unable to delete '{filepath}'. {e}")
        return False

def main(args):
    if args.encrypt and args.decrypt:
        print("Error: -e/--encrypt and -d/--decrypt cannot be used together.")
        print("Use -h or --help for more information.")
        sys.exit(1)

    if not args.encrypt and not args.decrypt and not args.delete:
        print("Error: Mode unspecified.")
        print("Use -h or --help for more information.")
        sys.exit(1)

    if args.delete and any([args.keyfile, args.output_file, args.iv, args.encrypt, args.decrypt, args.original_format]):
        print("Error: -D/--delete cannot be combined with other options.")
        print("Use -h or --help for more information.")
        sys.exit(1)

    if args.iv:
        try:
            args.iv = sanitize_iv(args.iv)
        except ValueError as e:
            print(f"Error: {e}")
            print("Use -h or --help for more information.")
            sys.exit(1)

    if args.encrypt and args.original_format:
        print("Error: -O/--original-format is only applicable with decryption.")
        print("Use -h or --help for more information.")
        sys.exit(1)

    if args.original_format and args.output_file and not os.path.isdir(args.output_file):
        print("Error: When using -O/--original-format, the output path (-o/--output) must be a directory.")
        print("Use -h or --help for more information.")
        sys.exit(1)

    if not login():
        print("Too many failed attempts. Exiting...")
        return

    keyfile = args.keyfile or DEFAULT_KEY_FILE
    key, hmac_key = (generate_key(keyfile) if not os.path.exists(keyfile) else load_key(keyfile))

    if not os.path.isfile(args.INPUT_FILE):
        print(f"Error: Input file '{args.INPUT_FILE}' does not exist or is not a file.")
        print("Use -h or --help for more information.")
        sys.exit(1)

    if args.original_format:
        args.output_file = args.output_file or "original"
    elif not args.output_file:
        args.output_file = f"{args.INPUT_FILE}.enc" if args.encrypt else f"{args.INPUT_FILE[:-4]}.dec"
    elif os.path.isdir(args.output_file):
        input_base = os.path.basename(args.INPUT_FILE)
        default_output_filename = f"{input_base}.enc" if args.encrypt else f"{input_base[:-4]}.dec"
        args.output_file = os.path.join(args.output_file, default_output_filename)

    if args.encrypt:
        iv = args.iv if args.iv else get_random_bytes(BLOCK_SIZE)
        success = encrypt_file(args.INPUT_FILE, args.output_file, key, hmac_key)
        if success:
            zero_memory(key)
            zero_memory(hmac_key)
            print(f"File encrypted successfully.\nOutput written to: {args.output_file}")
    elif args.decrypt:
        success = decrypt_file(args.INPUT_FILE, args.output_file, key, hmac_key)
        if success:
            zero_memory(key)
            zero_memory(hmac_key)
            print("File decrypted successfully.")
            print(f"Output written to: {args.output_file}")
    elif args.delete:
        success = secure_delete(args.INPUT_FILE)
        if not success:
            sys.exit(1)
    else:
        print("Error: Invalid mode.")
        sys.exit(1)

class CustomHelpFormatter(argparse.RawTextHelpFormatter):
    def add_usage(self, usage, actions, groups, prefix=None):
        return "Usage: SecureEncrypt.py [-h] [-k ...] [-i ...] [-e | -d] [-o ...] [-O] [-D] INPUT_FILE\n\n"

    def start_section(self, heading):
        if heading == 'positional arguments':
            heading = 'Positional Arguments'
        elif heading == 'options':
            heading = 'Options'
        super().start_section(heading)

    def _format_action(self, action):
        if action.option_strings:
            option_string = ', '.join(action.option_strings)
            option_line = f"  {option_string:<22} "
        else:
            option_line = f"  {action.dest.upper():<22} "

        description = action.help or ""
        help_lines = self._split_lines(description, 60)
        formatted_lines = [option_line + help_lines[0]]
        formatted_lines.extend(" " * 23 + line for line in help_lines[1:])
        return "\n".join(formatted_lines) + "\n"

    def format_help(self):
        help_text = "SecureEncrypt: A tool for AES file encryption, decryption, and secure deletion.\n\n"
        help_text += self.add_usage(None, None, None, None)
        help_text += super().format_help()
        return help_text.strip()


class CustomArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        missing_arg_match = re.search(r"argument (\S+): expected one argument", message)
        
        if missing_arg_match:
            arg = missing_arg_match.group(1)
            print(f"Error: Expected an argument for {arg}")
        elif "unrecognized arguments:" in message.lower():
            unrecognized_args = message.split(":")[1].strip().split()
            if len(unrecognized_args) == 1:
                print(f"Error: Unrecognized argument '{unrecognized_args[0]}'")
            else:
                args_str = " ".join(f"'{arg}'" for arg in unrecognized_args)
                print(f"Error: Unrecognized arguments {args_str}")
        elif "not allowed with argument" in message:
            conflicting_args = message.split(": ")[1].split(" and ")
            if len(conflicting_args) == 2:
                print(f"Error: {conflicting_args[0]} cannot be combined with {conflicting_args[1]}")
            else:
                print(f"Error: {message.capitalize()}")
        else:
            print(f"Error: {message.capitalize()}")

        print("Use -h or --help for more information.")
        self.exit(2)

parser = CustomArgumentParser(
    description="",
    formatter_class=CustomHelpFormatter,
    add_help=False
)

parser.add_argument("INPUT_FILE", help="Path to the input file to encrypt, decrypt, or delete.")
parser.add_argument("-h", "--help", action="help", help="Show this help message and exit.")
parser.add_argument("-k", "--keyfile", help="Specify the path to the key file. (Default: encryption_key.bin)")
parser.add_argument("-i", "--iv", help="Specify the initialization vector in hexadecimal format. (16 bytes)")
mode_group = parser.add_mutually_exclusive_group()
mode_group.add_argument("-e", "--encrypt", action="store_true", help="Encrypt the specified input file.")
mode_group.add_argument("-d", "--decrypt", action="store_true", help="Decrypt the specified input file.")
parser.add_argument("-o", "--output", dest="output_file", help="Specify the output file path.")
parser.add_argument("-O", "--original-format", action="store_true", help="Restore the original filename when decrypting (if embedded in the encrypted file).")
parser.add_argument("-D", "--delete", action="store_true", help="Securely delete the specified input file.")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    
    args = parser.parse_args()

    try:
        main(args)
    except ValueError as e:
        print(f"Error: {e}")
        print("Use -h or --help for more information.")
        sys.exit(1)