# =============================================================================
# Script: p11xs.py → PKCS#11 XML Signer
#
# Description:
#   Command-line utility for digitally signing XML files (single or batch)
#   using PKCS#11-backed smart card or HSM keys. Supports both XML DSig and
#   XAdES signature formats, with options for SCAP/Base reference handling.
#
# Author: [Daniel Harris / NIWC Atlantic]
# License: Portions of this script were developed at Naval Information Warfare Center Atlantic by employees of the Federal Government in the course of their official duties. Pursuant to title 17 Section 105 of the United States Code this software is not subject to copyright protection and is in the public domain. The Government assumes no responsibility whatsoever for its use by other parties, and the software is provided "AS IS" without warranty or guarantee of any kind, express or implied, including, but not limited to, the warranties of merchantability and of fitness for a particular purpose. In no event shall the Government be liable for any claim, damages or other liability, whether in an action of contract, tort or other dealings in the software. The Government has no obligation hereunder to provide maintenance, support, updates, enhancements, or modifications. We would appreciate acknowledgement if the software is used. This software can be redistributed and/or modified freely provided that any derivative works bear some notice that they are derived from it, and any modified versions bear some notice that they have been modified.
#
# =============================================================================

import argparse
import binascii
import getpass
import logging
import os
import platform
import shutil
import sys
from typing import Tuple

import PyKCS11
from lxml import etree
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from signxml import XMLSigner, XMLVerifier, SignatureReference
from signxml.xades import XAdESSigner, XAdESVerifier, XAdESDataObjectFormat  # noqa: F401  (import kept for future use)

# =============================================================================
# Global Constants
# =============================================================================
# Default path to the OpenSC PKCS#11 module. Adjust as needed for your platform
# or PKCS#11 provider. On Linux/macOS this will likely be a .so or .dylib path.
PKCS11_MODULE = r"C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"


# =============================================================================
# Logging Configuration
# =============================================================================
def configure_logging(debug: bool, log_file: str = None):
    """
    Set up application logging.

    Args:
        debug: If True, emit verbose DEBUG logs; otherwise INFO.
        log_file: Optional log file path. If provided, logs are written both to
                  stdout and the file; otherwise to stdout only.
    """
    level = logging.DEBUG if debug else logging.INFO
    handlers = [logging.StreamHandler()]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=handlers,
    )


# =============================================================================
# SignXML Interface (Minimal wrappers so SignXML can use a PKCS#11 key)
# =============================================================================
class PublicNumbers:
    """Container for RSA public key parameters (n, e)."""
    def __init__(self, n: int, e: int):
        self.n = n
        self.e = e


class PublicKey:
    """Adapter that exposes public_numbers() like cryptography keys."""
    def __init__(self, n: int, e: int):
        self.pubnumbers = PublicNumbers(n, e)

    def public_numbers(self) -> PublicNumbers:
        return self.pubnumbers


class Key:
    """
    A PKCS#11-backed key pair interface used by signxml.

    Performs:
      - Retrieval of RSA public numbers (n, e)
      - Private-key signatures via CKM_SHA256_RSA_PKCS
    """
    def __init__(self, session: PyKCS11.Session, keyid: bytes):
        logging.debug("Initializing Key object.")
        self.session = session
        self.keyid = keyid
        self.pubkey = self._get_public_key()

    def _get_public_key(self) -> PublicKey:
        logging.debug("Retrieving public key from token.")
        pubkey = self.session.findObjects(
            [(PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY), (PyKCS11.CKA_ID, self.keyid)]
        )
        if not pubkey:
            raise RuntimeError("No matching public key found on the token for the given key ID.")

        pubkey = pubkey[0]
        modulus = self.session.getAttributeValue(pubkey, [PyKCS11.CKA_MODULUS])[0]
        exponent = self.session.getAttributeValue(pubkey, [PyKCS11.CKA_PUBLIC_EXPONENT])[0]
        n = int(binascii.hexlify(bytearray(modulus)), 16)
        e = int(binascii.hexlify(bytearray(exponent)), 16)
        logging.debug("Public key retrieved: modulus (n) and exponent (e).")
        return PublicKey(n, e)

    def sign(self, data: bytes, padding, algorithm) -> bytes:  # API surface kept for signxml
        logging.debug("Signing data using the private key.")
        privkey = self.session.findObjects(
            [(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY), (PyKCS11.CKA_ID, self.keyid)]
        )
        if not privkey:
            raise RuntimeError("No matching private key found on the token for the given key ID.")

        privkey = privkey[0]
        sig = self.session.sign(privkey, data, PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS))
        logging.debug("Data signed successfully.")
        return bytes(sig)

    def public_key(self) -> PublicKey:
        return self.pubkey


# =============================================================================
# Signer: High-level workflow for XML signing & verification
# =============================================================================
class Signer:
    """
    Manages the end-to-end signing workflow:

      - Loads the PKCS#11 module and opens sessions
      - Retrieves certificates & key IDs from the token
      - Signs XML using XML DSig or XAdES modes
      - Verifies the resulting signature
    """
    def __init__(
        self,
        pkcs11_module: str,
        signer_type: str = "dsig",
        c14n_algorithm: str = "http://www.w3.org/2006/12/xml-c14n11",
        cert_id: str = None,
        slot_index: int = 0,
        scap: bool = False,
        base: bool = False,
        references: int = 0,
    ):
        logging.debug("Initializing Signer object.")
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load(pkcs11_module)
        logging.debug(f"PKCS#11 module loaded: {pkcs11_module}")
        self.session = None
        self.signer_type = signer_type
        self.c14n_algorithm = c14n_algorithm
        self.cert_id = cert_id
        self.slot_index = slot_index
        self.scap = scap
        self.references = 0
        self.base = base

    def list_certs(self):
        """List all certificates on all present tokens/slots."""
        logging.info("Listing all certificates on all slots.")
        slots = self.pkcs11.getSlotList(tokenPresent=True)
        if not slots:
            raise RuntimeError("No slots with tokens found.")

        for slot_index, slot in enumerate(slots):
            logging.info(f"Checking slot {slot_index}: {slot}")
            session = None
            try:
                session = self._open_session(slot, None)
                pk11objects = session.findObjects(
                    [(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)]
                )
                for i, pk11object in enumerate(pk11objects):
                    try:
                        attributes = session.getAttributeValue(pk11object, [
                            PyKCS11.CKA_VALUE, PyKCS11.CKA_ID, PyKCS11.CKA_LABEL
                        ])
                        cert = bytes(attributes[0])
                        cert_id = binascii.hexlify(bytes(attributes[1])).decode()
                        label = attributes[2] if attributes[2] else "<No Label>"
                        cert_obj = x509.load_der_x509_certificate(cert, backend=default_backend())
                        cert_subject = cert_obj.subject.rfc4514_string()
                        cert_issuer = cert_obj.issuer.rfc4514_string()
                        serial_number = cert_obj.serial_number

                        logging.info(
                            f"Slot {slot_index}, Certificate {i}: "
                            f"ID={cert_id}, Label={label}, Subject={cert_subject}, Issuer={cert_issuer}, Serial={serial_number}"
                        )
                    except PyKCS11.PyKCS11Error as e:
                        logging.warning(f"Error retrieving attributes for certificate {i} in slot {slot_index}: {e}")
            except RuntimeError as e:
                logging.warning(f"Unable to access slot {slot_index}: {e}")
            finally:
                if session:
                    try:
                        session.logout()
                    except PyKCS11.PyKCS11Error as e:
                        logging.debug(f"Session logout failed for slot {slot_index}: {e}")
                    session.closeSession()

    def sign(self, input_path: str):
        """Sign a single XML file, or every .xml in a directory."""
        pin = self._prompt_for_pin()
        if os.path.isdir(input_path):
            logging.info(f"Processing directory: {input_path}")
            for filename in os.listdir(input_path):
                if filename.lower().endswith(".xml"):
                    file_path = os.path.join(input_path, filename)
                    logging.info(f"Signing file: {file_path}")
                    self.sign_file(pin, file_path)
        elif os.path.isfile(input_path):
            self.sign_file(pin, input_path)
        else:
            raise ValueError(f"Invalid input path: {input_path}")

    def sign_file(self, pin, input_file: str):
        """
        Sign a single XML file and write the output to the 'SignedOutput' directory.
        """
        logging.info(f"Starting the signing process for file: {input_file}")
        try:
            slot = self._get_slot()
            self.session = self._open_session(slot, pin)

            # Read and parse the input file
            root = self._read_input_file(input_file)

            # Retrieve certificate and key ID from the token
            keyid, cert_pem = self._get_cert()

            # Initialize the Key object (SignXML-compatible)
            key = Key(self.session, keyid)

            # Sign the XML document
            signed_root = self._sign(root, key, cert_pem)

            # Generate the output filename (ensure output dir exists)
            output_file = self._generate_output_filename(input_file)
            os.makedirs(os.path.dirname(output_file), exist_ok=True)

            # Save the signed XML document
            self._write_output_file(signed_root, output_file)

            # Verify the signature
            self._verify_signature(signed_root, cert_pem)
        finally:
            self._logout()

    def _gather_reference_uris(self, root: etree.Element):
        """
        Build a list of SignatureReference objects derived from IDs in the XML.

        Modes:
            - SCAP mode (self.scap=True): add data-stream id and component ids
            - Base mode (self.base=True): add only the root element's id/Id
            - Default: no custom references (let signxml decide)
        """
        references = []

        if self.scap:
            data_stream_el = root.find(".//data-stream") or root.find(".//{*}data-stream")
            if data_stream_el is not None and "id" in data_stream_el.attrib:
                ds_id = data_stream_el.get("id")
                logging.debug(f"Found <data-stream> element with ID: {ds_id}")
                references.append(SignatureReference(URI=f"#{ds_id}"))

            component_els = root.findall(".//component") or root.findall(".//{*}component")
            for comp in component_els:
                if "id" in comp.attrib:
                    comp_id = comp.get("id")
                    logging.debug(f"Found <component> element with ID: {comp_id}")
                    references.append(SignatureReference(URI=f"#{comp_id}"))
        elif self.base:
            if "id" in root.attrib:
                root_id = root.get("id")
                logging.debug(f"Found id for root element: {root_id}")
                references.append(SignatureReference(URI=f"#{root_id}"))
            elif "Id" in root.attrib:
                root_id = root.get("Id")
                logging.debug(f"Found Id for root element: {root_id}")
                references.append(SignatureReference(URI=f"#{root_id}"))
            else:
                # Explicitly return None to mark "no applicable base reference"
                logging.debug("No ID found for root element in Base mode.")
                return None
        else:
            logging.debug("No custom SignatureReference mode selected (default).")

        logging.debug(f"Total references gathered: {len(references)}")
        return references

    def _sign(self, root: etree.Element, key: Key, cert: bytes) -> etree.Element:
        """
        Create a digital signature over the XML document.
        """
        logging.info(f"Using {self.signer_type} signer for the document.")
        reference_uri = self._gather_reference_uris(root)
        self.references = len(reference_uri) if reference_uri else 1

        if self.signer_type == "dsig":
            signer = XMLSigner(c14n_algorithm=self.c14n_algorithm)
        elif self.signer_type == "xades":
            # XAdES often adds additional references (e.g., signed properties)
            self.references += 2
            signer = XAdESSigner(c14n_algorithm=self.c14n_algorithm)
        else:
            raise ValueError(f"Unsupported signer type: {self.signer_type}")

        # Guard against None from Base-mode "no ID" case
        if reference_uri and len(reference_uri) > 0:
            return signer.sign(root, key=key, cert=cert, reference_uri=reference_uri)
        else:
            return signer.sign(root, key=key, cert=cert)

    def _verify_signature(self, signed_root: etree.Element, cert: bytes):
        """Verify the signature of 'signed_root'."""
        logging.info("Verifying the signed XML document.")
        if self.signer_type == "dsig":
            verifier = XMLVerifier()
            verifier.verify(signed_root, x509_cert=cert, expect_references=self.references)
        elif self.signer_type == "xades":
            verifier = XAdESVerifier()
            verifier.verify(signed_root, x509_cert=cert, expect_references=self.references)
        else:
            raise ValueError(f"Unsupported verifier type: {self.signer_type}")
        logging.info("Signature verification successful.")

    def _prompt_for_pin(self) -> str:
        """Securely prompt the user for a token PIN."""
        return getpass.getpass("Enter your PIN: ")

    def _get_slot(self) -> int:
        """Resolve the slot index to use for session/login."""
        logging.info("Retrieving available slots.")
        slots = self.pkcs11.getSlotList(tokenPresent=True)
        if not slots:
            raise RuntimeError("No slots with tokens found.")
        if self.slot_index < 0 or self.slot_index >= len(slots):
            raise ValueError(f"Invalid slot index: {self.slot_index}. Available slots: {len(slots)}")
        return slots[self.slot_index]

    def _open_session(self, slot: int, pin: str) -> PyKCS11.Session:
        """Open a (read-write) PKCS#11 session for the given slot and optionally log in."""
        logging.info(f"Opening a session with the token in slot: {slot}.")
        session = self.pkcs11.openSession(slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
        if pin:
            session.login(pin)
            logging.debug("Session opened and logged in successfully.")
        return session

    def _get_cert(self) -> Tuple[bytes, bytes]:
        """
        Retrieve a certificate and its corresponding key ID from the token.
        """
        logging.info("Retrieving certificate from the token.")
        pk11objects = self.session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)])
        if not pk11objects:
            raise RuntimeError("No certificates found on the token.")

        matched_obj = None
        matched_cert_id_str = None

        for pk11object in pk11objects:
            try:
                attributes = self.session.getAttributeValue(
                    pk11object, [PyKCS11.CKA_VALUE, PyKCS11.CKA_ID]
                )
                der_cert = bytes(attributes[0])
                cert_id = binascii.hexlify(bytes(attributes[1])).decode()

                if self.cert_id:
                    if cert_id.lower() == self.cert_id.lower():
                        matched_obj = der_cert
                        matched_cert_id_str = cert_id
                        break
                else:
                    matched_obj = der_cert
                    matched_cert_id_str = cert_id
                    break
            except PyKCS11.PyKCS11Error as e:
                logging.warning(f"Error retrieving certificate attributes: {e}")

        if not matched_obj:
            if self.cert_id:
                raise RuntimeError(f"No certificate found matching cert_id={self.cert_id}")
            else:
                raise RuntimeError("No valid certificates found on the token.")

        key_id_bytes = bytes.fromhex(matched_cert_id_str)
        cert_obj = x509.load_der_x509_certificate(matched_obj, backend=default_backend())
        cert_pem = cert_obj.public_bytes(encoding=serialization.Encoding.PEM)

        logging.debug(f"Matched certificate ID = {matched_cert_id_str}")
        return key_id_bytes, cert_pem

    def _read_input_file(self, file_path: str) -> etree.Element:
        """Load and parse an XML file into an lxml Element."""
        logging.info(f"Reading input file: {file_path}")
        try:
            with open(file_path, "rb") as file:
                return etree.fromstring(file.read())
        except FileNotFoundError:
            raise RuntimeError(f"Input file not found: {file_path}")
        except etree.XMLSyntaxError as e:
            raise RuntimeError(f"Error parsing XML file: {e}")

    def _generate_output_filename(self, input_file: str) -> str:
        """Create an output path like SignedOutput/input-signed.xml."""
        filename = os.path.basename(input_file)
        base, ext = os.path.splitext(filename)
        output_filename = f"{base}-signed{ext}"
        output_filepath = os.path.join("SignedOutput", output_filename)
        return output_filepath

    def _write_output_file(self, signed_root: etree.Element, file_path: str):
        """Serialize and persist the signed XML document to disk."""
        logging.info(f"Writing signed file to: {file_path}")
        with open(file_path, "wb") as file:
            file.write(etree.tostring(signed_root))

    def _logout(self):
        """Log out of the token (if logged in) and close the session."""
        if self.session:
            logging.info("Logging out and closing the session.")
            try:
                self.session.logout()
            except PyKCS11.PyKCS11Error as e:
                logging.debug(f"Session logout failed: {e}")
            self.session.closeSession()
            self.session = None


# =============================================================================
# Utilities
# =============================================================================
def clear_screen():
    """Clear the terminal screen in a cross-platform way."""
    system = platform.system()
    if system == "Windows":
        os.system("cls")
    elif system in ("Linux", "Darwin", "FreeBSD"):
        os.system("clear")
    else:
        print("\n" * 100)


def ensure_clean_dir(path: str):
    """
    Ensure a clean output directory at 'path'.
    Removes it if present; recreates it. Raises on unrecoverable errors.
    """
    try:
        shutil.rmtree(path)
        logging.debug("Cleaned up directory: %s", path)
    except FileNotFoundError:
        logging.debug("Directory did not exist: %s", path)
    except OSError as e:
        raise RuntimeError(f"Failed to remove directory '{path}': {e}") from e

    try:
        os.makedirs(path, exist_ok=True)
        logging.debug("Created directory: %s", path)
    except OSError as e:
        raise RuntimeError(f"Failed to create directory '{path}': {e}") from e


# =============================================================================
# CLI (Improved: validation, clearer errors, safer flow)
# =============================================================================
class SafeArgumentParser(argparse.ArgumentParser):
    """Argparse with friendlier error output (prints help on error)."""
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: error: {message}\n")


def parse_arguments() -> argparse.Namespace:
    parser = SafeArgumentParser(
        description="Sign an XML file or all XML files in a directory using XML DSig or XAdES with PKCS#11."
    )
    parser.add_argument(
        "input_path", nargs="?", default=None, help="Path to the input XML file or directory."
    )
    parser.add_argument(
        "--signer_type",
        choices=["dsig", "xades"],
        default="dsig",
        help="Type of signer to use. Default: dsig",
    )
    parser.add_argument(
        "--c14n_algorithm",
        default="http://www.w3.org/2006/12/xml-c14n11",
        help="Canonicalization algorithm URI. Default: http://www.w3.org/2006/12/xml-c14n11",
    )
    parser.add_argument(
        "--cert_id",
        default=None,
        help="Hex ID of the certificate to use. If omitted, the first certificate on the token is used.",
    )
    parser.add_argument(
        "--list_certs",
        action="store_true",
        help="List all certificates on the token and exit.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging.",
    )
    parser.add_argument(
        "--log_file",
        default=None,
        help="Optional log file path (defaults to stdout only).",
    )
    parser.add_argument(
        "--slot_index",
        type=int,
        default=0,
        help="Slot index to use. Default: 0",
    )
    parser.add_argument(
        "--scap",
        action="store_true",
        help="Add SCAP-style SignatureReferences (data-stream + component ids).",
    )
    parser.add_argument(
        "--base-reference",
        dest="base_reference",
        action="store_true",
        help="Use only the root element's id/Id as the single reference.",
    )
    parser.add_argument(
        "--pkcs11_module",
        default=PKCS11_MODULE,
        help=f"Path to the PKCS#11 module (DLL/.so/.dylib). Default: '{PKCS11_MODULE}'",
    )

    args = parser.parse_args()

    # Mutual intent check: either list or sign
    if not args.list_certs and not args.input_path:
        parser.error("Either --list_certs must be specified, or an input path must be provided.")

    # Validate slot index
    if args.slot_index < 0:
        parser.error("--slot_index must be >= 0")

    # Validate PKCS#11 module path
    if not os.path.exists(args.pkcs11_module):
        parser.error(f"--pkcs11_module path does not exist: '{args.pkcs11_module}'")

    # Validate input path when signing
    if not args.list_certs and args.input_path:
        if not os.path.exists(args.input_path):
            parser.error(f"input_path does not exist: '{args.input_path}'")
        if os.path.isfile(args.input_path) and not args.input_path.lower().endswith(".xml"):
            logging.warning("Input path is a file but not .xml; continuing anyway.")

    return args


def main():
    try:
        args = parse_arguments()
        configure_logging(args.debug, args.log_file)

        logging.debug("Args parsed: %s", vars(args))

        if args.list_certs:
            # No screen clearing / directory touching for listing
            signer = Signer(
                pkcs11_module=args.pkcs11_module,
                signer_type=args.signer_type,
                c14n_algorithm=args.c14n_algorithm,
                cert_id=args.cert_id,
                slot_index=args.slot_index,
                scap=args.scap,
                base=args.base_reference,
            )
            signer.list_certs()
            return

        # Signing flow
        clear_screen()
        # Prepare output directory only when signing
        ensure_clean_dir("SignedOutput")

        signer = Signer(
            pkcs11_module=args.pkcs11_module,
            signer_type=args.signer_type,
            c14n_algorithm=args.c14n_algorithm,
            cert_id=args.cert_id,
            slot_index=args.slot_index,
            scap=args.scap,
            base=args.base_reference,
        )
        signer.sign(args.input_path)

    except SystemExit:
        # Argparse already emitted a message and exit code
        raise
    except Exception as e:
        logging.error("Fatal error: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
