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
from typing import Tuple

import PyKCS11
from lxml import etree
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from signxml import XMLSigner, XMLVerifier, SignatureReference
from signxml.xades import XAdESSigner, XAdESVerifier, XAdESDataObjectFormat

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
        handlers.append(logging.FileHandler(log_file))
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=handlers,
    )


# =============================================================================
# SignXML Interface (Minimal wrappers so SignXML can use a PKCS#11 key)
# =============================================================================
class PublicNumbers:
    """
    Container for RSA public key parameters, matching the interface expected by
    signxml/cryptography: modulus (n) and public exponent (e).
    """
    def __init__(self, n: int, e: int):
        self.n = n
        self.e = e


class PublicKey:
    """
    Simple adapter that exposes a 'public_numbers()' method so SignXML can read
    the RSA public key parameters.
    """
    def __init__(self, n: int, e: int):
        self.pubnumbers = PublicNumbers(n, e)

    def public_numbers(self) -> PublicNumbers:
        return self.pubnumbers


class Key:
    """
    A PKCS#11-backed key pair interface.

    Uses the provided session and key ID to:
      - Retrieve the public key numbers (n, e) from the token.
      - Perform signatures with the private key via CKM_SHA256_RSA_PKCS.
    """
    def __init__(self, session: PyKCS11.Session, keyid: bytes):
        logging.debug("Initializing Key object.")
        self.session = session
        self.keyid = keyid
        self.pubkey = self._get_public_key()

    def _get_public_key(self) -> PublicKey:
        """
        Retrieve the RSA public key from the token that matches self.keyid.

        Returns:
            PublicKey: Adapter exposing 'public_numbers()'.

        Raises:
            RuntimeError: If a matching public key is not found.
        """
        logging.debug("Retrieving public key from token.")
        pubkey = self.session.findObjects(
            [(PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY), (PyKCS11.CKA_ID, self.keyid)]
        )
        if not pubkey:
            raise RuntimeError("No matching public key found on the token for the given key ID.")

        pubkey = pubkey[0]
        # Extract modulus and exponent attributes and convert to Python ints.
        modulus = self.session.getAttributeValue(pubkey, [PyKCS11.CKA_MODULUS])[0]
        exponent = self.session.getAttributeValue(pubkey, [PyKCS11.CKA_PUBLIC_EXPONENT])[0]
        n = int(binascii.hexlify(bytearray(modulus)), 16)
        e = int(binascii.hexlify(bytearray(exponent)), 16)
        logging.debug("Public key retrieved: modulus (n) and exponent (e).")
        return PublicKey(n, e)

    def sign(self, data: bytes, padding, algorithm) -> bytes:
        """
        Sign pre-hashed data using the token's private key.

        Notes:
            - 'padding' and 'algorithm' parameters are present for API
              compatibility with signxml; PKCS#11 mechanism defines these.

        Args:
            data: The digest or data blob to be signed (per SignXML expectations).
            padding: Unused (controlled by PKCS#11 mechanism).
            algorithm: Unused (SHA256-RSA-PKCS is enforced).

        Returns:
            The raw signature bytes.

        Raises:
            RuntimeError: If a matching private key is not found.
        """
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
        """Return the corresponding PublicKey adapter for SignXML."""
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

    The 'scap' and 'base' flags control how SignatureReference URIs are
    gathered from the input XML.
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
        """
        List all certificates available on all present tokens/slots,
        logging key details (ID, label, subject, issuer, serial).
        """
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
        """
        Sign a single XML file, or if a directory is provided, sign every .xml
        file in that directory.

        Prompts the user for a PIN before signing to authenticate with the token.
        """
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

        Workflow:
            1) Open a session on the selected slot.
            2) Parse the input XML.
            3) Retrieve certificate and key ID.
            4) Sign the document.
            5) Write output.
            6) Verify the signature for sanity.
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

            # Generate the output filename
            output_file = self._generate_output_filename(input_file)

            # Save the signed XML document
            self._write_output_file(signed_root, output_file)

            # Verify the signature
            self._verify_signature(signed_root, cert_pem)
        finally:
            self._logout()

    def _gather_reference_uris(self, root: etree.Element) -> list[SignatureReference]:
        """
        Build a list of SignatureReference objects derived from IDs in the XML.

        Modes:
            - SCAP mode (self.scap=True):
                1) Include the 'id' attribute of the <data-stream> element, if present.
                2) Include the 'id' attribute of each <component> element, in order.
            - Base mode (self.base=True):
                Include only the 'id' or 'Id' attribute of the **root element**.
            - Default:
                No custom references are added (SignXML defaults are used).

        Returns:
            A list of SignatureReference objects (possibly empty),
            or None when Base mode is selected but no root id/Id is present.
        """
        references = []

        if self.scap:
            # 1) Add <data-stream id="..."> first (if present)
            data_stream_el = root.find(".//data-stream") or root.find(".//{*}data-stream")
            if data_stream_el is not None and "id" in data_stream_el.attrib:
                ds_id = data_stream_el.get("id")
                logging.debug(f"Found <data-stream> element with ID: {ds_id}")
                references.append(
                    SignatureReference(
                        URI=f"#{ds_id}",
                    )
                )
                logging.debug(f"Added SignatureReference for data-stream: #{ds_id}")

            # 2) Then add all <component id="..."> values
            component_els = root.findall(".//component") or root.findall(".//{*}component")
            for comp in component_els:
                if "id" in comp.attrib:
                    comp_id = comp.get("id")
                    logging.debug(f"Found <component> element with ID: {comp_id}")
                    references.append(
                        SignatureReference(
                            URI=f"#{comp_id}",
                        )
                    )
                    logging.debug(f"Added SignatureReference for component: #{comp_id}")
        elif self.base:
            # For Base mode, use the root element's id or Id (if present).
            if "id" in root.attrib:
                root_id = root.get("id")
                logging.debug(f"Found id for root element: {root_id}")
                references.append(
                    SignatureReference(
                        URI=f"#{root_id}",
                    )
                )
                logging.debug(f"Added SignatureReference for root element: #{root_id}")
            elif "Id" in root.attrib:
                root_id = root.get("Id")
                logging.debug(f"Found Id for root element: {root_id}")
                references.append(
                    SignatureReference(
                        URI=f"#{root_id}",
                    )
                )
                logging.debug(f"Added SignatureReference for root element: #{root_id}")
            else:
                references = None
                logging.debug("No ID found for root element in Base mode.")
        else:
            logging.debug("No custom SignatureReference mode selected (default).")

        if references is not None:
            logging.debug(f"Total references gathered: {len(references)}")
        return references

    def _sign(self, root: etree.Element, key: Key, cert: bytes) -> etree.Element:
        """
        Create a digital signature over the XML document.

        Behavior:
            - Chooses XML DSig or XAdES signer per 'self.signer_type'.
            - Builds custom reference URIs based on 'scap'/'base' flags.
            - Updates 'self.references' with the expected reference count for verification.
        """
        logging.info(f"Using {self.signer_type} signer for the document.")
        
        # Gather a list of SignatureReference objects from the XML file
        reference_uri = self._gather_reference_uris(root)
        self.references = len(reference_uri) if reference_uri else 1

        # Initialize the appropriate signer
        if self.signer_type == "dsig":
            signer = XMLSigner(c14n_algorithm=self.c14n_algorithm)
        elif self.signer_type == "xades":
            # In XAdES, you might be adding additional references
            # (like the signed properties), so let's add 2 more references:
            self.references += 2
            signer = XAdESSigner(c14n_algorithm=self.c14n_algorithm)
        else:
            raise ValueError(f"Unsupported signer type: {self.signer_type}")
        
        # If reference_uri is non-empty, pass it explicitly; otherwise let SignXML decide.
        if len(reference_uri) > 0:
            return signer.sign(root, key=key, cert=cert, reference_uri=reference_uri)
        else:
            return signer.sign(root, key=key, cert=cert)

    def _verify_signature(self, signed_root: etree.Element, cert: bytes):
        """
        Verify the signature of 'signed_root' using the selected verification type.

        Raises:
            ValueError: If an unsupported signer/verifier type is set.
        """
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
        """
        Securely prompt the user for a token PIN.

        Returns:
            The PIN string provided by the user (no echo on terminal).
        """
        return getpass.getpass("Enter your PIN: ")

    def _get_slot(self) -> int:
        """
        Resolve the slot index to use for session/login.

        Returns:
            The slot number at 'self.slot_index'.

        Raises:
            RuntimeError: If no tokens are present.
            ValueError: If the configured slot index is out of bounds.
        """
        logging.info("Retrieving available slots.")
        slots = self.pkcs11.getSlotList(tokenPresent=True)
        if not slots:
            raise RuntimeError("No slots with tokens found.")
        if self.slot_index < 0 or self.slot_index >= len(slots):
            raise ValueError(f"Invalid slot index: {self.slot_index}. Available slots: {len(slots)}")
        return slots[self.slot_index]

    def _open_session(self, slot: int, pin: str) -> PyKCS11.Session:
        """
        Open a (read-write) PKCS#11 session for the given slot and optionally log in.

        Args:
            slot: Slot number to open a session on.
            pin: If provided, will log in immediately.

        Returns:
            A PyKCS11.Session object.
        """
        logging.info(f"Opening a session with the token in slot: {slot}.")
        session = self.pkcs11.openSession(slot, PyKCS11.CKF_SERIAL_SESSION | PyKCS11.CKF_RW_SESSION)
        if pin:
            session.login(pin)
            logging.debug("Session opened and logged in successfully.")
        return session

    def _get_cert(self) -> Tuple[bytes, bytes]:
        """
        Retrieve a certificate and its corresponding key ID from the token.

        Selection logic:
            - If --cert_id is provided, match against that hex ID.
            - Otherwise, return the first certificate found.

        Returns:
            (key_id_bytes, cert_pem):
                key_id_bytes: Raw key ID (bytes) used to locate keys on the token.
                cert_pem: PEM-encoded certificate bytes.

        Raises:
            RuntimeError: If no certificate is found or no match for --cert_id.
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

        # Convert the hex certificate ID to raw bytes (used as CKA_ID when locating keys).
        key_id_bytes = bytes.fromhex(matched_cert_id_str)

        # Convert DER certificate to PEM for use by SignXML verifiers.
        cert_obj = x509.load_der_x509_certificate(matched_obj, backend=default_backend())
        cert_pem = cert_obj.public_bytes(encoding=serialization.Encoding.PEM)

        logging.debug(f"Matched certificate ID = {matched_cert_id_str}")
        return key_id_bytes, cert_pem

    def _read_input_file(self, file_path: str) -> etree.Element:
        """
        Load and parse an XML file into an lxml Element.

        Raises:
            RuntimeError: If the file is missing or XML parsing fails.
        """
        logging.info(f"Reading input file: {file_path}")
        try:
            with open(file_path, "rb") as file:
                return etree.fromstring(file.read())
        except FileNotFoundError:
            raise RuntimeError(f"Input file not found: {file_path}")
        except etree.XMLSyntaxError as e:
            raise RuntimeError(f"Error parsing XML file: {e}")

    def _generate_output_filename(self, input_file: str) -> str:
        """
        Create an output path for the signed file in 'SignedOutput', e.g.:
            input.xml -> SignedOutput/input-signed.xml
        """
        filename = os.path.basename(input_file)
        base, ext = os.path.splitext(filename)
        output_filename = f"{base}-signed{ext}"
        output_filepath = os.path.join("SignedOutput", output_filename)
        return output_filepath

    def _write_output_file(self, signed_root: etree.Element, file_path: str):
        """
        Serialize and persist the signed XML document to disk.
        """
        logging.info(f"Writing signed file to: {file_path}")
        with open(file_path, "wb") as file:
            file.write(etree.tostring(signed_root))

    def _logout(self):
        """
        Log out of the token (if logged in) and close the session. Safe to call
        multiple times; guards against missing/closed sessions.
        """
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
    """
    Clear the terminal screen in a cross-platform way.

    Primarily cosmetic; keeps CLI output tidy between runs.
    """
    system = platform.system()
    if system == "Windows":
        os.system("cls")
    elif system in ("Linux", "Darwin", "FreeBSD"):
        os.system("clear")
    else:
        print("\n" * 100)


def clean_up(path):
    """
    Ensure a clean output directory at 'path'.

    Behavior:
        - Remove the directory if it exists (recursively).
        - Re-create the directory.

    Prints status messages to stdout; exits on non-recoverable OS errors.
    """
    try:
        shutil.rmtree(path)
        print("Cleaned up: " + path)
    except FileNotFoundError:
        print("Directory: " + path + " does not exist")
    except OSError as e:
        print("Error: Failed to remove directory: " + path + " error: " + e)
        exit()

    try:
        os.makedirs(path)
        print("Created directory: " + path)
    except OSError as e:
        print("Error: failed to create directory: " + path + " error: " + e)
        exit()


# =============================================================================
# CLI Entrypoint
# =============================================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Sign an XML file or all XML files in a directory using XML DSig or XAdES with PKCS#11."
    )
    parser.add_argument(
        "input_path", nargs="?", default=None, help="Path to the input XML file or directory."
    )
    parser.add_argument(
        "--signer_type",
        choices=["dsig", "xades"],
        default="dsig",
        help="Type of signer to use for signing. Default is dsig.",
    )
    parser.add_argument(
        "--c14n_algorithm",
        default="http://www.w3.org/2006/12/xml-c14n11",
        help="Canonicalization algorithm to use. Default is http://www.w3.org/2006/12/xml-c14n11.",
    )
    parser.add_argument(
        "--cert_id",
        default=None,
        help=(
            "Hex string ID of the certificate to use for signing. "
            "If not specified, the first certificate found on the token is used."
        ),
    )
    parser.add_argument(
        "--list_certs",
        action="store_true",
        help="List all certificates on the card and exit.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging.",
    )
    parser.add_argument(
        "--log_file",
        default=None,
        help="File to save logs. Defaults to stdout only.",
    )
    parser.add_argument(
        "--slot_index",
        type=int,
        default=0,
        help="Index of the slot to use for signing. Default is 0.",
    )
    parser.add_argument(
        "--scap",
        action="store_true",
        help="If set, adds custom SignatureReference objects at signing time (SCAP mode).",
    )
    parser.add_argument(
        "--base-reference",
        action="store_true",
        help="If set, adds as the only reference the id or Id of the root element.",
    )
    parser.add_argument(
        "--pkcs11_module",
        default=PKCS11_MODULE,
        help=(
            "Path to the PKCS#11 module (DLL or shared library). "
            f"Defaults to '{PKCS11_MODULE}'."
        ),
    )

    # Cosmetic cleanup and ensure output directory exists
    clear_screen()
    clean_up("SignedOutput")

    args = parser.parse_args()

    configure_logging(args.debug, args.log_file)

    logging.debug("input_path: " + str(args.input_path))

    signer = Signer(
        pkcs11_module=args.pkcs11_module,
        signer_type=args.signer_type,
        c14n_algorithm=args.c14n_algorithm,
        cert_id=args.cert_id,
        slot_index=args.slot_index,
        scap=args.scap,
        base=args.base_reference,
    )

    if args.list_certs:
        signer.list_certs()
    elif args.input_path:
        signer.sign(args.input_path)
    else:
        parser.error("Either --list_certs must be specified, or an input path must be provided.")
