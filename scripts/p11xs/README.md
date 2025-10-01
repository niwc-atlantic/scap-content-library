# p11xs — PKCS#11 XML Signer

A command-line utility for digitally signing XML files (single file or directory batch) using **PKCS#11** smart cards or HSMs. Supports **XML DSig** and **XAdES** signatures, with optional SCAP/Base reference handling.

> Portions of this software were developed at NIWC Atlantic by U.S. Government employees and are in the **public domain** (see [License](#license)).

---

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [List Certificates](#list-certificates)
  - [Sign a Single File](#sign-a-single-file)
  - [Sign All XML in a Directory](#sign-all-xml-in-a-directory)
  - [Reference Modes (SCAP / Base)](#reference-modes-scap--base)
  - [Select a Specific Certificate](#select-a-specific-certificate)
  - [All CLI Options](#all-cli-options)
- [PKCS#11 Module Paths (Examples)](#pkcs11-module-paths-examples)
- [Outputs & Verification](#outputs--verification)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [Security Notes](#security-notes)
- [License](#license)

---

## Features

- 🔐 Uses **PKCS#11** tokens (smart cards / HSMs) via [PyKCS11].
- ✍️ Generates **XML DSig** or **XAdES** signatures.
- 🧭 Flexible reference modes:
  - **SCAP**: signs `<data-stream id>` and all `<component id>` elements.
  - **Base**: signs only the root element’s `id`/`Id`.
- ✅ Verifies the signature after signing.
- 🧰 Clean CLI with helpful validations and error messages.
- 🗂️ Batch-sign all `.xml` files in a directory.

---

## Requirements

- **Python** 3.8+
- A PKCS#11 provider and token/driver (e.g., **OpenSC**)
- Runtime Python dependencies:
  - `PyKCS11`
  - `lxml`
  - `cryptography`
  - `signxml`

Create a `requirements.txt` (already included in this repo):

```
PyKCS11
lxml
cryptography
signxml
```

---

## Installation

```bash
git clone <your-repo-url>
cd p11xs
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
```

If you use a system Python without a venv, ensure you have permissions to install packages.

---

## Quick Start

1. Plug in your smart card/HSM and ensure your PKCS#11 provider is installed.
2. (Optional) List certificates to discover available IDs:

   ```bash
   python p11xs.py --pkcs11_module "<path-to-your-pkcs11-module>" --list_certs
   ```

3. Sign a file:

   ```bash
   python p11xs.py path/to/input.xml --pkcs11_module "<path-to-your-pkcs11-module>"
   ```

You’ll be prompted for your PIN. The signed file is written to `SignedOutput/<name>-signed.xml`.

---

## Usage

### List Certificates

```bash
python p11xs.py --pkcs11_module "C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll" --list_certs
```

> Lists certificate **ID**, label, subject, issuer, and serial for each token/slot.  
> Does **not** prompt for PIN and does **not** touch output directories.

### Sign a Single File

```bash
# Windows (OpenSC default path example)
python p11xs.py "C:\data\input.xml" --pkcs11_module "C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll"

# Linux
python p11xs.py /path/to/input.xml --pkcs11_module /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so

# macOS
python p11xs.py /path/to/input.xml --pkcs11_module /Library/OpenSC/lib/opensc-pkcs11.dylib
```

### Sign All XML in a Directory

```bash
python p11xs.py /path/to/xml-dir --pkcs11_module /usr/lib/opensc-pkcs11.so
```

All `.xml` files in the directory will be signed.

### Reference Modes (SCAP / Base)

- **SCAP mode**: add references for `<data-stream id>` and each `<component id>`:

  ```bash
  python p11xs.py input.xml --scap --pkcs11_module /usr/lib/opensc-pkcs11.so
  ```

- **Base mode**: use **only** the root element’s `id`/`Id`:

  ```bash
  python p11xs.py input.xml --base-reference --pkcs11_module /usr/lib/opensc-pkcs11.so
  ```

> If Base mode is enabled and the root has no `id` or `Id`, the signer falls back to default SignXML behavior.

### Select a Specific Certificate

If multiple certificates are on your token, select one by **hex ID**:

```bash
python p11xs.py input.xml --cert_id 4a3f12ab... --pkcs11_module /usr/lib/opensc-pkcs11.so
```

Obtain IDs using `--list_certs`.

### All CLI Options

```text
usage: p11xs.py [-h] [--signer_type {dsig,xades}] [--c14n_algorithm C14N]
                [--cert_id HEX] [--list_certs] [--debug] [--log_file PATH]
                [--slot_index N] [--scap] [--base-reference]
                [--pkcs11_module PATH]
                [input_path]

Sign an XML file or all XML files in a directory using XML DSig or XAdES with PKCS#11.

positional arguments:
  input_path             Path to the input XML file or directory. Required unless --list_certs is used.

options:
  -h, --help             Show this help message and exit.
  --signer_type {dsig,xades}
                         Signature profile. Default: dsig
  --c14n_algorithm C14N  Canonicalization algorithm URI. Default: http://www.w3.org/2006/12/xml-c14n11
  --cert_id HEX          Hex ID of certificate to use (else first cert on token).
  --list_certs           List certificates on the token and exit.
  --debug                Enable debug logging.
  --log_file PATH        Optional log file path (in addition to stdout).
  --slot_index N         Token slot index. Default: 0
  --scap                 Add SCAP references (data-stream + component ids).
  --base-reference       Use only the root element’s id/Id as the single reference.
  --pkcs11_module PATH   Path to PKCS#11 module (DLL/.so/.dylib). Must exist.
```

---

## PKCS#11 Module Paths (Examples)

Typical module paths (adjust per your installation):

- **Windows (OpenSC)**  
  `C:\Program Files\OpenSC Project\OpenSC\pkcs11\opensc-pkcs11.dll`

- **Linux (OpenSC)**  
  `/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so`  
  `/usr/lib/opensc-pkcs11.so`

- **macOS (OpenSC)**  
  `/Library/OpenSC/lib/opensc-pkcs11.dylib`

For vendor HSMs (Thales, Utimaco, YubiHSM, etc.), consult vendor documentation for the correct module.

---

## Outputs & Verification

- Signed files are written to:  
  **`SignedOutput/<original-name>-signed.xml`**
- The script runs a **verification step** after signing and logs success or any verification errors.

---

## Troubleshooting

- **`--pkcs11_module path does not exist`**  
  Provide the correct module for your OS/vendor (see above). Some packages install to non-standard locations.
- **`No slots with tokens found`**  
  Ensure the token is inserted and the driver is installed & running (e.g., OpenSC). Try another USB port or slot index.
- **`Invalid slot index`**  
  Use `--slot_index` within the available range (0..N-1). Some systems expose multiple readers/slots.
- **PIN prompt / login issues**  
  Some tokens require user-presence, PIN caching, or specific middleware. Check vendor documentation and confirm the token is unlocked/usable with their tooling.

> Tip: Run with `--debug` and optionally `--log_file p11xs.log` for detailed diagnostics.

---

## Development

Project layout (suggested):

```
p11xs/
├─ p11xs.py
├─ requirements.txt
├─ README.md
└─ .gitignore
```

- Code style: standard Python formatting; type hints are used in core areas.

---

## Security Notes

- Your **PIN** is read securely via `getpass` and not logged.
- Keep PKCS#11 modules and token middleware up-to-date.
- Ensure your environment (host OS, Python, dependencies) is patched and trusted.
- If signing sensitive or regulated content, validate your **canonicalization algorithm** and **signature profile** meet your compliance requirements.

---

## License

Public domain under **Title 17 U.S.C. § 105** with the following notice copied from the script header:

> The Government assumes no responsibility whatsoever for its use by other parties, and the software is provided "AS IS" without warranty or guarantee of any kind, express or implied, including, but not limited to, the warranties of merchantability and of fitness for a particular purpose. In no event shall the Government be liable for any claim, damages or other liability, whether in an action of contract, tort or other dealings in the software. The Government has no obligation hereunder to provide maintenance, support, updates, enhancements, or modifications. We would appreciate acknowledgement if the software is used. This software can be redistributed and/or modified freely provided that any derivative works bear some notice that they are derived from it, and any modified versions bear some notice that they have been modified.

---

**Happy signing!**
