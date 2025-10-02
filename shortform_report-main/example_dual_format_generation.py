"""
Example script demonstrating dual-format SFR generation (JSON and CoRIM).

This script shows how to use the ExtendedShortFormReport class to generate
Security Findings Reports in both the original JSON format and the new
CoRIM (CBOR) format that complies with the OCP SAFE SFR CDDL schema.

Author: Extended from Jeremy Boone's original example
Date  : January 2025
"""

from OcpReportLib import ShortFormReport
import traceback
import sys
import json
import hashlib
import os

# Test key configuration (same as original example)
MY_PRIV_KEY = "testkey_p521.pem"
MY_PUB_KEY = "testkey_ecdsa_p521.pub"
MY_SIGN_ALGO = "ES512"
MY_KID = "Wile E Coyote"

def generate_test_keys():
    """Generate test keys if they don't exist."""
    if not os.path.exists(MY_PRIV_KEY):
        print("Generating test ECDSA P-521 key pair...")
        os.system(f"openssl ecparam -name secp521r1 -genkey -noout -out {MY_PRIV_KEY}")
        os.system(f"openssl ec -in {MY_PRIV_KEY} -pubout -out {MY_PUB_KEY}")
        print(f"Generated {MY_PRIV_KEY} and {MY_PUB_KEY}")

def main():
    print("=== OCP SAFE SFR Dual-Format Generation Example ===\n")
    
    # Generate test keys if needed
    generate_test_keys()
    
    # Create the report object
    rep = ShortFormReport(framework_ver="1.1")
    
    # Add device information (same API as original SFR generation library)
    fw_hash_sha384 = "cd484defa77e8c3e4a8dd73926e32365ea0dbd01e4eff017f211d4629cfcd8e4890dd66ab1bded9be865cd1c849800d4"
    fw_hash_sha512 = "84635baabc039a8c74aed163a8deceab8777fed32dc925a4a8dacfd478729a7b6ab1cb91d7d35b49e2bd007a80ae16f292be3ea2b9d9a88cb3cc8dff6a216988"
    
    rep.add_device(
        "ACME Inc",         # vendor name
        "Roadrunner Trap",  # product name
        "storage",          # device category
        "release_v1_2_3",   # repo tag
        "1.2.3",            # firmware version
        fw_hash_sha384,     # SHA-384 hash
        fw_hash_sha512      # SHA-512 hash
    )
    
    # Add audit information
    rep.add_audit(
        "My Pentest Corporation",  # SRP name
        "whitebox",               # Test methodology
        "2023-06-25",            # Test completion date
        "1.2",                   # Report version
        1,                       # The OCP SAFE scope level
    )
    
    # Add security issues
    rep.add_issue(
        "Memory corruption when reading record from SPI flash",
        "7.9",
        "AV:L/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:L",
        "CWE-111",
        "Due to insufficient input validation in the firmware, a local"
        " attacker who tampers with a configuration structure in"
        " SPI flash, can cause stack-based memory corruption."
    )
    
    rep.add_issue(
        "Debug commands enable arbitrary memory read/write",
        "8.7",
        "AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L",
        "CWE-222",
        "The firmware exposes debug command handlers that enable host-side"
        " drivers to read and write arbitrary regions of the device's"
        " SRAM.",
        cve="CVE-2014-10000"
    )
    
    print("=== JSON FORMAT OUTPUT ===")
    print(rep.get_report_as_str())
    
    print("\n=== CoRIM FORMAT OUTPUT ===")
    try:
        corim_dict = rep.get_report_as_corim_dict()
        print("CoRIM structure (Python dict):")
        print(json.dumps(corim_dict, indent=2, default=str))
        
        corim_cbor = rep.get_report_as_corim_cbor()
        print(f"\nCoRIM CBOR bytes ({len(corim_cbor)} bytes):")
        print(corim_cbor.hex())
        
        # Save CoRIM to file
        with open("example_report.cbor", "wb") as f:
            f.write(corim_cbor)
        print(f"\nCoRIM saved to: example_report.cbor")
        
    except Exception as e:
        print(f"Error generating CoRIM: {e}")
        traceback.print_exc()
    
    print("\n=== SIGNING DEMONSTRATION ===")
    
    # Load private key
    try:
        with open(MY_PRIV_KEY, "rb") as f:
            privkey = f.read()
    except FileNotFoundError:
        print(f"Private key file {MY_PRIV_KEY} not found. Please generate keys first.")
        return
    
    # Save JSON report (unsigned)
    print("Saving JSON report...")
    json_report = rep.get_report_as_str()
    with open("example_report.json", "w") as f:
        f.write(json_report)
    print("JSON report saved to: example_report.json")
    
    # Sign JSON format (original method)
    print("\nSigning JSON report...")
    success = rep.sign_report(privkey, MY_SIGN_ALGO, MY_KID)
    if success:
        signed_json = rep.get_signed_report()
        print(f"JSON JWS signature created ({len(signed_json)} bytes)")
        
        # Save signed JSON
        with open("example_report.jws", "w") as f:
            f.write(signed_json.decode() if isinstance(signed_json, bytes) else signed_json)
        print("Signed JSON saved to: example_report.jws")
    else:
        print("Failed to sign JSON report")
    
    # Sign CoRIM format (new method)
    print("\nSigning CoRIM report...")
    try:
        success = rep.sign_corim(privkey, MY_SIGN_ALGO, MY_KID)
        if success:
            signed_corim = rep.get_signed_corim()
            print(f"CoRIM COSE-Sign1 signature created ({len(signed_corim)} bytes)")
            
            # Save signed CoRIM
            with open("example_report_signed.cbor", "wb") as f:
                f.write(signed_corim)
            print("Signed CoRIM saved to: example_report_signed.cbor")
        else:
            print("Failed to sign CoRIM report")
    except Exception as e:
        print(f"Error signing CoRIM: {e}")
        print("Note: CoRIM signing requires 'cwt' library. Install with: pip install cwt")
    
    print("\n=== VERIFICATION DEMONSTRATION ===")
    
    # Verify JSON signature
    if success and os.path.exists(MY_PUB_KEY):
        try:
            with open(MY_PUB_KEY, "rb") as f:
                pubkey = f.read()
            
            print("Verifying JSON signature...")
            rep.verify_signed_report(signed_json, pubkey)
            print("JSON signature verification: SUCCESS")
            
        except Exception as e:
            print(f"JSON verification failed: {e}")
    
    print("\n=== FORMAT COMPARISON ===")
    
    # Compare file sizes
    files_info = []
    for filename in ["example_report.json", "example_report.cbor", "example_report.jws", "example_report_signed.cbor"]:
        if os.path.exists(filename):
            size = os.path.getsize(filename)
            files_info.append((filename, size))
    
    if files_info:
        print("File size comparison:")
        for filename, size in files_info:
            print(f"  {filename}: {size} bytes")
    
    print("\n=== SUMMARY ===")
    print("✓ JSON format: Backward compatible, uses JWS signing")
    print("✓ CoRIM format: New CBOR format, uses COSE-Sign1 signing")
    print("✓ Same API: Existing code works unchanged")
    print("✓ Dual output: Generate both formats from same data")
    
    print("\nFiles generated:")
    for filename in ["example_report.json", "example_report.cbor", "example_report.jws", "example_report_signed.cbor"]:
        if os.path.exists(filename):
            print(f"  ✓ {filename}")

if __name__ == "__main__":
    main()
