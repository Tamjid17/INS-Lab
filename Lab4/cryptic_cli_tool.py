#!/usr/bin/env python3
"""
crypto_lab4_openssl.py

CLI wrapper that uses system OpenSSL for:
    - AES (128/256) ECB & CFB
    - RSA encrypt/decrypt
    - RSA signature/verify (SHA-256)
    - SHA-256 hashing
    - Key generation & file storage
    - Timing of operations

Usage: python3 crypto_lab4_openssl.py
"""

import os
import subprocess
import sys
import time
from pathlib import Path

# --- Default file names ---
RSA_PRIV = "rsa_private.pem"
RSA_PUB  = "rsa_public.pem"
AES_KEY_128 = "aes_key_128.key"  # binary
AES_KEY_256 = "aes_key_256.key"  # binary

# --- Helpers ---
def run(cmd, capture_output=False):
    """Run shell command (list form). Raises CalledProcessError on error."""
    if capture_output:
        return subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    else:
        return subprocess.run(cmd, check=True)

def ensure_rsa_keys(default_bits=2048):
    """Generate RSA key pair if not present."""
    if not Path(RSA_PRIV).exists() or not Path(RSA_PUB).exists():
        print(f"[+] Generating RSA keypair ({default_bits} bits)...")
        run(["openssl", "genpkey", "-algorithm", "RSA", "-out", RSA_PRIV, "-pkeyopt", f"rsa_keygen_bits:{default_bits}"])
        run(["openssl", "rsa", "-pubout", "-in", RSA_PRIV, "-out", RSA_PUB])
        print(f"[+] Saved: {RSA_PRIV}, {RSA_PUB}")
    else:
        print("[+] RSA keys already exist.")

def ensure_aes_keys():
    """Generate AES keys if not present"""
    if not Path(AES_KEY_128).exists():
        print("[+] Generating AES-128 key (16 bytes)...")
        run(["openssl", "rand", "-out", AES_KEY_128, "16"])
        print(f"[+] Saved: {AES_KEY_128}")
    else:
        print("[+] AES-128 key exists.")
    if not Path(AES_KEY_256).exists():
        print("[+] Generating AES-256 key (32 bytes)...")
        run(["openssl", "rand", "-out", AES_KEY_256, "32"])
        print(f"[+] Saved: {AES_KEY_256}")
    else:
        print("[+] AES-256 key exists.")

def hex_of_file(path):
    b = Path(path).read_bytes()
    return b.hex()

def aes_encrypt(infile, outfile, key_bits=128, mode="ecb"):
    """
    Encrypt using openssl enc.
    mode: 'ecb' or 'cfb'
    key_bits: 128 or 256
    For CFB, an IV file named outfile+'.iv' will be created (binary).
    """
    assert key_bits in (128, 256)
    algo = f"aes-{key_bits}-{mode}"
    keyfile = AES_KEY_128 if key_bits == 128 else AES_KEY_256
    key_hex = hex_of_file(keyfile)
    cmd = ["openssl", "enc", f"-{algo}", "-in", infile, "-out", outfile, "-K", key_hex]
    iv_file = None
    if mode == "cfb":
        # generate random iv (16 bytes)
        iv_file = outfile + ".iv"
        iv_bytes = os.urandom(16)
        Path(iv_file).write_bytes(iv_bytes)
        iv_hex = iv_bytes.hex()
        cmd += ["-iv", iv_hex]
    start = time.perf_counter()
    run(cmd)
    end = time.perf_counter()
    elapsed = end - start
    print(f"[+] AES encrypt done ({algo}). Output: {outfile}")
    if iv_file:
        print(f"[+] IV (binary) saved to: {iv_file}")
    print(f"[+] Time elapsed: {elapsed:.6f} seconds")
    return elapsed

def aes_decrypt(infile, outfile, key_bits=128, mode="ecb", iv_path=None):
    """
    Decrypt using openssl enc -d
    If mode == cfb, iv_path required or expects infile+'.iv'
    """
    assert key_bits in (128, 256)
    algo = f"aes-{key_bits}-{mode}"
    keyfile = AES_KEY_128 if key_bits == 128 else AES_KEY_256
    key_hex = hex_of_file(keyfile)
    cmd = ["openssl", "enc", f"-{algo}", "-d", "-in", infile, "-out", outfile, "-K", key_hex]
    if mode == "cfb":
        if iv_path is None:
            iv_path = infile + ".iv"
        if not Path(iv_path).exists():
            raise FileNotFoundError(f"IV file required for CFB decrypt: {iv_path}")
        iv_hex = Path(iv_path).read_bytes().hex()
        cmd += ["-iv", iv_hex]
    start = time.perf_counter()
    run(cmd)
    end = time.perf_counter()
    elapsed = end - start
    print(f"[+] AES decrypt done ({algo}). Output: {outfile}")
    print(f"[+] Time elapsed: {elapsed:.6f} seconds")
    return elapsed

def rsa_encrypt(infile, outfile, pubkey=RSA_PUB):
    """Encrypt using public key (pkeyutl)"""
    if not Path(pubkey).exists():
        raise FileNotFoundError("RSA public key not found.")
    cmd = ["openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey", pubkey, "-in", infile, "-out", outfile]
    start = time.perf_counter()
    run(cmd)
    end = time.perf_counter()
    elapsed = end - start
    print(f"[+] RSA encrypt done. Output: {outfile}")
    print(f"[+] Time elapsed: {elapsed:.6f} seconds")
    return elapsed

def rsa_decrypt(infile, outfile, privkey=RSA_PRIV):
    """Decrypt using private key (pkeyutl)"""
    if not Path(privkey).exists():
        raise FileNotFoundError("RSA private key not found.")
    cmd = ["openssl", "pkeyutl", "-decrypt", "-inkey", privkey, "-in", infile, "-out", outfile]
    start = time.perf_counter()
    run(cmd)
    end = time.perf_counter()
    elapsed = end - start
    print(f"[+] RSA decrypt done. Output: {outfile}")
    print(f"[+] Time elapsed: {elapsed:.6f} seconds")
    return elapsed

def rsa_sign(infile, sigfile, privkey=RSA_PRIV):
    """Sign file with RSA private key (SHA-256)"""
    if not Path(privkey).exists():
        raise FileNotFoundError("RSA private key not found.")
    cmd = ["openssl", "dgst", "-sha256", "-sign", privkey, "-out", sigfile, infile]
    start = time.perf_counter()
    run(cmd)
    end = time.perf_counter()
    elapsed = end - start
    print(f"[+] Signature created: {sigfile}")
    print(f"[+] Time elapsed: {elapsed:.6f} seconds")
    return elapsed

def rsa_verify(infile, sigfile, pubkey=RSA_PUB):
    """Verify signature. Returns True if verified, False otherwise."""
    if not Path(pubkey).exists():
        raise FileNotFoundError("RSA public key not found.")
    cmd = ["openssl", "dgst", "-sha256", "-verify", pubkey, "-signature", sigfile, infile]
    start = time.perf_counter()
    try:
        res = run(cmd, capture_output=True)
        out = res.stdout.decode().strip() if res.stdout else ""
        ok = ("Verified OK" in out) or (res.returncode == 0)
    except subprocess.CalledProcessError as e:
        # openssl prints verification result to stdout/stderr and uses exit code non-zero on fail
        out = (e.stdout or b"").decode() + (e.stderr or b"").decode()
        ok = False
    end = time.perf_counter()
    print(f"[+] Verify output:\n{out.strip()}")
    print(f"[+] Time elapsed: {end - start:.6f} seconds")
    return ok

def sha256_hash(infile):
    """Return sha256 hash printed by openssl"""
    cmd = ["openssl", "dgst", "-sha256", infile]
    res = run(cmd, capture_output=True)
    s = res.stdout.decode().strip()
    # typical format: "SHA256(filename)= <hash>"
    print(f"[+] {s}")
    return s

# --- Timing experiment helper (simple) ---
def timing_experiment_rsa_encrypt_decrypt(infile, key_sizes=(512,1024,2048,3072,4096)):
    """
    For RSA: generate keys of sizes in key_sizes, measure encrypt+decrypt times.
    Keys are temporary and removed after the experiment.
    """
    print("[*] RSA timing experiment")
    results = {}
    for size in key_sizes:
        priv = f"temp_rsa_{size}.pem"
        pub  = f"temp_rsa_{size}_pub.pem"
        print(f"[+] Generating RSA {size}-bit...")
        run(["openssl", "genpkey", "-algorithm", "RSA", "-out", priv, "-pkeyopt", f"rsa_keygen_bits:{size}"])
        run(["openssl", "rsa", "-pubout", "-in", priv, "-out", pub])
        enc_out = f"temp_enc_{size}.bin"
        dec_out = f"temp_dec_{size}.bin"
        t1 = rsa_encrypt(infile, enc_out, pub)
        t2 = rsa_decrypt(enc_out, dec_out, priv)
        results[size] = {"encrypt": t1, "decrypt": t2}
        # cleanup temp keys & files
        for p in (priv, pub, enc_out, dec_out):
            try: Path(p).unlink()
            except Exception: pass
    print("[*] RSA timing results (seconds):")
    for k,v in results.items():
        print(f"  {k}-bit: encrypt={v['encrypt']:.6f}, decrypt={v['decrypt']:.6f}")
    return results

def timing_experiment_aes_sizes(infile, key_bits_choices=(128,256), modes=("ecb","cfb")):
    """
    For AES: measure encryption/decryption times for available key sizes and modes.
    Note: AES only supports certain key sizes (128/256). This function varies mode and key.
    """
    print("[*] AES timing experiment")
    results = {}
    for kb in key_bits_choices:
        for mode in modes:
            out_enc = f"temp_aes_{kb}_{mode}.bin"
            out_dec = f"temp_aes_{kb}_{mode}.dec"
            try:
                t_enc = aes_encrypt(infile, out_enc, key_bits=kb, mode=mode)
                iv_path = out_enc + ".iv" if mode=="cfb" else None
                t_dec = aes_decrypt(out_enc, out_dec, key_bits=kb, mode=mode, iv_path=iv_path)
                results[(kb,mode)] = {"encrypt": t_enc, "decrypt": t_dec}
            finally:
                for p in (out_enc, out_enc+".iv", out_dec):
                    try: Path(p).unlink()
                    except Exception: pass
    print("[*] AES timing results (seconds):")
    for k,v in results.items():
        print(f"  {k[0]}-{k[1]}: encrypt={v['encrypt']:.6f}, decrypt={v['decrypt']:.6f}")
    return results

# --- CLI ---
def print_menu():
    print("\n=== Lab4 OpenSSL CLI ===")
    print("1) Generate keys (RSA & AES) [one-time]")
    print("2) AES encrypt file")
    print("3) AES decrypt file")
    print("4) RSA encrypt file")
    print("5) RSA decrypt file")
    print("6) RSA sign file (SHA-256)")
    print("7) RSA verify signature")
    print("8) SHA-256 hash file")
    print("9) Timing experiment (RSA key sizes)")
    print("10) Timing experiment (AES modes/key sizes)")
    print("0) Exit")

def main_loop():
    print("Lab4 OpenSSL CLI - starting")
    ensure_rsa_keys()
    ensure_aes_keys()
    while True:
        print_menu()
        choice = input("Select option: ").strip()
        try:
            if choice == "1":
                ensure_rsa_keys()
                ensure_aes_keys()
            elif choice == "2":
                infile = input("Input plaintext file path: ").strip()
                outfile = input("Output encrypted file path: ").strip()
                kb = int(input("Key bits (128 or 256): ").strip())
                mode = input("Mode ('ecb' or 'cfb'): ").strip().lower()
                aes_encrypt(infile, outfile, key_bits=kb, mode=mode)
            elif choice == "3":
                infile = input("Input encrypted file path: ").strip()
                outfile = input("Output decrypted file path: ").strip()
                kb = int(input("Key bits (128 or 256): ").strip())
                mode = input("Mode ('ecb' or 'cfb'): ").strip().lower()
                iv = None
                if mode == "cfb":
                    iv = input("IV file path (leave blank for infile+'.iv'): ").strip() or None
                aes_decrypt(infile, outfile, key_bits=kb, mode=mode, iv_path=iv)
                print("[+] Decrypted content (first 4k bytes):")
                print(Path(outfile).read_bytes()[:4096].decode(errors="replace"))
            elif choice == "4":
                infile = input("Input plaintext file path: ").strip()
                outfile = input("Output encrypted file path: ").strip()
                rsa_encrypt(infile, outfile)
            elif choice == "5":
                infile = input("Input encrypted file path: ").strip()
                outfile = input("Output decrypted file path: ").strip()
                rsa_decrypt(infile, outfile)
                print("[+] Decrypted content (first 4k bytes):")
                print(Path(outfile).read_bytes()[:4096].decode(errors="replace"))
            elif choice == "6":
                infile = input("Input file to sign: ").strip()
                sigfile = input("Signature output file (binary): ").strip()
                rsa_sign(infile, sigfile)
            elif choice == "7":
                infile = input("Original file path: ").strip()
                sigfile = input("Signature file path: ").strip()
                ok = rsa_verify(infile, sigfile)
                print("[+] Verified:" if ok else "[-] Verification failed")
            elif choice == "8":
                infile = input("File to hash: ").strip()
                sha256_hash(infile)
            elif choice == "9":
                infile = input("File to use for RSA timing (small text file): ").strip()
                # default sizes (you can edit)
                sizes = input("RSA key sizes (comma separated, default 512,1024,2048,3072,4096): ").strip() or "512,1024,2048,3072,4096"
                ks = tuple(int(x.strip()) for x in sizes.split(",") if x.strip())
                timing_experiment_rsa_encrypt_decrypt(infile, ks)
            elif choice == "10":
                infile = input("File to use for AES timing: ").strip()
                timing_experiment_aes_sizes(infile)
            elif choice == "0":
                print("Exiting.")
                break
            else:
                print("Invalid choice.")
        except subprocess.CalledProcessError as e:
            print("OpenSSL command failed.")
            print("STDOUT:", (e.stdout or b"").decode(errors="ignore"))
            print("STDERR:", (e.stderr or b"").decode(errors="ignore"))
        except Exception as e:
            print("Error:", str(e))

if __name__ == "__main__":
    try:
        main_loop()
    except KeyboardInterrupt:
        print("\nInterrupted. Bye.")
        sys.exit(0)
