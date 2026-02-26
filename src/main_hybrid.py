# IMPORTS
import os #environmental variables
import time #measuring performance
import json #storing metadata
import base64 #encoding binary into text
import sys #command line arg
from pathlib import Path #file handling

import boto3 
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization #encode public keys
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# CONFIGURATION
BUCKET = os.environ.get("HYBRID_TEST_BUCKET") or "s3-bucket-for-hybrid-crypto-project"
S3_PREFIX = "hybrid-simple/testfile" #base name
DEFAULT_TESTFILE = Path(__file__).resolve().parents[1] / "testfiles" / "test1mb.bin" #default file creation
s3 = boto3.client("s3") #creates aws client


# HELPER FUNCTIONS
#converts raw binary data into a URL-safe string
def b64(x: bytes) -> str:
    return base64.b64encode(x).decode()

#converts a Base64 string back into raw binary data
def ub64(s: str) -> bytes:
    return base64.b64decode(s.encode())

#ensure atleast one file exist to upload
def ensure_testfile(path: Path, size_bytes=1024 * 1024):
    path.parent.mkdir(parents=True, exist_ok=True) #folder creation
    if not path.exists():
        path.write_bytes(os.urandom(size_bytes)) #random file creation

#upload bytes to S3
def upload_to_s3(key: str, blob: bytes):
    t0 = time.perf_counter() #start timing
    s3.put_object(Bucket=BUCKET, Key=key, Body=blob) #upload
    elapsed = time.perf_counter() - t0 #compute upload time
    print(f"File uploaded to S3 → Bucket name: '{BUCKET}', File uploaded: '{key}'")
    return elapsed #return time taken

#download file from S3
def download_from_s3(key: str) -> tuple[bytes, float]:
    t0 = time.perf_counter() #start timing
    obj = s3.get_object(Bucket=BUCKET, Key=key)
    return obj["Body"].read(), time.perf_counter() - t0 # return file data and download time


# CRYPTOGRAPHIC FUNCTIONS
#AES function
def aes_encrypt(key, data):
    nonce = os.urandom(12) #generate 12 byte nonce
    return nonce, AESGCM(key).encrypt(nonce, data, None) #encrypt and return nonce and ciphertext

def aes_decrypt(key, nonce, ct):
    return AESGCM(key).decrypt(nonce, ct, None) #return plaintext

#RSA function
#wrap aes key via rsa public key + oaep then return encrypted AES key
def rsa_wrap(pub, key):
    return pub.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()), #oaep has in-built hash checking
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

#unwrap aes key via rsa private key + oaep then return original AES key
def rsa_unwrap(priv, wrapped):
    return priv.decrypt(
        wrapped,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()), #oaep has in-built hash checking
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

#ECC function
#Wrap AES key using ECDH
#generating ECC private and public key first
# bob - receiver; alice - sender
def ec_wrap(pub, key):
    eph_priv = ec.generate_private_key(pub.curve) #Generate EC alice's private key
    #sent to bob(in main method) to compute shared secret key
    eph_pub = eph_priv.public_key().public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint,
    ) #alice's public key
    shared = eph_priv.exchange(ec.ECDH(), pub) #compute shared secret (sender side)
 
    #run HKDF to make weak key into strong
    kek = HKDF(
        algorithm=hashes.SHA256(), 
        length=32, 
        salt=None, 
        info=b"hybrid-wrap"
    ).derive(shared)

    nonce = os.urandom(12) #nonce for wrapping aes
    wrapped = AESGCM(kek).encrypt(nonce, key, None) #encrypt aes
    return eph_pub, nonce, wrapped #return metadata

#Unwrap AES key using EC Diffie-Hellman
def ec_unwrap(priv, eph_pub, nonce, wrapped):
    #Rebuild ECC public key
    eph = ec.EllipticCurvePublicKey.from_encoded_point(priv.curve, eph_pub)
    shared = priv.exchange(ec.ECDH(), eph) #Recompute shared secret (receiver side)
 
    #run the same HKDF
    kek = HKDF(
        algorithm=hashes.SHA256(), 
        length=32, 
        salt=None, 
        info=b"hybrid-wrap"
    ).derive(shared)

    return AESGCM(kek).decrypt(nonce, wrapped, None) #Recover AES key


# RSA FLOW
def encrypt_and_upload_rsa(path, pub):
    data = Path(path).read_bytes() #read file
    size_mb = len(data) / (1024 * 1024) #compute file size
    key = AESGCM.generate_key(256) #generate aes-256 key
    
    #encrypt key + data, measure it
    t0 = time.perf_counter()
    iv, ct = aes_encrypt(key, data)
    enc_time = time.perf_counter() - t0

    #wrap aes key, measure it
    t0 = time.perf_counter()
    wrapped = rsa_wrap(pub, key)
    wrap_time = time.perf_counter() - t0

    #upload ciphertext
    up_time = upload_to_s3(f"{S3_PREFIX}-rsa.enc", ct)

    #store IV and wrapped key
    meta = {"iv": b64(iv), "wrapped": b64(wrapped)}
    
    #upload metadata
    upload_to_s3(f"{S3_PREFIX}-rsa.meta", json.dumps(meta).encode())

    #return all measurments
    return enc_time, wrap_time, up_time, size_mb

# RSA FLOW
def decrypt_download_rsa(priv):
    ct, dl_time = download_from_s3(f"{S3_PREFIX}-rsa.enc") #download ciphertext
    meta, _ = download_from_s3(f"{S3_PREFIX}-rsa.meta") #download metadata
    meta = json.loads(meta.decode()) #decode metadata

    #unwrap aes key, measure it
    t0 = time.perf_counter()
    key = rsa_unwrap(priv, ub64(meta["wrapped"]))
    unwrap_time = time.perf_counter() - t0

    #decrypt file, measure it
    t0 = time.perf_counter()
    pt = aes_decrypt(key, ub64(meta["iv"]), ct)
    dec_time = time.perf_counter() - t0

    #return all measurements
    return unwrap_time, dec_time, dl_time, pt


# ECC flow - same as RSA flow except eph, nonce
def encrypt_and_upload_ec(path, pub):
    data = Path(path).read_bytes()
    size_mb = len(data) / (1024 * 1024)

    key = AESGCM.generate_key(256)

    t0 = time.perf_counter()
    iv, ct = aes_encrypt(key, data)
    enc_time = time.perf_counter() - t0

    t0 = time.perf_counter()
    eph, nonce, wrapped = ec_wrap(pub, key)
    wrap_time = time.perf_counter() - t0

    up_time = upload_to_s3(f"{S3_PREFIX}-ec.enc", ct)

    meta = {
        "iv": b64(iv),
        "wrapped": b64(wrapped),
        "nonce": b64(nonce),
        "eph": b64(eph),
    }
    upload_to_s3(f"{S3_PREFIX}-ec.meta", json.dumps(meta).encode())

    return enc_time, wrap_time, up_time, size_mb

# ECC flow - same as RSA flow except eph, nonce
def decrypt_download_ec(priv):
    ct, dl_time = download_from_s3(f"{S3_PREFIX}-ec.enc")
    meta, _ = download_from_s3(f"{S3_PREFIX}-ec.meta")
    meta = json.loads(meta.decode())

    t0 = time.perf_counter()
    key = ec_unwrap(
        priv,
        ub64(meta["eph"]),
        ub64(meta["nonce"]),
        ub64(meta["wrapped"]),
    )
    unwrap_time = time.perf_counter() - t0

    t0 = time.perf_counter()
    pt = aes_decrypt(key, ub64(meta["iv"]), ct)
    dec_time = time.perf_counter() - t0

    return unwrap_time, dec_time, dl_time, pt


# main function
def run_minimal_demo():
    #use the file given in CLI
    if len(sys.argv) > 1:
        file = Path(sys.argv[1]).resolve()
    # else use the default file
    else:
        ensure_testfile(DEFAULT_TESTFILE)
        file = DEFAULT_TESTFILE

    #read original file
    data = file.read_bytes()

    # ---------- RSA ----------
    t0 = time.perf_counter()
    rsa_priv = rsa.generate_private_key(65537, 2048) #generate RSA private key
    rsa_pub = rsa_priv.public_key() #get public key
    rsa_keygen = time.perf_counter() - t0 #measure key generation time

    print("\n-- RSA variant --")
    #encrypt and upload
    enc, wrap, up, size = encrypt_and_upload_rsa(file, rsa_pub)
    #download and decrypt
    unwrap, dec, dl, pt = decrypt_download_rsa(rsa_priv)

    print(f"Key generation time: {rsa_keygen:.4f}s")
    print(f"Encrypt time: {enc:.4f}s")
    print(f"Throughput: {size / enc:.2f} MB/s")
    print(f"Wrap time: {wrap:.4f}s")
    print(f"Upload time: {up:.4f}s")
    print(f"Download time: {dl:.4f}s")
    print(f"Unwrap time: {unwrap:.4f}s")
    print(f"Decrypt time: {dec:.4f}s")
    print(f"OK: {pt == data}") # verify correctness

    # ---------- ECC ----------
    t0 = time.perf_counter()
    ec_priv = ec.generate_private_key(ec.SECP256R1()) #generate bob's ECC private key
    ec_pub = ec_priv.public_key() #get public key
    ec_keygen = time.perf_counter() - t0 #measure key generation time

    print("\n-- ECC variant --")
    #encrypt and upload
    enc, wrap, up, size = encrypt_and_upload_ec(file, ec_pub)
    #download and decrypt
    unwrap, dec, dl, pt = decrypt_download_ec(ec_priv)

    print(f"Key generation time: {ec_keygen:.4f}s")
    print(f"Encrypt time: {enc:.4f}s")
    print(f"Throughput: {size / enc:.2f} MB/s")
    print(f"Wrap time: {wrap:.4f}s")
    print(f"Upload time: {up:.4f}s")
    print(f"Download time: {dl:.4f}s")
    print(f"Unwrap time: {unwrap:.4f}s")
    print(f"Decrypt time: {dec:.4f}s")
    print(f"OK: {pt == data}") #verify correctness

if __name__ == "__main__":
    run_minimal_demo()