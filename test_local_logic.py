"""
Local-only test: proves chunking + convergent encryption works correctly
WITHOUT needing AWS credentials. Run this first to sanity-check the core
logic before wiring it to your real S3/DynamoDB.
"""
from dedup_core import cdc_chunks, derive_key, tag_of, encrypt_chunk, decrypt_chunk
from speck_cipher import speck_encrypt, speck_decrypt

# Simulate two files that share a lot of duplicate content
file_a = b"AAAA" * 3000 + b"unique-to-file-a-only-data-here" + b"BBBB" * 2000
file_b = b"AAAA" * 3000 + b"totally-different-unique-part!!" + b"BBBB" * 2000

for name, data in [("file_a", file_a), ("file_b", file_b)]:
    chunks = cdc_chunks(data)
    print(f"{name}: {len(data)} bytes -> {len(chunks)} chunks")
    for i, c in enumerate(chunks):
        k, ct, tag = encrypt_chunk(c)
        print(f"  chunk {i}: {len(c)} bytes, tag={tag[:12]}...")

# Verify convergent encryption: identical chunk content -> identical ciphertext tag
chunks_a = cdc_chunks(file_a)
chunks_b = cdc_chunks(file_b)

tags_a = {encrypt_chunk(c)[2] for c in chunks_a}
tags_b = {encrypt_chunk(c)[2] for c in chunks_b}
shared = tags_a & tags_b
print(f"\nShared (duplicate) chunk tags between file_a and file_b: {len(shared)}")

# Confirm same content always produces same ciphertext under convergent encryption
sample_chunk = chunks_a[0]
key1, ct1, tag1 = encrypt_chunk(sample_chunk)
key2, ct2, tag2 = encrypt_chunk(sample_chunk)
assert key1 == key2, "Convergent key derivation is not deterministic!"
assert ct1 == ct2, "Same content should produce identical ciphertext!"
assert tag1 == tag2, "Same content should produce identical tag!"
print("Convergent encryption determinism check: PASSED")

# Confirm decryption recovers original chunk
recovered = decrypt_chunk(ct1, key1)
assert recovered == sample_chunk, "Decryption did not recover original chunk!"
print("Encrypt -> decrypt round-trip check: PASSED")

print("\nAll local logic tests passed. Safe to proceed to AWS integration.")
