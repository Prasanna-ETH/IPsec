"""
Standardized Cryptographic Lookups for IKEv1, IKEv2, ESP, and Child SAs.
References:
- RFC 7296 (IKEv2)
- RFC 8247 (IKEv2 Cryptographic Algorithms)
- RFC 8221 (ESP Cryptographic Algorithms)
- RFC 2409 (IKEv1)
- NIST SP 800-77 Rev. 1
"""

# IKEv2 Transform Types (RFC 7296 Sec 3.3.2)
TRANSFORM_TYPES = {
    1: "ENCR",  # Encryption Algorithm
    2: "PRF",   # Pseudo-random Function
    3: "INTEG", # Integrity Algorithm
    4: "D-H",   # Diffie-Hellman Group
    5: "ESN",   # Extended Sequence Numbers
}

# IKEv2 Encryption Transform IDs (RFC 8247)
ENCR_TRANSFORMS = {
    1: ("DES-IV64", "DEPRECATED"),
    2: ("DES", "DEPRECATED"),
    3: ("3DES-CBC", "DEPRECATED"),
    4: ("RC5", "DEPRECATED"),
    5: ("IDEA", "DEPRECATED"),
    6: ("CAST", "DEPRECATED"),
    7: ("Blowfish", "DEPRECATED"),
    8: ("3IDEA", "DEPRECATED"),
    9: ("DES-IV32", "DEPRECATED"),
    11: ("NULL", "INSECURE"),
    12: ("AES-CBC", "ACCEPTABLE"),
    13: ("AES-CTR", "ACCEPTABLE"),
    18: ("AES-CCM-8", "ACCEPTABLE"),
    19: ("AES-CCM-12", "ACCEPTABLE"),
    20: ("AES-CCM-16", "ACCEPTABLE"),
    28: ("AES-GCM-16", "RECOMMENDED"),
    29: ("AES-GCM-12", "ACCEPTABLE"),
    30: ("AES-GCM-8", "DEPRECATED"),
    36: ("CHACHA20-POLY1305", "RECOMMENDED"),
}

# IKEv2 PRF Transform IDs (RFC 8247)
PRF_TRANSFORMS = {
    1: ("PRF_HMAC_MD5", "DEPRECATED"),
    2: ("PRF_HMAC_SHA1", "DEPRECATED"),
    3: ("PRF_HMAC_TIGER", "DEPRECATED"),
    4: ("PRF_AES128_XCBC", "ACCEPTABLE"),
    5: ("PRF_HMAC_SHA2_256", "RECOMMENDED"),
    6: ("PRF_HMAC_SHA2_384", "RECOMMENDED"),
    7: ("PRF_HMAC_SHA2_512", "RECOMMENDED"),
    8: ("PRF_AES128_CMAC", "ACCEPTABLE"),
}

# IKEv2 Integrity Transform IDs (RFC 8247)
INTEG_TRANSFORMS = {
    0: ("NONE", "INFORMATIONAL"),
    1: ("AUTH_HMAC_MD5_96", "DEPRECATED"),
    2: ("AUTH_HMAC_SHA1_96", "DEPRECATED"),
    3: ("AUTH_DES_MAC", "DEPRECATED"),
    4: ("AUTH_KPDK_MD5", "DEPRECATED"),
    5: ("AUTH_AES_XCBC_96", "ACCEPTABLE"),
    12: ("AUTH_HMAC_SHA2_256_128", "RECOMMENDED"),
    13: ("AUTH_HMAC_SHA2_384_192", "RECOMMENDED"),
    14: ("AUTH_HMAC_SHA2_512_256", "RECOMMENDED"),
}

# Diffie-Hellman Group IDs (RFC 8247 / RFC 7296)
DH_GROUPS = {
    1: ("Group 1 (MODP-768)", "CRITICAL_LEGACY"),
    2: ("Group 2 (MODP-1024)", "LEGACY_WEAK"),
    5: ("Group 5 (MODP-1536)", "LEGACY_WEAK"),
    14: ("Group 14 (MODP-2048)", "RECOMMENDED_MINIMUM"),
    15: ("Group 15 (MODP-3072)", "RECOMMENDED"),
    16: ("Group 16 (MODP-4096)", "RECOMMENDED"),
    17: ("Group 17 (MODP-6144)", "RECOMMENDED"),
    18: ("Group 18 (MODP-8192)", "RECOMMENDED"),
    19: ("Group 19 (ECP-256 / NIST P-256)", "RECOMMENDED"),
    20: ("Group 20 (ECP-384 / NIST P-384)", "RECOMMENDED"),
    21: ("Group 21 (ECP-521 / NIST P-521)", "RECOMMENDED"),
    28: ("Group 28 (BrainpoolP256r1)", "RECOMMENDED"),
    29: ("Group 29 (BrainpoolP384r1)", "RECOMMENDED"),
    30: ("Group 30 (BrainpoolP512r1)", "RECOMMENDED"),
    31: ("Group 31 (Curve25519)", "RECOMMENDED"),
}

# IKEv2 Exchange Types (RFC 7296)
IKEV2_EXCHANGES = {
    34: "IKE_SA_INIT",
    35: "IKE_AUTH",
    36: "CREATE_CHILD_SA",
    37: "INFORMATIONAL",
    38: "IKE_SESSION_RESUME",
}

# IKEv1 Exchange Types (RFC 2409)
IKEV1_EXCHANGES = {
    1: "None",
    2: "Base",
    3: "Identity_Protection (Main Mode)",
    4: "Authentication_Only",
    5: "Aggressive",
    6: "Informational",
    32: "Quick_Mode",
    33: "New_Group_Mode",
}

def get_encr_name(transform_id: int) -> tuple[str, str]:
    return ENCR_TRANSFORMS.get(transform_id, (f"ENCR_UNKNOWN_{transform_id}", "UNKNOWN"))

def get_prf_name(transform_id: int) -> tuple[str, str]:
    return PRF_TRANSFORMS.get(transform_id, (f"PRF_UNKNOWN_{transform_id}", "UNKNOWN"))

def get_integ_name(transform_id: int) -> tuple[str, str]:
    return INTEG_TRANSFORMS.get(transform_id, (f"INTEG_UNKNOWN_{transform_id}", "UNKNOWN"))

def get_dh_name(group_id: int) -> tuple[str, str]:
    return DH_GROUPS.get(group_id, (f"DH_Group_{group_id}", "UNKNOWN"))

def assess_proposal(encr: str, prf: str, integ: str, dh: str) -> str:
    """Classify overall proposal posture based on NIST SP 800-77 and RFC 8247."""
    critical_terms = ["3DES", "DES", "NULL", "MD5", "Group 1", "MODP-768"]
    weak_terms = ["SHA1", "Group 2", "Group 5", "MODP-1024", "MODP-1536"]
    
    combined = f"{encr} {prf} {integ} {dh}"
    for term in critical_terms:
        if term in combined:
            return "CRITICAL_LEGACY"
    for term in weak_terms:
        if term in combined:
            return "LEGACY_WEAK"
    return "COMPLIANT"
