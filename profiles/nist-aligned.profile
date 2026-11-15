# Length-first, blocklist-based policy in the spirit of NIST SP 800-63B.
# Verify the minimum-length figure against the current revision for your
# assurance level (it differs between single-factor and MFA use).
policy_min_length=15
policy_max_length=128
policy_require_classes=0
policy_block_common=1
policy_min_entropy_bits=45
hash_allow_legacy=0
hash_min_bcrypt_cost=12
hash_min_pbkdf2_iterations=600000
hash_min_argon2_mib=46
hash_min_argon2_time=2
hash_min_shacrypt_rounds=250000
wordlist_warn_dup_pct=5
mfa_min_totp_digits=6
mfa_max_totp_window=1
mfa_max_attempts=5
mfa_require_phishing_resistant=1
mfa_min_recovery_entropy_bits=80
session_min_entropy_bits=128
session_max_idle_min=15
session_max_absolute_min=480
reset_min_entropy_bits=128
reset_max_token_ttl_min=15
reset_max_requests_per_hour=3
