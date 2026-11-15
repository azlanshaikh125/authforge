#!/usr/bin/env bash
# shellcheck shell=bash disable=SC2034
# AUTHFORGE core: constants and exit-code contract.
[[ -n "${_AN_CONSTANTS:-}" ]] && return 0
_AN_CONSTANTS=1

readonly AN_NAME="AUTHFORGE"
readonly AN_VERSION="0.1.0"
readonly AN_TAGLINE="ENTERPRISE SECURITY ENGINE"

# Exit-code contract (documented in docs/ARCHITECTURE.md)
readonly EX_OK=0
readonly EX_GENERAL=1
readonly EX_USAGE=2
readonly EX_CONFIG=3
readonly EX_DEPENDENCY=4
readonly EX_AUTHZ=5
readonly EX_VALIDATION=6
readonly EX_FINDINGS=10     # findings at/above --fail-on threshold
readonly EX_INTERRUPT=130

# Severity / confidence vocabularies (index = rank)
readonly -a AN_SEVERITIES=(INFO LOW MEDIUM HIGH CRITICAL)
readonly -a AN_CONFIDENCES=(LOW MEDIUM HIGH)

# Compliance control evaluation statuses and frameworks (M5-P1)
readonly -a AN_COMPLIANCE_STATUSES=(PASS PARTIAL FAIL "NOT TESTED" "N/A")
readonly -a AN_COMPLIANCE_FRAMEWORKS=(ASVS NIST CIS)
