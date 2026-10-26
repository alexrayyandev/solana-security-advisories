# Security Advisory — `merkle_tree_token_claimer`

**Researcher:** Alex Rayyan (bansoslab2026@tutamail.com)
**Severity:** HIGH

## Executive Summary

The program implements a Merkle-airdrop claimer. Core accounting (checked arithmetic, PDA bump validation, ATA constraints) is mostly sound. Two issues stand out: (1) the Merkle leaf is not bound to the airdrop instance (mint / `airdrop_state`), enabling cross-instance proof replay where roots collide; (2) the unbounded `hashes: