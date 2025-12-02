# Anonymous-human-validation-on-decentralized-blockchain
Decentralized anonymous human verification system using distributed consensus and cryptographic credentials. Proves unique humanness without revealing identity through biometric hashing, Byzantine fault-tolerant validator network, and service-specific key derivation. Combats bot networks while preserving privacy.

## About

This project demonstrates a decentralized solution to one of the internet's most pressing problems: distinguishing real humans from sophisticated bot networks operated by nation-states and commercial actors.

### The Problem

Nation-state actors and commercial bot farms deploy thousands of fake accounts to manipulate online discourse, spread propaganda, and undermine democratic processes. Current verification methods (phone numbers, email, CAPTCHA) are easily defeated at scale or compromise user privacy.

### Our Solution

A cryptographically secure system that proves someone is a unique verified human without revealing their identity. Users verify once using biometric data, receive an anonymous credential, and can access multiple services while remaining unlinkable across platforms.

### Key Features

- **Privacy-Preserving**: Services verify you're human without learning who you are
- **Uniqueness Enforcement**: Biometric hashing ensures one verification per person
- **Byzantine Fault Tolerant**: Distributed validator network (3 of 5 consensus) prevents single points of failure
- **Cross-Service Unlinkability**: Deterministic key derivation creates different identities per service
- **Decentralized**: No central authority controls the verification process

### Technical Architecture

- **ECDSA P-256** cryptographic keypairs for user identity
- **SHA-256** biometric hashing for uniqueness proofs
- **Distributed consensus** with configurable threshold (60% in demo)
- **Challenge-response** protocol prevents credential theft
- **Service-specific key derivation** ensures privacy across platforms

### What's Included

This repository contains a working proof-of-concept with:
- 5 independent validator nodes (Node.js/Express)
- Browser-based client application (HTML/JavaScript/Web Crypto API)
- Complete verification workflow from keypair generation to service access
- Real-time consensus visualization
- Comprehensive documentation of cryptographic operations

### Use Cases

- Social media platforms combating bot networks
- Online voting systems requiring one-person-one-vote
- Anonymous forums preventing astroturfing
- Fair token airdrops and distributions
- Any service needing to verify unique humans while preserving privacy

### Demo Setup

The system runs locally with 5 validator VMs communicating over a host-only network. Each validator independently votes on verification requests, and credentials are only issued when consensus (3/5 approvals) is reached.

This is a functional proof-of-concept demonstrating the core technical feasibility. Production deployment would require additional security hardening, real biometric capture with liveness detection, hardware security modules for key storage, and a larger validator network.
