# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **V3 Hidden Services**: Full client support for v3 onion services (56-character .onion addresses)
  - Ed25519 cryptographic primitives for identity keys
  - Blinded key derivation per rend-spec-v3 section 2.2
  - V3 descriptor parsing and decryption
  - HS-ntor handshake implementation
  - V3 HSDir selection algorithm
  - New relay cells: `CellRelayIntroduce1V3`, `CellRelayIntroduce2`, `CellRelayRendezvous1`
  - Comprehensive test suite (33 tests for v3 hidden services)
- **Conflux (Proposal 329)**: Full multipath circuit support
  - AIMD congestion control with sequence tracking
  - 4 traffic distribution algorithms (ROUND_ROBIN, WEIGHTED, LOWEST_LATENCY, MIN_RTT_CWND)
  - Circuit health monitoring with automatic failover
  - Out-of-order packet buffering and reordering
- **Vanguards (Proposal 292)**: Hidden service guard discovery protection
  - Bandwidth-weighted node selection from consensus
  - max(X,X) rotation distribution for longer lifetimes
  - Flag-based node replacement (Fast/Stable/Running/Valid monitoring)
  - Circuit usage tracking and statistics
  - 7 circuit purpose types with path differentiation
- **Link Protocol 5 Support**: Full implementation of TOR Link Protocol version 5
  - Added `CellPaddingNegotiate` (NUM=84) for connection padding negotiation
  - Added `CellVPadding` (NUM=128) for variable-length padding
  - Padding negotiation in handshake automatically disables link padding for performance
- **New Cell Types**: Complete implementation of missing cell types
  - Added `CellCreated` (NUM=2) - Response to CREATE cell using TAP handshake
  - Added `CellAuthenticate` (NUM=131) - Optional authentication cell
  - Added `CellAuthorize` (NUM=132) - Reserved for future use
- **Unknown Cell Handler**: Graceful handling of unrecognized cell types
  - New `CellUnknown` class provides a generic handler for unknown cells
  - Prevents crashes when connecting to relays using newer protocol features
  - Logs warnings for unknown cell types instead of raising exceptions

### Fixed
- **CellAuthChallenge deserialization**: Fixed parameter mismatch in `__init__()` causing handshake failures
- **Guard connection retry**: Improved error handling for connection timeouts and handshake failures
  - Changed error logging from ERROR to WARNING/DEBUG for expected failures
  - Added `TorSocketConnectError` and `TimeoutError` to expected exceptions list
  - Reduced noise in logs during guard selection retry process
- **Consensus download timeout**: Increased stream recv timeout from 60s to 120s to handle slow directory downloads
- **Python 3.12 Compatibility**: Full support for Python 3.12
  - Replaced deprecated `ssl.wrap_socket()` with `SSLContext.wrap_socket()`
  - Fixed SSL context configuration for TOR connections
  - Properly handles `check_hostname` requirements
- **Unit Tests**: Comprehensive test suite for new cell types
  - Tests for serialization/deserialization of all new cells
  - Tests for TorCommands registry
  - Tests for unknown cell type handling
  - Tests for protocol version support

### Changed

- Updated `TorProtocol.SUPPORTED_VERSION` to include version 5: `[3, 4, 5]`
- Improved handshake to skip unknown cells during protocol negotiation
- Enhanced error handling throughout cell socket communication

### Fixed

- Fixed `AttributeError: module 'ssl' has no attribute 'wrap_socket'` on Python 3.12
- Fixed `ValueError: check_hostname requires server_hostname` during TLS handshake
- Fixed `Exception: Cell type (84) not found` crash on unknown cell types

## [1.1.6] - 2021-XX-XX

### Previous Releases

See the [GitHub releases page](https://github.com/torpyorg/torpy/releases) for earlier version history.

---

## Version Support

| torpy Version | Python Versions | Link Protocol Versions |
|---------------|-----------------|------------------------|
| Latest (dev)  | 3.6 - 3.12      | 3, 4, 5                |
| 1.1.6         | 3.6 - 3.11      | 3, 4                   |

## Migration Guide

### Upgrading to Link Protocol 5

No code changes required. The library automatically:

1. Negotiates the highest mutually supported protocol version
2. Handles padding negotiation for protocol v5 connections
3. Falls back gracefully to v3/v4 when connecting to older relays

### Python 3.12 Compatibility

If you were using a forked version for Python 3.12 support, you can now use the standard package. The SSL connection handling has been updated to use the modern `SSLContext` API.
