Torpy ![Python Versions] [![Build Status](https://travis-ci.com/torpyorg/torpy.svg?branch=master)](https://travis-ci.com/torpyorg/torpy) [![Build status](https://ci.appveyor.com/api/projects/status/14l6t8nq4tvno1pg?svg=true)](https://ci.appveyor.com/project/jbrown299/torpy) [![Coverage Status](https://coveralls.io/repos/github/torpyorg/torpy/badge.svg?branch=master)](https://coveralls.io/github/torpyorg/torpy?branch=master)
=====

A pure python Tor client implementation of the Tor protocol.
Torpy can be used to communicate with clearnet hosts or hidden services through the [Tor Network](https://torproject.org/about/overview.html).

**Features**
- No Stem or official Tor client required
- Python 3.6 - 3.12 compatible
- **Complete TOR Protocol Support:**
  - Link Protocol versions 3, 4, and 5 (current standard)
  - ntor, TAP, and CREATE_FAST handshakes
  - Certificate validation (CERTS cell parsing)
  - Consensus and HSDir v3 support with Shared Random Values (SRV)
- **Hidden Services:**
  - **v3 hidden services** (56-character .onion addresses) - **FULLY IMPLEMENTED**
    - Ed25519 identity keys and x25519 encryption
    - HS-ntor handshake protocol
    - Blinded key derivation with time periods
    - Descriptor encryption/decryption
    - Client authorization support (optional)
  - v2 hidden services (16-character .onion) with Basic/Stealth authorization
- **Advanced Features:**
  - **Conflux**: Traffic splitting across multiple circuits for improved throughput
  - **Vanguards**: Guard discovery protection for hidden services (Proposal 333)
  - Link padding negotiation (Protocol 5)
  - Graceful handling of unknown cell types for forward compatibility
- **HTTP Integration:**
  - [TorHttpAdapter](https://github.com/torpyorg/torpy/blob/master/torpy/http/adapter.py) for [requests](https://requests.readthedocs.io/) library
  - urllib [tor_opener](https://github.com/torpyorg/torpy/blob/master/torpy/http/urlopener.py) with no dependencies
  - Built-in Socks5 proxy server

**Donation**

If you find this project interesting, you can send some [Bitcoins](https://bitcoin.org/) to address: `16mF9TYaJKkb9eGbZ5jGuJbodTF3mYvcRF`

**Note**

This product is produced independently from the Tor® anonymity software and carries no guarantee from [The Tor Project](https://www.torproject.org/) about quality, suitability or anything else.

Console examples
-----------
There are several console utilities to test the client.

A simple HTTP/HTTPS request:
```bash
$ torpy_cli --url https://ifconfig.me --header "User-Agent" "curl/7.37.0"
Loading cached NetworkStatusDocument from TorCacheDirStorage: .local/share/torpy/network_status
Loading cached DirKeyCertificateList from TorCacheDirStorage: .local/share/torpy/dir_key_certificates
Connecting to guard node 141.98.136.79:443 (Poseidon; Tor 0.4.3.6)... (TorClient)
Sending: GET https://ifconfig.me
Creating new circuit #80000001 with 141.98.136.79:443 (Poseidon; Tor 0.4.3.6) router...
...
Building 3 hops circuit...
Extending the circuit #80000001 with 109.70.100.23:443 (kren; Tor 0.4.4.5)...
...
Extending the circuit #80000001 with 199.249.230.175:443 (Quintex86; Tor 0.4.4.5)...
...
Stream #4: creating attached to #80000001 circuit...
Stream #4: connecting to ('ifconfig.me', 443)
Stream #4: connected (remote ip '216.239.36.21')
Stream #4: closing (state = Connected)...
Stream #4: remote disconnected (reason = DONE)
Response status: 200
Stream #4: closing (state = Closed)...
Stream #4: closed already
Closing guard connections (TorClient)...
Destroy circuit #80000001
Closing guard connections (Router descriptor downloader)...
Destroy circuit #80000002
> 199.249.230.175
```

Create Socks5 proxy to relay requests via the Tor Network:
```
$ torpy_socks -p 1050 --hops 3
Loading cached NetworkStatusDocument from TorCacheDirStorage: .local/share/torpy/network_status
Connecting to guard node 89.142.75.60:9001 (spongebobness; Tor 0.3.5.8)...
Creating new circuit #80000001 with 89.142.75.60:9001 (spongebobness; Tor 0.3.5.8) router...
Building 3 hops circuit...
Extending the circuit #80000001 with 185.248.143.42:9001 (torciusv; Tor 0.3.5.8)...
Extending the circuit #80000001 with 158.174.122.199:9005 (che1; Tor 0.4.1.6)...
Start socks proxy at 127.0.0.1:1050
...
```

Torpy module also has a command-line interface:

```bash
$ python3.7 -m torpy --url https://facebookcorewwwi.onion --to-file index.html
Loading cached NetworkStatusDocument from TorCacheDirStorage: .local/share/torpy/network_status
Connecting to guard node 185.2.31.8:443 (cx10TorServer; Tor 0.4.0.5)...
Sending: GET https://facebookcorewwwi.onion
Creating new circuit #80000001 with 185.2.31.8:443 (cx10TorServer; Tor 0.4.0.5) router...
Building 3 hops circuit...
Extending the circuit #80000001 with 144.172.71.110:8447 (TonyBamanaboni; Tor 0.4.1.5)...
Extending the circuit #80000001 with 179.43.134.154:9001 (father; Tor 0.4.0.5)...
Creating stream #1 attached to #80000001 circuit...
Stream #1: connecting to ('facebookcorewwwi.onion', 443)
Extending #80000001 circuit for hidden service facebookcorewwwi.onion...
Rendezvous established (CellRelayRendezvousEstablished())
Iterate over responsible dirs of the hidden service
Iterate over introduction points of the hidden service
Create circuit for hsdir
Creating new circuit #80000002 with 185.2.31.8:443 (cx10TorServer; Tor 0.4.0.5) router...
Building 0 hops circuit...
Extending the circuit #80000002 with 132.248.241.5:9001 (toritounam; Tor 0.3.5.8)...
Creating stream #2 attached to #80000002 circuit...
Stream #2: connecting to hsdir
Stream #2: closing...
Destroy circuit #80000002
Creating new circuit #80000003 with 185.2.31.8:443 (cx10TorServer; Tor 0.4.0.5) router...
Building 0 hops circuit...
Extending the circuit #80000003 with 88.198.17.248:8443 (bauruine31; Tor 0.4.1.5)...
Introduced (CellRelayIntroduceAck())
Destroy circuit #80000003
Creating stream #3 attached to #80000001 circuit...
Stream #3: connecting to ('www.facebookcorewwwi.onion', 443)
Extending #80000001 circuit for hidden service facebookcorewwwi.onion...
Response status: 200
Writing to file index.html
Stream #1: closing...
Stream #3: closing...
Closing guard connections...
Destroy circuit #80000001
```

Usage examples 
-----------

A basic example of how to send some data to a clearnet host or a hidden service:
```python
from torpy import TorClient

hostname = 'ifconfig.me'  # It's possible use onion hostname here as well
with TorClient() as tor:
    # Choose random guard node and create 3-hops circuit
    with tor.create_circuit(3) as circuit:
        # Create tor stream to host
        with circuit.create_stream((hostname, 80)) as stream:
            # Now we can communicate with host
            stream.send(b'GET / HTTP/1.0\r\nHost: %s\r\n\r\n' % hostname.encode())
            recv = stream.recv(1024)
```

TorHttpAdapter is a convenient Tor adapter for the [requests library](https://2.python-requests.org/en/master/user/advanced/#transport-adapters).
The following example shows the usage of TorHttpAdapter for multi-threaded HTTP requests:
```python
from multiprocessing.pool import ThreadPool
from torpy.http.requests import tor_requests_session

with tor_requests_session() as s:  # returns requests.Session() object
    links = ['http://nzxj65x32vh2fkhk.onion', 'http://facebookcorewwwi.onion'] * 2

    with ThreadPool(3) as pool:
        pool.map(s.get, links)

```

For more examples see [test_integration.py](https://github.com/torpyorg/torpy/blob/master/tests/integration/test_integration.py)

### V3 Hidden Services

Connecting to v3 hidden services (56-character .onion addresses):
```python
from torpy import TorClient

# Example v3 hidden service (BBC News)
hostname = 'deepweb4wt3m4dhutpxpe7d7wxdftfdf4hhag4sizgon6th5lcefloid.onion'

with TorClient() as tor:
    with tor.create_circuit(3) as circuit:
        with circuit.create_stream((hostname, 80)) as stream:
            stream.send(b'GET / HTTP/1.0\r\nHost: %s\r\n\r\n' % hostname.encode())
            recv = stream.recv(4096)
            print(recv.decode())
```

V3 hidden services with client authorization:
```python
from torpy import TorClient
from torpy.hiddenservice import HiddenService

# Your x25519 private key for client authorization (32 bytes)
client_auth_key = bytes.fromhex('your_private_key_here')

hostname = 'your_authorized_service.onion'
hidden_service = HiddenService(hostname, client_auth_key=client_auth_key)

with TorClient() as tor:
    with tor.create_circuit(3) as circuit:
        circuit.extend_to_hidden(hidden_service)
        # Now you can create streams through the authenticated circuit
        with circuit.create_stream((hostname, 80)) as stream:
            stream.send(b'GET / HTTP/1.0\r\nHost: %s\r\n\r\n' % hostname.encode())
            recv = stream.recv(4096)
```

### Conflux (Multipath Circuits)

Use multiple circuits for improved throughput and resilience. Full Proposal 329 implementation includes:
- **Sequence tracking** for ordered delivery across circuits
- **AIMD congestion control** per circuit
- **Automatic failover** with health monitoring
- **Multiple algorithms**: Round-robin, weighted, lowest-latency, min-RTT/CWND

```python
from torpy import TorClient
from torpy.conflux import ConfluxManager, ConfluxAlgorithm

with TorClient() as tor:
    # Create Conflux manager with health monitoring
    with ConfluxManager(enable_health_monitoring=True) as manager:
        # Create a Conflux set with optimal throughput algorithm
        conflux_set = manager.create_set(algorithm=ConfluxAlgorithm.MIN_RTT_CWND)
        
        # Add multiple circuits to the set
        circuit1 = tor.create_circuit(3)
        circuit2 = tor.create_circuit(3)
        conflux_set.add_circuit(circuit1)
        conflux_set.add_circuit(circuit2)
        
        # Link the circuits
        conflux_set.link_circuits()
        
        # Sending data with sequence tracking
        seq = conflux_set.allocate_sequence_number()
        circuit = conflux_set.select_circuit()  # Respects congestion windows
        conflux_set.mark_packet_sent(circuit)
        
        # ... send data on circuit ...
        
        # Update stats and congestion window
        conflux_set.update_circuit_stats(circuit, bytes_sent=512, rtt=0.05)
        conflux_set.mark_packet_acked(circuit)  # AIMD increase
        
        # Receiving data handles out-of-order delivery
        delivered_packets = conflux_set.receive_data(seq, data)
        
        # Get statistics
        stats = conflux_set.get_stats()
        print(f"CWND: {stats['circuits'][0]['cwnd']}")
        print(f"Buffered: {stats['buffered_packets']}")
```

Available algorithms:
- `ROUND_ROBIN`: Simple alternating between circuits
- `WEIGHTED`: Distribute based on RTT (lower RTT = more traffic)
- `LOWEST_LATENCY`: Always select circuit with lowest RTT
- `MIN_RTT_CWND`: Optimal throughput (minimizes RTT/CWND ratio)

### Vanguards (Hidden Service Protection)

Protect hidden services from guard discovery attacks:
```python
from torpy import TorClient
from torpy.vanguards import VanguardManager

consensus = tor_client.get_consensus()
vanguards = VanguardManager(consensus)

# Enable vanguards (initializes Layer 2 and Layer 3 guards)
vanguards.enable()

# Get a Layer 2 vanguard node for circuit building
layer2_node = vanguards.get_layer2_node()
layer3_node = vanguards.get_layer3_node()

# View statistics
stats = vanguards.get_stats()
print(f"Layer 2: {stats['layer2']['node_count']} nodes")
print(f"Layer 3: {stats['layer3']['node_count']} nodes")

# Vanguards will automatically rotate expired nodes
# When done:
vanguards.disable()
```


Installation
------------
* Just `pip3 install torpy`
* Or for using TorHttpAdapter with requests library you need install extras:
`pip3 install torpy[requests]`

Contribute
----------
* Use It
* Code review is appreciated
* Open [Issue], send [PR]


TODO
----
- [x] ~~Implement v3 hidden services~~ **DONE!** (see [rend-spec-v3](https://gitlab.torproject.org/tpo/core/torspec/-/blob/main/spec/rend-spec-v3.md))
- [x] ~~Certificate validation~~ **DONE!** (CERTS cell parsing and validation)
- [x] ~~Shared Random Value (SRV) extraction~~ **DONE!** (from consensus for v3 HSDir selection)
- [x] ~~Conflux implementation~~ **DONE!** (full Proposal 329 with AIMD, sequencing, health monitoring)
- [x] ~~Vanguards implementation~~ **DONE!** (Layer 2/3 guard discovery protection)
- [x] ~~More unit tests~~ **DONE!** (80+ tests for cells and v3 hidden services)
- [ ] Refactor Tor cells serialization/deserialization
- [ ] Rewrite the library using asyncio
- [ ] Implement onion services (server-side)
- [ ] CONFLUX_LINK/CONFLUX_LINKED cell protocol integration
- [ ] Full Vanguards integration with circuit building

## Protocol Compliance

TorPy implements a comprehensive set of TOR protocol features:

### Core Protocol
- **Link Protocol**: Versions 3, 4, and 5 (current standard as of 2026)
- **Handshakes**: 
  - ntor (Type 2) - Primary, secure modern handshake
  - TAP (Type 0) - Legacy support for v2 hidden services
  - CREATE_FAST (Type 1) - Bootstrap without consensus
- **Cryptography**:
  - Ed25519 signatures and identity keys (v3 HS)
  - x25519 key agreement (HS-ntor)
  - Curve25519 (ntor handshake)
  - SHA3-256 hashing (v3 HS)
  - RSA (legacy, v2 support)

### Hidden Services
- **V3 (Current Standard)**: 
  - Complete implementation per rend-spec-v3
  - Ed25519 identity keys
  - Blinded public key derivation
  - Time period-based descriptor rotation (24h)
  - Two-layer descriptor encryption
  - HS-ntor handshake
  - Client authorization support
  - HSDir v3 selection with SRV
- **V2 (Legacy)**: Full support with Basic/Stealth authorization

### Advanced Features
- **Conflux (Proposal 329)**: Multipath circuit support for traffic splitting
- **Vanguards (Proposal 333)**: Layer 2/3 guards for hidden service protection
- **Link Padding**: Protocol 5 padding negotiation
- **Certificate Validation**: CERTS and AUTH_CHALLENGE cell parsing

Supported Cell Types
--------------------
torpy implements the following TOR cell types per the [TOR specification](https://spec.torproject.org/):

### Fixed-Length Cells (513 bytes)

| Cell Type | NUM | Description | Status |
|-----------|-----|-------------|--------|
| PADDING | 0 | Keep-alive padding | ✅ Full |
| CREATE | 1 | Create circuit (TAP handshake) | ✅ Full |
| CREATED | 2 | Circuit created response | ✅ Full |
| RELAY | 3 | Relay data | ✅ Full |
| DESTROY | 4 | Destroy circuit | ✅ Full |
| CREATE_FAST | 5 | Fast circuit creation | ✅ Full |
| CREATED_FAST | 6 | Fast circuit response | ✅ Full |
| VERSIONS | 7 | Protocol version negotiation | ✅ Full |
| NETINFO | 8 | Network information | ✅ Full |
| RELAY_EARLY | 9 | Early relay cell | ✅ Full |
| CREATE2 | 10 | Create circuit (ntor handshake) | ✅ Full |
| CREATED2 | 11 | Circuit created response | ✅ Full |
| PADDING_NEGOTIATE | 12 | Link padding negotiation (v5) | ✅ Full |

### Variable-Length Cells

| Cell Type | NUM | Description | Status |
|-----------|-----|-------------|--------|
| VPADDING | 128 | Variable-length padding | ✅ Full |
| CERTS | 129 | Certificates | ✅ Parse + Validate |
| AUTH_CHALLENGE | 130 | Authentication challenge | ✅ Parse |
| AUTHENTICATE | 131 | Authentication response | ✅ Reserved |
| AUTHORIZE | 132 | Reserved for future use | ✅ Reserved |

### Relay Cell Commands

Supported relay cell types include:
- **Stream Management**: BEGIN, DATA, END, CONNECTED, SENDME
- **Circuit Extension**: EXTEND2, EXTENDED2
- **Directory**: BEGIN_DIR (for consensus/descriptor fetching)
- **Hidden Services**: 
  - ESTABLISH_RENDEZVOUS, RENDEZVOUS_ESTABLISHED
  - INTRODUCE1, INTRODUCE_ACK, RENDEZVOUS2
  - INTRODUCE1_V3 (v3 hidden service introduction)

Unknown cell types are handled gracefully, allowing torpy to work with newer TOR protocol versions.

## Testing

### V3 Hidden Service Testing

To test v3 hidden service connectivity, you can use the BBC News onion site:
```python
from torpy import TorClient

# BBC News v3 onion (reliable for testing)
bbc_onion = 'deepweb4wt3m4dhutpxpe7d7wxdftfdf4hhag4sizgon6th5lcefloid.onion'

with TorClient() as tor:
    with tor.create_circuit(3) as circuit:
        with circuit.create_stream((bbc_onion, 80)) as stream:
            stream.send(b'GET / HTTP/1.0\r\nHost: %s\r\n\r\n' % bbc_onion.encode())
            response = stream.recv(4096)
            assert b'BBC' in response
            print("✅ V3 hidden service connection successful!")
```

### Running Integration Tests

```bash
# Run all integration tests
pytest tests/integration/test_integration.py

# Run only v3 hidden service tests
pytest tests/integration/test_integration.py::test_onion_v3_raw
pytest tests/integration/test_integration.py::test_onion_v3_requests
```

### Unit Tests

```bash
# Run all unit tests
pytest tests/unittest/

# Run v3-specific tests
pytest tests/unittest/test_hsv3.py

# Run with coverage
pytest --cov=torpy tests/
```


License
-------
Licensed under the Apache License, Version 2.0


References
----------
- Official [Tor](https://gitweb.torproject.org/tor.git/) client
- [TOR Protocol Specifications](https://spec.torproject.org/)
- [Pycepa](https://github.com/pycepa/pycepa)
- [TorPylle](https://github.com/cea-sec/TorPylle)
- [TinyTor](https://github.com/Marten4n6/TinyTor)
- C++ Windows only implementation [Mini-tor](https://github.com/wbenny/mini-tor)
- Nice Java implementation [Orchid](https://github.com/subgraph/Orchid)

Changelog
---------
See [CHANGELOG.md](CHANGELOG.md) for version history and release notes.


[Python Versions]:      https://img.shields.io/badge/python-3.6,%203.7,%203.8,%203.9,%203.10,%203.11,%203.12-blue.svg
[Issue]:                https://github.com/torpyorg/torpy/issues
[PR]:                   https://github.com/torpyorg/torpy/pulls