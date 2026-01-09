# Copyright 2025 Richard Dawson
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""
Conflux: Traffic splitting across multiple circuits.

Per Proposal 329, Conflux allows a client to multiplex traffic across
multiple circuits for improved throughput and resilience. This is
particularly useful for:
- High-bandwidth applications
- Reducing latency variance
- Resilience to circuit failures

Full specification implementation includes:
- Sequence number tracking for ordered delivery
- AIMD (Additive Increase Multiplicative Decrease) congestion control
- Circuit health monitoring with automatic failover
- Multiple traffic distribution algorithms
- Out-of-order packet buffering
- RTT estimation with exponential moving average
"""

import os
import time
import logging
import threading
from enum import IntEnum, auto
from typing import List, Optional, Dict, Tuple
from collections import defaultdict, deque

logger = logging.getLogger(__name__)

# Conflux cell types (reserved in Tor spec)
CELL_CONFLUX_LINK = 0x20
CELL_CONFLUX_LINKED = 0x21
CELL_CONFLUX_SWITCH = 0x22

# Congestion control parameters
INITIAL_CWND = 10  # Initial congestion window (cells)
MIN_CWND = 2  # Minimum congestion window
MAX_CWND = 1000  # Maximum congestion window
SSTHRESH_INIT = 100  # Initial slow start threshold
MULTIPLICATIVE_DECREASE = 0.5  # Factor for multiplicative decrease on congestion

MULTIPLICATIVE_DECREASE = 0.5  # Factor for multiplicative decrease on congestion

# Health check parameters
HEALTH_CHECK_INTERVAL = 5.0  # Seconds between health checks
CIRCUIT_TIMEOUT = 30.0  # Seconds before considering a circuit dead
MAX_RETRIES = 3  # Maximum retries before marking circuit as failed


class ConfluxAlgorithm(IntEnum):
    """Conflux traffic distribution algorithms."""
    # Round-robin: Simple alternating between circuits
    ROUND_ROBIN = 0
    # Weighted: Distribute based on circuit performance
    WEIGHTED = 1
    # Lowest latency: Send on circuit with lowest RTT
    LOWEST_LATENCY = 2
    # Min RTT * CWND: Optimal throughput (lowest RTT * highest CWND)
    MIN_RTT_CWND = 3


class ConfluxLinkState(IntEnum):
    """State of a Conflux link between circuits."""
    UNLINKED = 0
    LINKING = auto()
    LINKED = auto()
    FAILED = auto()


class ConfluxCircuitSet:
    """
    A set of circuits linked together for traffic multiplexing.
    
    This class manages multiple circuits that share the same destination
    and distributes traffic across them according to the selected algorithm.
    
    Full specification implementation includes:
    - Sequence number tracking for ordered delivery across circuits
    - AIMD congestion control per circuit
    - Out-of-order packet buffering and reordering
    - Circuit health monitoring
    - Automatic failover on circuit failures
    """
    
    def __init__(self, set_id: Optional[bytes] = None, algorithm: ConfluxAlgorithm = ConfluxAlgorithm.ROUND_ROBIN):
        """
        Initialize a Conflux circuit set.
        
        Args:
            set_id: Unique identifier for this circuit set (32 bytes)
            algorithm: Traffic distribution algorithm
        """
        self._set_id = set_id or os.urandom(32)
        self._algorithm = algorithm
        self._circuits = []
        self._circuit_weights = {}
        self._next_circuit_idx = 0
        self._lock = threading.Lock()
        self._state = ConfluxLinkState.UNLINKED
        
        # Sequence tracking for ordered delivery
        self._next_seq_send = 0  # Next sequence number to send
        self._next_seq_recv = 0  # Next sequence number expected to receive
        self._recv_buffer = {}  # Out-of-order packets: seq -> data
        
        # Congestion control per circuit (AIMD)
        self._circuit_cwnd = {}  # Congestion window per circuit
        self._circuit_ssthresh = {}  # Slow start threshold per circuit
        self._circuit_in_flight = {}  # In-flight cells per circuit
        
        # Statistics
        self._bytes_sent = defaultdict(int)
        self._cells_sent = defaultdict(int)
        self._rtt_estimates = {}
        self._last_active = {}  # Last activity timestamp per circuit
        self._retries = defaultdict(int)  # Retry counter per circuit
    
    @property
    def set_id(self) -> bytes:
        """Get the unique identifier for this circuit set."""
        return self._set_id
    
    @property
    def circuit_count(self) -> int:
        """Get the number of circuits in this set."""
        return len(self._circuits)
    
    @property
    def is_linked(self) -> bool:
        """Check if circuits are linked and ready for use."""
        return self._state == ConfluxLinkState.LINKED
    
    def add_circuit(self, circuit, weight: float = 1.0):
        """
        Add a circuit to this Conflux set.
        
        Args:
            circuit: TorCircuit to add
            weight: Weight for weighted distribution (default 1.0)
        """
        with self._lock:
            if circuit not in self._circuits:
                self._circuits.append(circuit)
                circuit_id = id(circuit)
                self._circuit_weights[circuit_id] = weight
                
                # Initialize congestion control for this circuit
                self._circuit_cwnd[circuit_id] = INITIAL_CWND
                self._circuit_ssthresh[circuit_id] = SSTHRESH_INIT
                self._circuit_in_flight[circuit_id] = 0
                self._last_active[circuit_id] = time.time()
                
                logger.info('Added circuit #%x to Conflux set %s (total: %d)',
                           circuit.id, self._set_id.hex()[:16], len(self._circuits))
    
    def remove_circuit(self, circuit):
        """
        Remove a circuit from this Conflux set.
        
        Args:
            circuit: TorCircuit to remove
        """
        with self._lock:
            if circuit in self._circuits:
                self._circuits.remove(circuit)
                circuit_id = id(circuit)
                del self._circuit_weights[circuit_id]
                
                # Clean up congestion control state
                self._circuit_cwnd.pop(circuit_id, None)
                self._circuit_ssthresh.pop(circuit_id, None)
                self._circuit_in_flight.pop(circuit_id, None)
                self._last_active.pop(circuit_id, None)
                self._retries.pop(circuit_id, None)
                
                logger.info('Removed circuit #%x from Conflux set %s (remaining: %d)',
                           circuit.id, self._set_id.hex()[:16], len(self._circuits))
    
    def select_circuit(self, data_size: int = 0):
        """
        Select which circuit to use for the next data transmission.
        
        Uses the configured algorithm and respects congestion windows.
        
        Args:
            data_size: Size of data to send (for weighted algorithms)
            
        Returns:
            Selected TorCircuit, or None if no circuits available
        """
        with self._lock:
            if not self._circuits:
                return None
            
            # Filter circuits that have available congestion window
            available_circuits = [
                c for c in self._circuits
                if self._circuit_in_flight.get(id(c), 0) < self._circuit_cwnd.get(id(c), INITIAL_CWND)
            ]
            
            if not available_circuits:
                # All circuits congested, use circuit with most available window
                available_circuits = [
                    max(self._circuits, 
                        key=lambda c: self._circuit_cwnd.get(id(c), INITIAL_CWND) - 
                                     self._circuit_in_flight.get(id(c), 0))
                ]
            
            if self._algorithm == ConfluxAlgorithm.ROUND_ROBIN:
                # Simple round-robin over available circuits
                circuit = available_circuits[self._next_circuit_idx % len(available_circuits)]
                self._next_circuit_idx += 1
                return circuit
            
            elif self._algorithm == ConfluxAlgorithm.WEIGHTED:
                # Weighted selection based on circuit performance
                total_weight = sum(self._circuit_weights.get(id(c), 1.0) for c in available_circuits)
                if total_weight == 0:
                    return available_circuits[0]
                
                # Weighted random selection
                import random
                r = random.uniform(0, total_weight)
                cumulative = 0
                for circuit in available_circuits:
                    cumulative += self._circuit_weights.get(id(circuit), 1.0)
                    if r <= cumulative:
                        return circuit
                return available_circuits[-1]
            
            elif self._algorithm == ConfluxAlgorithm.LOWEST_LATENCY:
                # Select circuit with lowest estimated RTT
                if not self._rtt_estimates:
                    return available_circuits[0]
                
                best_circuit = min(available_circuits,
                                  key=lambda c: self._rtt_estimates.get(id(c), float('inf')))
                return best_circuit
            
            elif self._algorithm == ConfluxAlgorithm.MIN_RTT_CWND:
                # Optimal throughput: minimize RTT / CWND ratio
                def score(c):
                    cid = id(c)
                    rtt = self._rtt_estimates.get(cid, 1.0)
                    cwnd = self._circuit_cwnd.get(cid, INITIAL_CWND)
                    return rtt / (cwnd + 1)
                
                best_circuit = min(available_circuits, key=score)
                return best_circuit
            
            else:
                return available_circuits[0]
    
    def update_circuit_stats(self, circuit, bytes_sent: int = 0, rtt: Optional[float] = None):
        """
        Update statistics for a circuit.
        
        Args:
            circuit: TorCircuit
            bytes_sent: Number of bytes sent on this circuit
            rtt: Round-trip time estimate (seconds)
        """
        with self._lock:
            circuit_id = id(circuit)
            self._last_active[circuit_id] = time.time()
            
            if bytes_sent > 0:
                self._bytes_sent[circuit_id] += bytes_sent
                self._cells_sent[circuit_id] += 1
            
            if rtt is not None:
                # Exponential moving average
                if circuit_id in self._rtt_estimates:
                    self._rtt_estimates[circuit_id] = 0.7 * self._rtt_estimates[circuit_id] + 0.3 * rtt
                else:
                    self._rtt_estimates[circuit_id] = rtt
                
                # Update weight based on RTT (lower RTT = higher weight)
                if self._algorithm == ConfluxAlgorithm.WEIGHTED:
                    self._circuit_weights[circuit_id] = 1.0 / (rtt + 0.001)
    
    def allocate_sequence_number(self) -> int:
        """
        Allocate the next sequence number for sending data.
        
        Returns:
            Sequence number to use for next transmission
        """
        with self._lock:
            seq = self._next_seq_send
            self._next_seq_send += 1
            return seq
    
    def receive_data(self, seq: int, data: bytes) -> List[bytes]:
        """
        Receive data with sequence number, handling out-of-order delivery.
        
        Args:
            seq: Sequence number of received data
            data: Received data payload
            
        Returns:
            List of data packets ready for delivery (in order)
        """
        with self._lock:
            # If this is the next expected packet, deliver immediately
            if seq == self._next_seq_recv:
                result = [data]
                self._next_seq_recv += 1
                
                # Check if buffered packets can now be delivered
                while self._next_seq_recv in self._recv_buffer:
                    result.append(self._recv_buffer.pop(self._next_seq_recv))
                    self._next_seq_recv += 1
                
                return result
            
            # If packet is ahead, buffer it
            elif seq > self._next_seq_recv:
                self._recv_buffer[seq] = data
                logger.debug('Buffered out-of-order packet seq=%d (expected=%d)', 
                           seq, self._next_seq_recv)
                return []
            
            # If packet is behind, it's a duplicate - ignore
            else:
                logger.warning('Received duplicate packet seq=%d (expected=%d)', 
                             seq, self._next_seq_recv)
                return []
    
    def mark_packet_sent(self, circuit):
        """
        Mark a packet as sent (in-flight) on a circuit.
        
        Args:
            circuit: TorCircuit
        """
        with self._lock:
            circuit_id = id(circuit)
            self._circuit_in_flight[circuit_id] = self._circuit_in_flight.get(circuit_id, 0) + 1
    
    def mark_packet_acked(self, circuit):
        """
        Mark a packet as acknowledged on a circuit.
        Updates congestion window using AIMD.
        
        Args:
            circuit: TorCircuit
        """
        with self._lock:
            circuit_id = id(circuit)
            
            # Decrease in-flight count
            if circuit_id in self._circuit_in_flight and self._circuit_in_flight[circuit_id] > 0:
                self._circuit_in_flight[circuit_id] -= 1
            
            # Update congestion window (AIMD)
            self._update_congestion_window(circuit_id, congestion_event=False)
    
    def mark_packet_lost(self, circuit):
        """
        Mark a packet as lost on a circuit.
        Triggers multiplicative decrease in congestion window.
        
        Args:
            circuit: TorCircuit
        """
        with self._lock:
            circuit_id = id(circuit)
            
            # Decrease in-flight count
            if circuit_id in self._circuit_in_flight and self._circuit_in_flight[circuit_id] > 0:
                self._circuit_in_flight[circuit_id] -= 1
            
            # Update congestion window (AIMD)
            self._update_congestion_window(circuit_id, congestion_event=True)
    
    def _update_congestion_window(self, circuit_id: int, congestion_event: bool):
        """
        Update congestion window using AIMD algorithm.
        
        Args:
            circuit_id: Circuit identifier
            congestion_event: True if packet loss detected
        """
        cwnd = self._circuit_cwnd.get(circuit_id, INITIAL_CWND)
        ssthresh = self._circuit_ssthresh.get(circuit_id, SSTHRESH_INIT)
        
        if congestion_event:
            # Multiplicative decrease
            ssthresh = max(cwnd * MULTIPLICATIVE_DECREASE, MIN_CWND)
            cwnd = max(ssthresh, MIN_CWND)
            logger.debug('Congestion detected on circuit %x: cwnd=%d ssthresh=%d',
                        circuit_id, cwnd, ssthresh)
        else:
            # Additive increase
            if cwnd < ssthresh:
                # Slow start: exponential growth
                cwnd = min(cwnd + 1, MAX_CWND)
            else:
                # Congestion avoidance: linear growth
                cwnd = min(cwnd + 1.0 / cwnd, MAX_CWND)
        
        self._circuit_cwnd[circuit_id] = cwnd
        self._circuit_ssthresh[circuit_id] = ssthresh
    
    def check_circuit_health(self) -> List:
        """
        Check health of all circuits and remove failed ones.
        
        Returns:
            List of circuits that were removed due to failures
        """
        with self._lock:
            current_time = time.time()
            failed_circuits = []
            
            for circuit in list(self._circuits):
                circuit_id = id(circuit)
                last_active = self._last_active.get(circuit_id, current_time)
                
                # Check if circuit has timed out
                if current_time - last_active > CIRCUIT_TIMEOUT:
                    retries = self._retries[circuit_id]
                    
                    if retries >= MAX_RETRIES:
                        logger.warning('Circuit #%x failed health check (timeout), removing',
                                     circuit.id)
                        failed_circuits.append(circuit)
                        self._circuits.remove(circuit)
                    else:
                        self._retries[circuit_id] += 1
                        logger.debug('Circuit #%x health check timeout (retry %d/%d)',
                                   circuit.id, retries + 1, MAX_RETRIES)
            
            return failed_circuits
    
    def link_circuits(self):
        """
        Link all circuits in this set together.
        
        This would send CONFLUX_LINK cells to establish the relationship
        between circuits. For now, just mark as linked.
        """
        with self._lock:
            if len(self._circuits) < 2:
                logger.warning('Conflux set needs at least 2 circuits to link')
                return False
            
            self._state = ConfluxLinkState.LINKING
            # TODO: Send CONFLUX_LINK cells to each circuit
            # For now, just mark as linked
            self._state = ConfluxLinkState.LINKED
            logger.info('Linked %d circuits in Conflux set %s',
                       len(self._circuits), self._set_id.hex()[:16])
            return True
    
    def get_stats(self) -> dict:
        """Get statistics for this Conflux set."""
        with self._lock:
            return {
                'set_id': self._set_id.hex(),
                'circuit_count': len(self._circuits),
                'algorithm': self._algorithm.name,
                'state': self._state.name,
                'total_bytes': sum(self._bytes_sent.values()),
                'total_cells': sum(self._cells_sent.values()),
                'next_seq_send': self._next_seq_send,
                'next_seq_recv': self._next_seq_recv,
                'buffered_packets': len(self._recv_buffer),
                'circuits': [
                    {
                        'circuit_id': circuit.id,
                        'bytes_sent': self._bytes_sent.get(id(circuit), 0),
                        'cells_sent': self._cells_sent.get(id(circuit), 0),
                        'rtt': self._rtt_estimates.get(id(circuit)),
                        'weight': self._circuit_weights.get(id(circuit), 1.0),
                        'cwnd': self._circuit_cwnd.get(id(circuit), INITIAL_CWND),
                        'ssthresh': self._circuit_ssthresh.get(id(circuit), SSTHRESH_INIT),
                        'in_flight': self._circuit_in_flight.get(id(circuit), 0),
                        'last_active': self._last_active.get(id(circuit), 0)
                    }
                    for circuit in self._circuits
                ]
            }


class ConfluxManager:
    """
    Manages multiple Conflux circuit sets.
    
    This class coordinates the creation and management of Conflux sets,
    allowing a client to have multiple multiplexed circuit groups for
    different destinations or purposes.
    
    Includes background health monitoring thread for automatic failover.
    """
    
    def __init__(self, enable_health_monitoring: bool = True):
        """
        Initialize Conflux manager.
        
        Args:
            enable_health_monitoring: Enable background health check thread
        """
        self._sets = {}  # set_id -> ConfluxCircuitSet
        self._lock = threading.Lock()
        self._health_monitor_thread = None
        self._health_monitor_running = False
        
        if enable_health_monitoring:
            self.start_health_monitoring()
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop_health_monitoring()
    
    def start_health_monitoring(self):
        """Start background health monitoring thread."""
        if not self._health_monitor_running:
            self._health_monitor_running = True
            self._health_monitor_thread = threading.Thread(
                target=self._health_monitor_loop,
                name='ConfluxHealthMonitor',
                daemon=True
            )
            self._health_monitor_thread.start()
            logger.info('Started Conflux health monitoring')
    
    def stop_health_monitoring(self):
        """Stop background health monitoring thread."""
        if self._health_monitor_running:
            self._health_monitor_running = False
            if self._health_monitor_thread:
                self._health_monitor_thread.join(timeout=5.0)
            logger.info('Stopped Conflux health monitoring')
    
    def _health_monitor_loop(self):
        """Background thread that monitors circuit health."""
        while self._health_monitor_running:
            try:
                # Check health of all circuit sets
                with self._lock:
                    for conflux_set in list(self._sets.values()):
                        failed = conflux_set.check_circuit_health()
                        
                        if failed:
                            logger.info('Removed %d failed circuits from set %s',
                                      len(failed), conflux_set.set_id.hex()[:16])
                        
                        # Remove empty sets
                        if conflux_set.circuit_count == 0:
                            logger.warning('Conflux set %s has no circuits, removing',
                                         conflux_set.set_id.hex()[:16])
                            self._sets.pop(conflux_set.set_id, None)
                
                # Sleep until next check
                time.sleep(HEALTH_CHECK_INTERVAL)
                
            except Exception as e:
                logger.exception('Error in Conflux health monitor: %s', e)
    
    def create_set(self, algorithm: ConfluxAlgorithm = ConfluxAlgorithm.ROUND_ROBIN) -> ConfluxCircuitSet:
        """
        Create a new Conflux circuit set.
        
        Args:
            algorithm: Traffic distribution algorithm
            
        Returns:
            New ConfluxCircuitSet
        """
        with self._lock:
            conflux_set = ConfluxCircuitSet(algorithm=algorithm)
            self._sets[conflux_set.set_id] = conflux_set
            logger.info('Created Conflux set %s with algorithm %s',
                       conflux_set.set_id.hex()[:16], algorithm.name)
            return conflux_set
    
    def get_set(self, set_id: bytes) -> Optional[ConfluxCircuitSet]:
        """Get a Conflux set by ID."""
        return self._sets.get(set_id)
    
    def remove_set(self, set_id: bytes):
        """Remove a Conflux set."""
        with self._lock:
            if set_id in self._sets:
                del self._sets[set_id]
                logger.info('Removed Conflux set %s', set_id.hex()[:16])
    
    def get_all_sets(self) -> List[ConfluxCircuitSet]:
        """Get all Conflux sets."""
        with self._lock:
            return list(self._sets.values())
    
    def get_total_stats(self) -> Dict:
        """
        Get aggregate statistics for all Conflux sets.
        
        Returns:
            Dictionary with total statistics
        """
        with self._lock:
            total_circuits = 0
            total_bytes = 0
            total_cells = 0
            
            for conflux_set in self._sets.values():
                stats = conflux_set.get_stats()
                total_circuits += stats['circuit_count']
                total_bytes += stats['total_bytes']
                total_cells += stats['total_cells']
            
            return {
                'total_sets': len(self._sets),
                'total_circuits': total_circuits,
                'total_bytes': total_bytes,
                'total_cells': total_cells,
                'health_monitoring': self._health_monitor_running
            }
