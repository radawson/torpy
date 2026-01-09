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

Implementation status: BASIC FRAMEWORK
- Circuit linking and unlinking
- Basic traffic distribution
- TODO: Full congestion control integration
- TODO: Recovery from circuit failures
- TODO: Optimal path selection algorithms
"""

import os
import logging
import threading
from enum import IntEnum, auto
from typing import List, Optional
from collections import defaultdict

logger = logging.getLogger(__name__)


class ConfluxAlgorithm(IntEnum):
    """Conflux traffic distribution algorithms."""
    # Round-robin: Simple alternating between circuits
    ROUND_ROBIN = 0
    # Weighted: Distribute based on circuit performance
    WEIGHTED = 1
    # Lowest latency: Send on circuit with lowest RTT
    LOWEST_LATENCY = 2


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
        
        # Statistics
        self._bytes_sent = defaultdict(int)
        self._cells_sent = defaultdict(int)
        self._rtt_estimates = {}
    
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
                self._circuit_weights[id(circuit)] = weight
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
                del self._circuit_weights[id(circuit)]
                logger.info('Removed circuit #%x from Conflux set %s (remaining: %d)',
                           circuit.id, self._set_id.hex()[:16], len(self._circuits))
    
    def select_circuit(self, data_size: int = 0):
        """
        Select which circuit to use for the next data transmission.
        
        Args:
            data_size: Size of data to send (for weighted algorithms)
            
        Returns:
            Selected TorCircuit, or None if no circuits available
        """
        with self._lock:
            if not self._circuits:
                return None
            
            if self._algorithm == ConfluxAlgorithm.ROUND_ROBIN:
                # Simple round-robin
                circuit = self._circuits[self._next_circuit_idx % len(self._circuits)]
                self._next_circuit_idx += 1
                return circuit
            
            elif self._algorithm == ConfluxAlgorithm.WEIGHTED:
                # Weighted selection based on circuit performance
                total_weight = sum(self._circuit_weights.values())
                if total_weight == 0:
                    return self._circuits[0]
                
                # Simple weighted random selection
                import random
                r = random.uniform(0, total_weight)
                cumulative = 0
                for circuit in self._circuits:
                    cumulative += self._circuit_weights[id(circuit)]
                    if r <= cumulative:
                        return circuit
                return self._circuits[-1]
            
            elif self._algorithm == ConfluxAlgorithm.LOWEST_LATENCY:
                # Select circuit with lowest estimated RTT
                if not self._rtt_estimates:
                    return self._circuits[0]
                
                best_circuit = min(self._circuits,
                                  key=lambda c: self._rtt_estimates.get(id(c), float('inf')))
                return best_circuit
            
            else:
                return self._circuits[0]
    
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
                'circuits': [
                    {
                        'circuit_id': circuit.id,
                        'bytes_sent': self._bytes_sent.get(id(circuit), 0),
                        'cells_sent': self._cells_sent.get(id(circuit), 0),
                        'rtt': self._rtt_estimates.get(id(circuit)),
                        'weight': self._circuit_weights.get(id(circuit), 1.0)
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
    """
    
    def __init__(self):
        self._sets = {}  # set_id -> ConfluxCircuitSet
        self._lock = threading.Lock()
    
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
        return list(self._sets.values())
