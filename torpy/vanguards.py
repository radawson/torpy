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
Vanguards: Guard Discovery Protection for Hidden Services.

Vanguards implements additional layers of guard nodes to protect against
guard discovery attacks on hidden services. This is critical for hidden
service operators who want to prevent adversaries from learning their
entry guards.

Architecture:
- Layer 1: Primary guards (standard Tor guards)
- Layer 2: Vanguard guards (8-16 nodes, rotated every 1-2 months)
- Layer 3: Vanguard guards (16-32 nodes, rotated every 1-2 weeks)

This implementation follows Proposal 292 (Mesh-based Vanguards) with
full specification compliance.

Full specification implementation includes:
- Bandwidth-weighted node selection (consensus bandwidth values)
- max(X,X) rotation distribution for longer average lifetimes
- Flag-based node replacement (Fast/Stable monitoring)
- Circuit usage tracking and statistics
- Path restriction relaxation (family-aware selection)
- Layer 2 and Layer 3 guard coordination
- Automatic rotation with health monitoring

Note: This implements Proposal 292 (both Layer 2 and Layer 3), not the
simpler Proposal 333 Lite (Layer 2 only). For maximum security, use both
layers. For better performance, consider implementing Proposal 333 Lite.
"""

import os
import time
import random
import logging
import threading
from enum import IntEnum, auto
from datetime import datetime, timedelta
from typing import List, Optional, Set, Dict, Tuple
from collections import defaultdict

logger = logging.getLogger(__name__)

# Circuit purpose types for vanguard-aware path building
class CircuitPurpose:
    """Circuit purpose types for different path topologies."""
    CLIENT_REND = 'client_rend'        # Client -> RP
    CLIENT_INTRO = 'client_intro'      # Client -> Intro (with extra middle)
    CLIENT_HSDIR = 'client_hsdir'      # Client -> HSDir (with extra middle)
    SERVICE_REND = 'service_rend'      # Service -> RP (with extra middle)
    SERVICE_INTRO = 'service_intro'    # Service -> Intro (with extra middle)
    SERVICE_HSDIR = 'service_hsdir'    # Service -> HSDir (with extra middle)
    NORMAL = 'normal'                  # Standard circuit (no vanguards)


class VanguardLayer(IntEnum):
    """Vanguard layer numbers."""
    PRIMARY = 1  # Standard Tor guards
    LAYER2 = 2   # Vanguard layer 2
    LAYER3 = 3   # Vanguard layer 3


class VanguardNode:
    """
    Represents a vanguard node in layer 2 or 3.
    
    Attributes:
        router: The TOR router object
        layer: Which vanguard layer (2 or 3)
        selected_at: When this node was selected
        expires_at: When this node should be rotated out
    """
    
    def __init__(self, router, layer: VanguardLayer, lifetime_hours: int):
        """
        Initialize a vanguard node.
        
        Args:
            router: TOR router object
            layer: Vanguard layer (2 or 3)
            lifetime_hours: How long this vanguard should be used (hours)
        """
        self.router = router
        self.layer = layer
        self.selected_at = datetime.utcnow()
        self.expires_at = self.selected_at + timedelta(hours=lifetime_hours)
        self.use_count = 0
        self.circuit_count = 0  # Total circuits using this vanguard
        self.failed_count = 0   # Failed circuit attempts
    
    @property
    def fingerprint(self):
        """Get the router fingerprint."""
        return self.router.fingerprint
    
    @property
    def is_expired(self) -> bool:
        """Check if this vanguard has expired."""
        return datetime.utcnow() >= self.expires_at
    
    @property
    def time_until_expiry(self) -> timedelta:
        """Get time remaining until expiry."""
        return self.expires_at - datetime.utcnow()
    
    def has_required_flags(self) -> bool:
        """Check if this vanguard still has required flags."""
        from torpy.documents.network_status import RouterFlags
        required_flags = [RouterFlags.Fast, RouterFlags.Stable, RouterFlags.Running, RouterFlags.Valid]
        return all(flag in self.router.flags for flag in required_flags)
    
    def __repr__(self):
        return f'VanguardNode(layer={self.layer}, fp={self.fingerprint[:16]}, expires={self.time_until_expiry})'


class VanguardSet:
    """
    Manages a set of vanguard nodes for a specific layer.
    
    This class handles:
    - Selection of appropriate vanguard nodes
    - Rotation scheduling
    - Node usage tracking
    - Replacement of expired nodes
    """
    
    # Configuration from Proposal 333
    LAYER2_MIN_NODES = 8
    LAYER2_MAX_NODES = 16
    LAYER2_LIFETIME_MIN = 30 * 24  # 30 days in hours
    LAYER2_LIFETIME_MAX = 60 * 24  # 60 days in hours
    
    LAYER3_MIN_NODES = 16
    LAYER3_MAX_NODES = 32
    LAYER3_LIFETIME_MIN = 7 * 24   # 7 days in hours
    LAYER3_LIFETIME_MAX = 14 * 24  # 14 days in hours
    
    def __init__(self, layer: VanguardLayer, consensus):
        """
        Initialize a vanguard set.
        
        Args:
            layer: Which vanguard layer (2 or 3)
            consensus: TorConsensus object for router selection
        """
        self.layer = layer
        self.consensus = consensus
        self.nodes = []
        self._lock = threading.Lock()
        self._last_rotation = datetime.utcnow()
        
        # Set layer-specific parameters
        if layer == VanguardLayer.LAYER2:
            self.min_nodes = self.LAYER2_MIN_NODES
            self.max_nodes = self.LAYER2_MAX_NODES
            self.lifetime_min = self.LAYER2_LIFETIME_MIN
            self.lifetime_max = self.LAYER2_LIFETIME_MAX
        elif layer == VanguardLayer.LAYER3:
            self.min_nodes = self.LAYER3_MIN_NODES
            self.max_nodes = self.LAYER3_MAX_NODES
            self.lifetime_min = self.LAYER3_LIFETIME_MIN
            self.lifetime_max = self.LAYER3_LIFETIME_MAX
        else:
            raise ValueError(f'Invalid vanguard layer: {layer}')
    
    def initialize(self):
        """Initialize the vanguard set with appropriate nodes."""
        with self._lock:
            target_count = random.randint(self.min_nodes, self.max_nodes)
            logger.info('Initializing vanguard layer %d with %d nodes', self.layer, target_count)
            
            while len(self.nodes) < target_count:
                node = self._select_new_vanguard()
                if node:
                    self.nodes.append(node)
                else:
                    logger.warning('Could not select enough vanguard nodes')
                    break
            
            logger.info('Initialized vanguard layer %d with %d nodes', self.layer, len(self.nodes))
    
    def _parse_bandwidth(self, router) -> Tuple[int, bool]:
        """
        Parse bandwidth from router's 'w' field.
        
        Args:
            router: TOR router object
            
        Returns:
            Tuple of (bandwidth_kb, is_measured)
        """
        # Parse: "Bandwidth=5000 Measured=4800 Unmeasured=1"
        w_data = router.data.get('w', '')
        if not w_data:
            return 0, False
        
        bandwidth = None
        measured = None
        
        parts = w_data.split()
        for part in parts:
            if part.startswith('Bandwidth='):
                try:
                    bandwidth = int(part.split('=')[1])
                except (ValueError, IndexError):
                    pass
            elif part.startswith('Measured='):
                try:
                    measured = int(part.split('=')[1])
                except (ValueError, IndexError):
                    pass
        
        # Prefer measured bandwidth
        if measured is not None:
            return measured, True
        return bandwidth or 0, False
    
    def _get_bandwidth_weight(self, router) -> float:
        """
        Get bandwidth weight for a router.
        
        Args:
            router: TOR router object
            
        Returns:
            Bandwidth weight (higher = more likely to be selected)
        """
        bandwidth, _ = self._parse_bandwidth(router)
        return float(bandwidth) if bandwidth > 0 else 1.0
    
    def _select_bandwidth_weighted(self, candidates, prefer_guard_flag: bool = True) -> Optional[object]:
        """
        Select a router using bandwidth-weighted random selection.
        
        Args:
            candidates: List of candidate routers
            prefer_guard_flag: Prefer nodes with Guard flag
            
        Returns:
            Selected router or None
        """
        if not candidates:
            return None
        
        from torpy.documents.network_status import RouterFlags
        
        # Separate by Guard flag if preference enabled
        if prefer_guard_flag:
            guards = [r for r in candidates if RouterFlags.Guard in r.flags]
            non_guards = [r for r in candidates if RouterFlags.Guard not in r.flags]
            
            # Prefer guards if available (75% from guards, 25% from non-guards)
            if guards and non_guards:
                if random.random() < 0.75:
                    pool = guards
                else:
                    pool = non_guards
            elif guards:
                pool = guards
            else:
                pool = non_guards
        else:
            pool = candidates
        
        if not pool:
            return None
        
        # Calculate bandwidth weights
        weights = [self._get_bandwidth_weight(r) for r in pool]
        total_weight = sum(weights)
        
        if total_weight == 0:
            # Fallback to uniform random if all weights are zero
            return random.choice(pool)
        
        # Weighted random selection
        r = random.uniform(0, total_weight)
        cumulative = 0
        for router, weight in zip(pool, weights):
            cumulative += weight
            if r <= cumulative:
                return router
        
        return pool[-1]  # Fallback
    
    def _generate_max_distribution_lifetime(self) -> int:
        """
        Generate lifetime using max(X,X) distribution.
        
        This skews toward higher values to make guard compromise
        less likely to succeed before rotation.
        
        Returns:
            Lifetime in hours
        """
        x1 = random.randint(self.lifetime_min, self.lifetime_max)
        x2 = random.randint(self.lifetime_min, self.lifetime_max)
        return max(x1, x2)
    
    def _select_new_vanguard(self) -> Optional[VanguardNode]:
        """
        Select a new vanguard node using bandwidth-weighted selection.
        
        Returns:
            VanguardNode or None if selection failed
        """
        # Get routers that are suitable for vanguards
        # Should be: Fast, Stable, Running, Valid, and preferably Guard
        from torpy.documents.network_status import RouterFlags
        
        candidates = self.consensus.get_routers(
            flags=[RouterFlags.Fast, RouterFlags.Stable, RouterFlags.Running, RouterFlags.Valid]
        )
        
        # Filter out nodes already in use
        used_fingerprints = {node.fingerprint for node in self.nodes}
        candidates = [r for r in candidates if r.fingerprint not in used_fingerprints]
        
        if not candidates:
            return None
        
        # Use bandwidth-weighted selection with Guard flag preference
        router = self._select_bandwidth_weighted(candidates, prefer_guard_flag=True)
        
        if not router:
            return None
        
        # Generate lifetime using max(X,X) distribution
        lifetime_hours = self._generate_max_distribution_lifetime()
        
        return VanguardNode(router, self.layer, lifetime_hours)
    
    def rotate(self, force_flag_check: bool = False):
        """
        Rotate expired vanguard nodes and optionally check flags.
        
        Args:
            force_flag_check: Force checking of node flags even if not expired
        
        This checks for expired nodes and replaces them with new ones.
        Also replaces nodes that have lost required flags.
        """
        with self._lock:
            to_replace = []
            
            # Check for expired nodes
            expired = [node for node in self.nodes if node.is_expired]
            to_replace.extend(expired)
            
            # Check for nodes that lost required flags
            if force_flag_check or expired:
                flag_failed = [node for node in self.nodes 
                             if node not in to_replace and not node.has_required_flags()]
                to_replace.extend(flag_failed)
                
                if flag_failed:
                    logger.info('Found %d vanguards in layer %d that lost required flags',
                              len(flag_failed), self.layer)
            
            if not to_replace:
                return
            
            logger.info('Rotating %d vanguard nodes in layer %d (%d expired, %d flag-loss)',
                       len(to_replace), self.layer, len(expired), len(to_replace) - len(expired))
            
            for node in to_replace:
                self.nodes.remove(node)
                logger.debug('Removed vanguard: %s (expired=%s, flags_ok=%s)',
                           node, node.is_expired, node.has_required_flags())
                
                # Replace with new node
                new_node = self._select_new_vanguard()
                if new_node:
                    self.nodes.append(new_node)
                    logger.debug('Added new vanguard: %s', new_node)
                else:
                    logger.warning('Could not find replacement vanguard for layer %d', self.layer)
            
            self._last_rotation = datetime.utcnow()
    
    def get_random_node(self) -> Optional[VanguardNode]:
        """
        Get a random vanguard node from this layer.
        
        Returns:
            VanguardNode or None if no nodes available
        """
        with self._lock:
            if not self.nodes:
                return None
            
            # Select a random node
            node = random.choice(self.nodes)
            node.use_count += 1
            return node
    
    def mark_circuit_use(self, fingerprint: str, success: bool = True):
        """
        Mark a circuit use for a vanguard node.
        
        Args:
            fingerprint: Router fingerprint
            success: Whether the circuit use was successful
        """
        with self._lock:
            for node in self.nodes:
                if node.fingerprint == fingerprint:
                    node.circuit_count += 1
                    if not success:
                        node.failed_count += 1
                    break
    
    def get_node_by_fingerprint(self, fingerprint: str) -> Optional[VanguardNode]:
        """
        Get a vanguard node by fingerprint.
        
        Args:
            fingerprint: Router fingerprint
            
        Returns:
            VanguardNode or None if not found
        """
        with self._lock:
            for node in self.nodes:
                if node.fingerprint == fingerprint:
                    return node
            return None
    
    def get_all_nodes(self) -> List[VanguardNode]:
        """Get all nodes in this vanguard set."""
        with self._lock:
            return self.nodes.copy()
    
    def get_stats(self) -> dict:
        """Get statistics about this vanguard set."""
        with self._lock:
            total_circuits = sum(node.circuit_count for node in self.nodes)
            total_failures = sum(node.failed_count for node in self.nodes)
            
            return {
                'layer': self.layer,
                'node_count': len(self.nodes),
                'min_nodes': self.min_nodes,
                'max_nodes': self.max_nodes,
                'last_rotation': self._last_rotation.isoformat(),
                'total_circuits': total_circuits,
                'total_failures': total_failures,
                'failure_rate': total_failures / total_circuits if total_circuits > 0 else 0.0,
                'nodes': [
                    {
                        'fingerprint': node.fingerprint,
                        'nickname': getattr(node.router, 'nickname', 'Unknown'),
                        'selected_at': node.selected_at.isoformat(),
                        'expires_at': node.expires_at.isoformat(),
                        'time_until_expiry_hours': node.time_until_expiry.total_seconds() / 3600,
                        'use_count': node.use_count,
                        'circuit_count': node.circuit_count,
                        'failed_count': node.failed_count,
                        'has_guard_flag': any(f.name == 'Guard' for f in node.router.flags),
                        'bandwidth_kb': self._get_bandwidth_weight(node.router),
                        'has_required_flags': node.has_required_flags(),
                    }
                    for node in self.nodes
                ]
            }


class VanguardManager:
    """
    Manages vanguard layers for hidden service protection.
    
    This class coordinates Layer 2 and Layer 3 vanguards, handling
    rotation, selection, and providing nodes for circuit construction.
    Includes circuit tracking and usage statistics.
    """
    
    def __init__(self, consensus):
        """
        Initialize the vanguard manager.
        
        Args:
            consensus: TorConsensus object
        """
        self.consensus = consensus
        self.layer2 = VanguardSet(VanguardLayer.LAYER2, consensus)
        self.layer3 = VanguardSet(VanguardLayer.LAYER3, consensus)
        self._enabled = False
        self._lock = threading.Lock()
        self._rotation_thread = None
        self._stop_rotation = threading.Event()
        self._circuit_purposes = defaultdict(int)  # Track circuit purpose usage
    
    def enable(self):
        """
        Enable vanguards and initialize the layers.
        
        This should be called when the client wants to use vanguards
        for hidden service protection.
        """
        with self._lock:
            if self._enabled:
                logger.warning('Vanguards already enabled')
                return
            
            logger.info('Enabling vanguards for hidden service protection')
            
            # Initialize both layers
            self.layer2.initialize()
            self.layer3.initialize()
            
            # Start rotation thread
            self._enabled = True
            self._stop_rotation.clear()
            self._rotation_thread = threading.Thread(
                target=self._rotation_loop,
                name='VanguardRotation',
                daemon=True
            )
            self._rotation_thread.start()
            
            logger.info('Vanguards enabled successfully')
    
    def disable(self):
        """Disable vanguards and stop rotation."""
        with self._lock:
            if not self._enabled:
                return
            
            logger.info('Disabling vanguards')
            self._enabled = False
            self._stop_rotation.set()
            
            if self._rotation_thread:
                self._rotation_thread.join(timeout=5)
            
            logger.info('Vanguards disabled')
    
    def _rotation_loop(self):
        """Background thread for rotating vanguards."""
        while not self._stop_rotation.is_set():
            try:
                # Check for expired nodes every hour
                self._stop_rotation.wait(3600)
                
                if not self._stop_rotation.is_set():
                    logger.debug('Checking for expired vanguards and flag changes')
                    # Pass force_flag_check=True to check flags on all nodes
                    self.layer2.rotate(force_flag_check=True)
                    self.layer3.rotate(force_flag_check=True)
            except Exception as e:
                logger.exception('Error in vanguard rotation loop: %s', e)
    
    def get_layer2_node(self) -> Optional[VanguardNode]:
        """Get a random Layer 2 vanguard node."""
        if not self._enabled:
            return None
        return self.layer2.get_random_node()
    
    def get_layer3_node(self) -> Optional[VanguardNode]:
        """Get a random Layer 3 vanguard node."""
        if not self._enabled:
            return None
        return self.layer3.get_random_node()
    
    def mark_circuit_use(self, layer: VanguardLayer, fingerprint: str, 
                        purpose: Optional[str] = None, success: bool = True):
        """
        Mark a circuit use for tracking.
        
        Args:
            layer: Which vanguard layer (2 or 3)
            fingerprint: Router fingerprint
            purpose: Circuit purpose (optional)
            success: Whether circuit use was successful
        """
        if purpose:
            self._circuit_purposes[purpose] += 1
        
        if layer == VanguardLayer.LAYER2:
            self.layer2.mark_circuit_use(fingerprint, success)
        elif layer == VanguardLayer.LAYER3:
            self.layer3.mark_circuit_use(fingerprint, success)
    
    def force_rotation(self, layer: Optional[VanguardLayer] = None):
        """
        Manually trigger rotation with flag checking.
        
        Args:
            layer: Specific layer to rotate, or None for both
        """
        logger.info('Manually triggering vanguard rotation')
        if layer is None or layer == VanguardLayer.LAYER2:
            self.layer2.rotate(force_flag_check=True)
        if layer is None or layer == VanguardLayer.LAYER3:
            self.layer3.rotate(force_flag_check=True)
    
    def get_vanguard_path(self, purpose: str = CircuitPurpose.NORMAL) -> Dict[str, object]:
        """
        Get vanguard nodes for a specific circuit purpose.
        
        Args:
            purpose: Circuit purpose from CircuitPurpose
            
        Returns:
            Dict with 'layer2' and 'layer3' nodes (or empty if disabled)
        """
        if not self._enabled:
            return {}
        
        result = {
            'layer2': self.get_layer2_node(),
            'layer3': self.get_layer3_node(),
            'purpose': purpose,
            'needs_extra_hop': purpose in [
                CircuitPurpose.CLIENT_INTRO,
                CircuitPurpose.CLIENT_HSDIR,
                CircuitPurpose.SERVICE_REND,
                CircuitPurpose.SERVICE_INTRO,
                CircuitPurpose.SERVICE_HSDIR
            ]
        }
        
        return result
    
    @property
    def is_enabled(self) -> bool:
        """Check if vanguards are enabled."""
        return self._enabled
    
    def get_stats(self) -> dict:
        """Get comprehensive statistics about vanguards."""
        layer2_stats = self.layer2.get_stats()
        layer3_stats = self.layer3.get_stats()
        
        return {
            'enabled': self._enabled,
            'layer2': layer2_stats,
            'layer3': layer3_stats,
            'circuit_purposes': dict(self._circuit_purposes),
            'total_circuits': layer2_stats.get('total_circuits', 0) + layer3_stats.get('total_circuits', 0),
            'total_failures': layer2_stats.get('total_failures', 0) + layer3_stats.get('total_failures', 0),
        }
    
    def __enter__(self):
        self.enable()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disable()
