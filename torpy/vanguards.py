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

This implementation follows Proposal 333 (Vanguards) and the vanguards
addon design.

Implementation status: BASIC FRAMEWORK
- Layer 2 and Layer 3 guard selection
- Rotation scheduling
- TODO: Integration with circuit building
- TODO: Full proposal 333 compliance
- TODO: Bandwidth weighting algorithms
"""

import os
import time
import random
import logging
import threading
from enum import IntEnum, auto
from datetime import datetime, timedelta
from typing import List, Optional, Set
from collections import defaultdict

logger = logging.getLogger(__name__)


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
    
    def _select_new_vanguard(self) -> Optional[VanguardNode]:
        """
        Select a new vanguard node.
        
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
        
        # TODO: Implement proper bandwidth-weighted selection
        # For now, use random selection
        router = random.choice(candidates)
        
        # Random lifetime within the range
        lifetime_hours = random.randint(self.lifetime_min, self.lifetime_max)
        
        return VanguardNode(router, self.layer, lifetime_hours)
    
    def rotate(self):
        """
        Rotate expired vanguard nodes.
        
        This checks for expired nodes and replaces them with new ones.
        """
        with self._lock:
            expired = [node for node in self.nodes if node.is_expired]
            
            if not expired:
                return
            
            logger.info('Rotating %d expired vanguard nodes in layer %d', len(expired), self.layer)
            
            for node in expired:
                self.nodes.remove(node)
                logger.debug('Removed expired vanguard: %s', node)
                
                # Replace with new node
                new_node = self._select_new_vanguard()
                if new_node:
                    self.nodes.append(new_node)
                    logger.debug('Added new vanguard: %s', new_node)
            
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
    
    def get_all_nodes(self) -> List[VanguardNode]:
        """Get all nodes in this vanguard set."""
        with self._lock:
            return self.nodes.copy()
    
    def get_stats(self) -> dict:
        """Get statistics about this vanguard set."""
        with self._lock:
            return {
                'layer': self.layer,
                'node_count': len(self.nodes),
                'min_nodes': self.min_nodes,
                'max_nodes': self.max_nodes,
                'last_rotation': self._last_rotation.isoformat(),
                'nodes': [
                    {
                        'fingerprint': node.fingerprint,
                        'selected_at': node.selected_at.isoformat(),
                        'expires_at': node.expires_at.isoformat(),
                        'time_until_expiry_hours': node.time_until_expiry.total_seconds() / 3600,
                        'use_count': node.use_count,
                    }
                    for node in self.nodes
                ]
            }


class VanguardManager:
    """
    Manages vanguard layers for hidden service protection.
    
    This class coordinates Layer 2 and Layer 3 vanguards, handling
    rotation, selection, and providing nodes for circuit construction.
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
                    logger.debug('Checking for expired vanguards')
                    self.layer2.rotate()
                    self.layer3.rotate()
            except Exception as e:
                logger.error('Error in vanguard rotation loop: %s', e)
    
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
    
    @property
    def is_enabled(self) -> bool:
        """Check if vanguards are enabled."""
        return self._enabled
    
    def get_stats(self) -> dict:
        """Get statistics about vanguards."""
        return {
            'enabled': self._enabled,
            'layer2': self.layer2.get_stats(),
            'layer3': self.layer3.get_stats(),
        }
    
    def __enter__(self):
        self.enable()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disable()
