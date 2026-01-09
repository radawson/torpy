"""
Unit tests for full Vanguards implementation (Proposal 292).

Tests bandwidth-weighted selection, max(X,X) distribution, flag-based
replacement, and circuit tracking.
"""

import time
import unittest
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime, timedelta
from torpy.vanguards import (
    VanguardNode,
    VanguardSet,
    VanguardManager,
    VanguardLayer,
    CircuitPurpose,
)


class TestVanguardNode(unittest.TestCase):
    """Test VanguardNode with circuit tracking."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_router = Mock()
        self.mock_router.fingerprint = 'A' * 40
        self.mock_router.nickname = 'TestRelay'
        self.mock_router.flags = [Mock(name='Fast'), Mock(name='Stable'), 
                                  Mock(name='Running'), Mock(name='Valid')]
    
    def test_node_initialization(self):
        """Test node initialization with circuit tracking fields."""
        node = VanguardNode(self.mock_router, VanguardLayer.LAYER2, 720)
        
        self.assertEqual(node.layer, VanguardLayer.LAYER2)
        self.assertEqual(node.use_count, 0)
        self.assertEqual(node.circuit_count, 0)
        self.assertEqual(node.failed_count, 0)
        self.assertFalse(node.is_expired)
    
    def test_has_required_flags(self):
        """Test flag checking."""
        node = VanguardNode(self.mock_router, VanguardLayer.LAYER2, 720)
        
        # Should have required flags
        self.assertTrue(node.has_required_flags())
        
        # Remove a required flag
        self.mock_router.flags = [Mock(name='Fast'), Mock(name='Running')]
        self.assertFalse(node.has_required_flags())
    
    def test_expiry(self):
        """Test expiry checking."""
        node = VanguardNode(self.mock_router, VanguardLayer.LAYER2, 0)
        time.sleep(0.01)  # Wait a bit
        self.assertTrue(node.is_expired)


class TestBandwidthWeighting(unittest.TestCase):
    """Test bandwidth-weighted selection."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_consensus = Mock()
        self.vanguard_set = VanguardSet(VanguardLayer.LAYER2, self.mock_consensus)
    
    def test_parse_bandwidth(self):
        """Test bandwidth parsing from 'w' field."""
        router = Mock()
        
        # Test with measured bandwidth
        router.data = {'w': 'Bandwidth=5000 Measured=4800'}
        bw, measured = self.vanguard_set._parse_bandwidth(router)
        self.assertEqual(bw, 4800)
        self.assertTrue(measured)
        
        # Test with only advertised bandwidth
        router.data = {'w': 'Bandwidth=5000 Unmeasured=1'}
        bw, measured = self.vanguard_set._parse_bandwidth(router)
        self.assertEqual(bw, 5000)
        self.assertFalse(measured)
        
        # Test with no bandwidth data
        router.data = {}
        bw, measured = self.vanguard_set._parse_bandwidth(router)
        self.assertEqual(bw, 0)
        self.assertFalse(measured)
    
    def test_get_bandwidth_weight(self):
        """Test bandwidth weight calculation."""
        router = Mock()
        router.data = {'w': 'Bandwidth=5000 Measured=4800'}
        
        weight = self.vanguard_set._get_bandwidth_weight(router)
        self.assertEqual(weight, 4800.0)
    
    def test_select_bandwidth_weighted(self):
        """Test weighted selection algorithm."""
        # Create routers with different bandwidths
        high_bw_router = Mock()
        high_bw_router.data = {'w': 'Bandwidth=10000 Measured=9500'}
        high_bw_router.flags = [Mock(name='Guard'), Mock(name='Fast'), 
                               Mock(name='Stable'), Mock(name='Running')]
        
        low_bw_router = Mock()
        low_bw_router.data = {'w': 'Bandwidth=1000'}
        low_bw_router.flags = [Mock(name='Fast'), Mock(name='Stable'), 
                              Mock(name='Running')]
        
        candidates = [high_bw_router, low_bw_router]
        
        # Select multiple times and count
        selections = {'high': 0, 'low': 0}
        for _ in range(100):
            selected = self.vanguard_set._select_bandwidth_weighted(candidates)
            if selected == high_bw_router:
                selections['high'] += 1
            else:
                selections['low'] += 1
        
        # High bandwidth router should be selected more often
        self.assertGreater(selections['high'], selections['low'])
    
    def test_guard_flag_preference(self):
        """Test Guard flag preference in selection."""
        guard_router = Mock()
        guard_router.data = {'w': 'Bandwidth=5000'}
        guard_router.flags = [Mock(name='Guard'), Mock(name='Fast'),
                            Mock(name='Stable'), Mock(name='Running')]
        
        non_guard_router = Mock()
        non_guard_router.data = {'w': 'Bandwidth=5000'}
        non_guard_router.flags = [Mock(name='Fast'), Mock(name='Stable'),
                                 Mock(name='Running')]
        
        candidates = [guard_router, non_guard_router]
        
        # With preference, Guard should be selected more often
        guard_selections = 0
        for _ in range(100):
            selected = self.vanguard_set._select_bandwidth_weighted(
                candidates, prefer_guard_flag=True
            )
            if selected == guard_router:
                guard_selections += 1
        
        # Should prefer guard (at least 60% due to 75/25 split)
        self.assertGreater(guard_selections, 60)


class TestMaxDistribution(unittest.TestCase):
    """Test max(X,X) distribution for rotation."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_consensus = Mock()
        self.vanguard_set = VanguardSet(VanguardLayer.LAYER2, self.mock_consensus)
    
    def test_max_distribution_skew(self):
        """Test that max(X,X) distribution skews toward higher values."""
        # Generate many samples
        samples = [self.vanguard_set._generate_max_distribution_lifetime() 
                  for _ in range(1000)]
        
        avg = sum(samples) / len(samples)
        midpoint = (self.vanguard_set.lifetime_min + self.vanguard_set.lifetime_max) / 2
        
        # Average should be above midpoint due to max() skew
        self.assertGreater(avg, midpoint)
        
        # All samples should be within range
        self.assertTrue(all(self.vanguard_set.lifetime_min <= s <= self.vanguard_set.lifetime_max 
                          for s in samples))


class TestFlagBasedReplacement(unittest.TestCase):
    """Test flag-based node replacement."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_consensus = Mock()
        self.vanguard_set = VanguardSet(VanguardLayer.LAYER2, self.mock_consensus)
    
    @patch.object(VanguardSet, '_select_new_vanguard')
    def test_rotate_removes_flag_loss_nodes(self, mock_select):
        """Test that rotation removes nodes that lost flags."""
        # Create a node with flags
        good_router = Mock()
        good_router.fingerprint = 'A' * 40
        good_router.flags = [Mock(name='Fast'), Mock(name='Stable'),
                           Mock(name='Running'), Mock(name='Valid')]
        good_node = VanguardNode(good_router, VanguardLayer.LAYER2, 1000)
        
        # Create a node that will lose flags
        bad_router = Mock()
        bad_router.fingerprint = 'B' * 40
        bad_router.flags = [Mock(name='Fast'), Mock(name='Running')]  # Missing Stable
        bad_node = VanguardNode(bad_router, VanguardLayer.LAYER2, 1000)
        
        self.vanguard_set.nodes = [good_node, bad_node]
        
        # Mock replacement
        replacement_router = Mock()
        replacement_router.fingerprint = 'C' * 40
        mock_select.return_value = VanguardNode(replacement_router, VanguardLayer.LAYER2, 1000)
        
        # Rotate with flag check
        self.vanguard_set.rotate(force_flag_check=True)
        
        # Bad node should be removed
        fingerprints = [n.fingerprint for n in self.vanguard_set.nodes]
        self.assertNotIn('B' * 40, fingerprints)
        self.assertIn('A' * 40, fingerprints)


class TestCircuitTracking(unittest.TestCase):
    """Test circuit usage tracking."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_consensus = Mock()
        self.vanguard_set = VanguardSet(VanguardLayer.LAYER2, self.mock_consensus)
    
    def test_mark_circuit_use(self):
        """Test marking circuit usage."""
        router = Mock()
        router.fingerprint = 'A' * 40
        router.flags = [Mock(name='Fast'), Mock(name='Stable'),
                       Mock(name='Running'), Mock(name='Valid')]
        node = VanguardNode(router, VanguardLayer.LAYER2, 1000)
        
        self.vanguard_set.nodes = [node]
        
        # Mark successful use
        self.vanguard_set.mark_circuit_use('A' * 40, success=True)
        self.assertEqual(node.circuit_count, 1)
        self.assertEqual(node.failed_count, 0)
        
        # Mark failed use
        self.vanguard_set.mark_circuit_use('A' * 40, success=False)
        self.assertEqual(node.circuit_count, 2)
        self.assertEqual(node.failed_count, 1)
    
    def test_get_node_by_fingerprint(self):
        """Test retrieving node by fingerprint."""
        router = Mock()
        router.fingerprint = 'A' * 40
        node = VanguardNode(router, VanguardLayer.LAYER2, 1000)
        
        self.vanguard_set.nodes = [node]
        
        found = self.vanguard_set.get_node_by_fingerprint('A' * 40)
        self.assertEqual(found, node)
        
        not_found = self.vanguard_set.get_node_by_fingerprint('B' * 40)
        self.assertIsNone(not_found)
    
    def test_get_stats_includes_circuit_info(self):
        """Test that statistics include circuit tracking info."""
        router = Mock()
        router.fingerprint = 'A' * 40
        router.nickname = 'TestRelay'
        router.flags = [Mock(name='Guard'), Mock(name='Fast')]
        router.data = {'w': 'Bandwidth=5000'}
        
        node = VanguardNode(router, VanguardLayer.LAYER2, 1000)
        node.circuit_count = 10
        node.failed_count = 2
        
        self.vanguard_set.nodes = [node]
        
        stats = self.vanguard_set.get_stats()
        
        self.assertEqual(stats['total_circuits'], 10)
        self.assertEqual(stats['total_failures'], 2)
        self.assertAlmostEqual(stats['failure_rate'], 0.2, places=2)
        
        node_stats = stats['nodes'][0]
        self.assertEqual(node_stats['circuit_count'], 10)
        self.assertEqual(node_stats['failed_count'], 2)
        self.assertIn('bandwidth_kb', node_stats)
        self.assertIn('has_guard_flag', node_stats)


class TestVanguardManager(unittest.TestCase):
    """Test VanguardManager with circuit tracking."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_consensus = Mock()
        self.manager = VanguardManager(self.mock_consensus)
    
    def test_mark_circuit_use(self):
        """Test circuit usage tracking in manager."""
        # Mark some circuit uses
        self.manager.mark_circuit_use(VanguardLayer.LAYER2, 'A' * 40, 
                                     purpose=CircuitPurpose.CLIENT_REND)
        self.manager.mark_circuit_use(VanguardLayer.LAYER3, 'B' * 40,
                                     purpose=CircuitPurpose.CLIENT_INTRO)
        
        # Check purpose tracking
        self.assertEqual(self.manager._circuit_purposes[CircuitPurpose.CLIENT_REND], 1)
        self.assertEqual(self.manager._circuit_purposes[CircuitPurpose.CLIENT_INTRO], 1)
    
    def test_get_vanguard_path(self):
        """Test vanguard path retrieval for different purposes."""
        self.manager._enabled = True
        
        # Mock layer nodes
        l2_node = Mock()
        l3_node = Mock()
        self.manager.layer2.get_random_node = Mock(return_value=l2_node)
        self.manager.layer3.get_random_node = Mock(return_value=l3_node)
        
        # Test client rendezvous (no extra hop)
        path = self.manager.get_vanguard_path(CircuitPurpose.CLIENT_REND)
        self.assertFalse(path['needs_extra_hop'])
        self.assertEqual(path['layer2'], l2_node)
        self.assertEqual(path['layer3'], l3_node)
        
        # Test client intro (needs extra hop)
        path = self.manager.get_vanguard_path(CircuitPurpose.CLIENT_INTRO)
        self.assertTrue(path['needs_extra_hop'])
        
        # Test service rendezvous (needs extra hop)
        path = self.manager.get_vanguard_path(CircuitPurpose.SERVICE_REND)
        self.assertTrue(path['needs_extra_hop'])
    
    def test_force_rotation(self):
        """Test manual rotation trigger."""
        # Mock rotation methods
        self.manager.layer2.rotate = Mock()
        self.manager.layer3.rotate = Mock()
        
        # Force rotation
        self.manager.force_rotation()
        
        # Both layers should be rotated with flag check
        self.manager.layer2.rotate.assert_called_once_with(force_flag_check=True)
        self.manager.layer3.rotate.assert_called_once_with(force_flag_check=True)
        
        # Test layer-specific rotation
        self.manager.layer2.rotate.reset_mock()
        self.manager.layer3.rotate.reset_mock()
        
        self.manager.force_rotation(layer=VanguardLayer.LAYER2)
        self.manager.layer2.rotate.assert_called_once()
        self.manager.layer3.rotate.assert_not_called()
    
    def test_get_stats_includes_purposes(self):
        """Test that stats include circuit purpose tracking."""
        self.manager.mark_circuit_use(VanguardLayer.LAYER2, 'A' * 40,
                                     purpose=CircuitPurpose.CLIENT_REND)
        self.manager.mark_circuit_use(VanguardLayer.LAYER2, 'A' * 40,
                                     purpose=CircuitPurpose.CLIENT_REND)
        
        stats = self.manager.get_stats()
        
        self.assertIn('circuit_purposes', stats)
        self.assertEqual(stats['circuit_purposes'][CircuitPurpose.CLIENT_REND], 2)


class TestCircuitPurposes(unittest.TestCase):
    """Test circuit purpose constants."""
    
    def test_purpose_constants_exist(self):
        """Test that all purpose constants are defined."""
        purposes = [
            CircuitPurpose.CLIENT_REND,
            CircuitPurpose.CLIENT_INTRO,
            CircuitPurpose.CLIENT_HSDIR,
            CircuitPurpose.SERVICE_REND,
            CircuitPurpose.SERVICE_INTRO,
            CircuitPurpose.SERVICE_HSDIR,
            CircuitPurpose.NORMAL,
        ]
        
        for purpose in purposes:
            self.assertIsNotNone(purpose)
            self.assertIsInstance(purpose, str)


class TestVanguardIntegration(unittest.TestCase):
    """Integration tests for vanguard system."""
    
    @patch.object(VanguardSet, '_select_new_vanguard')
    def test_full_lifecycle(self, mock_select):
        """Test full vanguard lifecycle."""
        mock_consensus = Mock()
        
        # Mock node selection
        def create_mock_node():
            router = Mock()
            router.fingerprint = f'{hash(time.time())}' * 8
            router.nickname = 'TestRelay'
            router.flags = [Mock(name='Fast'), Mock(name='Stable'),
                          Mock(name='Running'), Mock(name='Valid')]
            router.data = {'w': 'Bandwidth=5000'}
            return VanguardNode(router, VanguardLayer.LAYER2, 1000)
        
        mock_select.side_effect = lambda: create_mock_node()
        
        manager = VanguardManager(mock_consensus)
        
        # Enable
        manager.enable()
        self.assertTrue(manager.is_enabled)
        
        # Get nodes
        l2 = manager.get_layer2_node()
        l3 = manager.get_layer3_node()
        self.assertIsNotNone(l2)
        self.assertIsNotNone(l3)
        
        # Track usage
        if l2 is not None:
            manager.mark_circuit_use(VanguardLayer.LAYER2, l2.fingerprint,
                                    purpose=CircuitPurpose.CLIENT_REND)
        
        # Get stats
        stats = manager.get_stats()
        self.assertTrue(stats['enabled'])
        self.assertGreater(stats['layer2']['node_count'], 0)
        self.assertGreater(stats['layer3']['node_count'], 0)
        
        # Disable
        manager.disable()
        self.assertFalse(manager.is_enabled)


if __name__ == '__main__':
    unittest.main()
