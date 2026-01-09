"""
Unit tests for full Conflux implementation (Proposal 329).

Tests sequence tracking, AIMD congestion control, health monitoring,
and traffic distribution algorithms.
"""

import time
import unittest
from unittest.mock import Mock, MagicMock
from torpy.conflux import (
    ConfluxCircuitSet,
    ConfluxManager,
    ConfluxAlgorithm,
    ConfluxLinkState,
    INITIAL_CWND,
    MIN_CWND,
    MAX_CWND,
    MULTIPLICATIVE_DECREASE,
)


class TestConfluxCircuitSet(unittest.TestCase):
    """Test ConfluxCircuitSet with full specification."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.conflux_set = ConfluxCircuitSet()
        self.mock_circuit1 = Mock()
        self.mock_circuit1.id = 0x1234
        self.mock_circuit2 = Mock()
        self.mock_circuit2.id = 0x5678
    
    def test_add_circuit_initializes_congestion_control(self):
        """Test that adding a circuit initializes CWND and ssthresh."""
        self.conflux_set.add_circuit(self.mock_circuit1)
        
        circuit_id = id(self.mock_circuit1)
        self.assertEqual(self.conflux_set._circuit_cwnd[circuit_id], INITIAL_CWND)
        self.assertEqual(self.conflux_set._circuit_in_flight[circuit_id], 0)
        self.assertIn(circuit_id, self.conflux_set._last_active)
    
    def test_remove_circuit_cleans_up_state(self):
        """Test that removing a circuit cleans up all state."""
        self.conflux_set.add_circuit(self.mock_circuit1)
        circuit_id = id(self.mock_circuit1)
        
        self.conflux_set.remove_circuit(self.mock_circuit1)
        
        self.assertNotIn(circuit_id, self.conflux_set._circuit_cwnd)
        self.assertNotIn(circuit_id, self.conflux_set._circuit_in_flight)
        self.assertNotIn(circuit_id, self.conflux_set._last_active)
    
    def test_sequence_number_allocation(self):
        """Test sequence number allocation."""
        seq1 = self.conflux_set.allocate_sequence_number()
        seq2 = self.conflux_set.allocate_sequence_number()
        seq3 = self.conflux_set.allocate_sequence_number()
        
        self.assertEqual(seq1, 0)
        self.assertEqual(seq2, 1)
        self.assertEqual(seq3, 2)
    
    def test_receive_data_in_order(self):
        """Test receiving data packets in order."""
        data0 = b'Packet 0'
        data1 = b'Packet 1'
        data2 = b'Packet 2'
        
        # Receive in order
        delivered = self.conflux_set.receive_data(0, data0)
        self.assertEqual(delivered, [data0])
        
        delivered = self.conflux_set.receive_data(1, data1)
        self.assertEqual(delivered, [data1])
        
        delivered = self.conflux_set.receive_data(2, data2)
        self.assertEqual(delivered, [data2])
        
        self.assertEqual(self.conflux_set._next_seq_recv, 3)
    
    def test_receive_data_out_of_order(self):
        """Test receiving data packets out of order."""
        data0 = b'Packet 0'
        data1 = b'Packet 1'
        data2 = b'Packet 2'
        
        # Receive packet 0
        delivered = self.conflux_set.receive_data(0, data0)
        self.assertEqual(delivered, [data0])
        
        # Receive packet 2 (out of order)
        delivered = self.conflux_set.receive_data(2, data2)
        self.assertEqual(delivered, [])  # Buffered
        self.assertEqual(len(self.conflux_set._recv_buffer), 1)
        
        # Receive packet 1 (fills the gap)
        delivered = self.conflux_set.receive_data(1, data1)
        self.assertEqual(len(delivered), 2)  # Delivers both 1 and 2
        self.assertEqual(delivered, [data1, data2])
        self.assertEqual(len(self.conflux_set._recv_buffer), 0)
        self.assertEqual(self.conflux_set._next_seq_recv, 3)
    
    def test_receive_data_duplicate(self):
        """Test receiving duplicate packets."""
        data0 = b'Packet 0'
        
        delivered = self.conflux_set.receive_data(0, data0)
        self.assertEqual(delivered, [data0])
        
        # Try to receive packet 0 again
        delivered = self.conflux_set.receive_data(0, data0)
        self.assertEqual(delivered, [])  # Ignored
    
    def test_mark_packet_sent_increases_in_flight(self):
        """Test marking packets as sent increases in-flight counter."""
        self.conflux_set.add_circuit(self.mock_circuit1)
        circuit_id = id(self.mock_circuit1)
        
        self.assertEqual(self.conflux_set._circuit_in_flight[circuit_id], 0)
        
        self.conflux_set.mark_packet_sent(self.mock_circuit1)
        self.assertEqual(self.conflux_set._circuit_in_flight[circuit_id], 1)
        
        self.conflux_set.mark_packet_sent(self.mock_circuit1)
        self.assertEqual(self.conflux_set._circuit_in_flight[circuit_id], 2)
    
    def test_mark_packet_acked_increases_cwnd(self):
        """Test AIMD: acknowledgment increases CWND."""
        self.conflux_set.add_circuit(self.mock_circuit1)
        circuit_id = id(self.mock_circuit1)
        
        initial_cwnd = self.conflux_set._circuit_cwnd[circuit_id]
        
        self.conflux_set.mark_packet_sent(self.mock_circuit1)
        self.conflux_set.mark_packet_acked(self.mock_circuit1)
        
        new_cwnd = self.conflux_set._circuit_cwnd[circuit_id]
        self.assertGreater(new_cwnd, initial_cwnd)
        self.assertEqual(self.conflux_set._circuit_in_flight[circuit_id], 0)
    
    def test_mark_packet_lost_decreases_cwnd(self):
        """Test AIMD: packet loss decreases CWND."""
        self.conflux_set.add_circuit(self.mock_circuit1)
        circuit_id = id(self.mock_circuit1)
        
        # Grow CWND first
        for _ in range(10):
            self.conflux_set.mark_packet_sent(self.mock_circuit1)
            self.conflux_set.mark_packet_acked(self.mock_circuit1)
        
        cwnd_before = self.conflux_set._circuit_cwnd[circuit_id]
        
        self.conflux_set.mark_packet_sent(self.mock_circuit1)
        self.conflux_set.mark_packet_lost(self.mock_circuit1)
        
        cwnd_after = self.conflux_set._circuit_cwnd[circuit_id]
        self.assertLess(cwnd_after, cwnd_before)
        
        # Check multiplicative decrease
        expected_cwnd = max(cwnd_before * MULTIPLICATIVE_DECREASE, MIN_CWND)
        self.assertAlmostEqual(cwnd_after, expected_cwnd, places=1)
    
    def test_select_circuit_respects_congestion_window(self):
        """Test that circuit selection respects congestion windows."""
        self.conflux_set.add_circuit(self.mock_circuit1)
        self.conflux_set.add_circuit(self.mock_circuit2)
        
        circuit1_id = id(self.mock_circuit1)
        
        # Fill circuit1's congestion window
        cwnd = self.conflux_set._circuit_cwnd[circuit1_id]
        for _ in range(int(cwnd)):
            self.conflux_set.mark_packet_sent(self.mock_circuit1)
        
        # Should select circuit2 since circuit1 is congested
        selected = self.conflux_set.select_circuit()
        self.assertEqual(selected, self.mock_circuit2)
    
    def test_select_circuit_round_robin(self):
        """Test round-robin algorithm."""
        conflux_set = ConfluxCircuitSet(algorithm=ConfluxAlgorithm.ROUND_ROBIN)
        conflux_set.add_circuit(self.mock_circuit1)
        conflux_set.add_circuit(self.mock_circuit2)
        
        # Should alternate
        selections = [conflux_set.select_circuit() for _ in range(4)]
        self.assertEqual(selections[0], self.mock_circuit1)
        self.assertEqual(selections[1], self.mock_circuit2)
        self.assertEqual(selections[2], self.mock_circuit1)
        self.assertEqual(selections[3], self.mock_circuit2)
    
    def test_select_circuit_lowest_latency(self):
        """Test lowest latency algorithm."""
        conflux_set = ConfluxCircuitSet(algorithm=ConfluxAlgorithm.LOWEST_LATENCY)
        conflux_set.add_circuit(self.mock_circuit1)
        conflux_set.add_circuit(self.mock_circuit2)
        
        # Set different RTTs
        conflux_set.update_circuit_stats(self.mock_circuit1, rtt=0.1)
        conflux_set.update_circuit_stats(self.mock_circuit2, rtt=0.05)
        
        # Should always select circuit2 (lower RTT)
        for _ in range(5):
            selected = conflux_set.select_circuit()
            self.assertEqual(selected, self.mock_circuit2)
    
    def test_select_circuit_min_rtt_cwnd(self):
        """Test MIN_RTT_CWND algorithm."""
        conflux_set = ConfluxCircuitSet(algorithm=ConfluxAlgorithm.MIN_RTT_CWND)
        conflux_set.add_circuit(self.mock_circuit1)
        conflux_set.add_circuit(self.mock_circuit2)
        
        # Circuit1: low RTT, low CWND
        conflux_set.update_circuit_stats(self.mock_circuit1, rtt=0.05)
        conflux_set._circuit_cwnd[id(self.mock_circuit1)] = 10
        
        # Circuit2: higher RTT, higher CWND
        conflux_set.update_circuit_stats(self.mock_circuit2, rtt=0.1)
        conflux_set._circuit_cwnd[id(self.mock_circuit2)] = 50
        
        # Circuit1 should be selected (lower RTT/CWND ratio)
        selected = conflux_set.select_circuit()
        self.assertEqual(selected, self.mock_circuit1)
    
    def test_check_circuit_health_removes_failed(self):
        """Test health check removes failed circuits."""
        self.conflux_set.add_circuit(self.mock_circuit1)
        self.conflux_set.add_circuit(self.mock_circuit2)
        
        # Set circuit1 as inactive (timeout)
        circuit1_id = id(self.mock_circuit1)
        self.conflux_set._last_active[circuit1_id] = time.time() - 100
        self.conflux_set._retries[circuit1_id] = 999  # Max retries exceeded
        
        # Health check should remove circuit1
        failed = self.conflux_set.check_circuit_health()
        
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0], self.mock_circuit1)
        self.assertNotIn(self.mock_circuit1, self.conflux_set._circuits)
        self.assertIn(self.mock_circuit2, self.conflux_set._circuits)
    
    def test_link_circuits(self):
        """Test linking circuits."""
        self.conflux_set.add_circuit(self.mock_circuit1)
        self.conflux_set.add_circuit(self.mock_circuit2)
        
        result = self.conflux_set.link_circuits()
        
        self.assertTrue(result)
        self.assertTrue(self.conflux_set.is_linked)
    
    def test_link_circuits_requires_two_circuits(self):
        """Test that linking requires at least 2 circuits."""
        self.conflux_set.add_circuit(self.mock_circuit1)
        
        result = self.conflux_set.link_circuits()
        
        self.assertFalse(result)
        self.assertFalse(self.conflux_set.is_linked)
    
    def test_get_stats_includes_congestion_info(self):
        """Test that statistics include congestion control info."""
        self.conflux_set.add_circuit(self.mock_circuit1)
        self.conflux_set.mark_packet_sent(self.mock_circuit1)
        
        stats = self.conflux_set.get_stats()
        
        self.assertIn('next_seq_send', stats)
        self.assertIn('next_seq_recv', stats)
        self.assertIn('buffered_packets', stats)
        
        circuit_stats = stats['circuits'][0]
        self.assertIn('cwnd', circuit_stats)
        self.assertIn('ssthresh', circuit_stats)
        self.assertIn('in_flight', circuit_stats)
        self.assertEqual(circuit_stats['in_flight'], 1)


class TestConfluxManager(unittest.TestCase):
    """Test ConfluxManager with health monitoring."""
    
    def test_create_set(self):
        """Test creating a Conflux set."""
        manager = ConfluxManager(enable_health_monitoring=False)
        
        conflux_set = manager.create_set(algorithm=ConfluxAlgorithm.WEIGHTED)
        
        self.assertIsInstance(conflux_set, ConfluxCircuitSet)
        self.assertIn(conflux_set.set_id, manager._sets)
    
    def test_get_set(self):
        """Test retrieving a Conflux set."""
        manager = ConfluxManager(enable_health_monitoring=False)
        conflux_set = manager.create_set()
        
        retrieved = manager.get_set(conflux_set.set_id)
        
        self.assertEqual(retrieved, conflux_set)
    
    def test_remove_set(self):
        """Test removing a Conflux set."""
        manager = ConfluxManager(enable_health_monitoring=False)
        conflux_set = manager.create_set()
        
        manager.remove_set(conflux_set.set_id)
        
        self.assertNotIn(conflux_set.set_id, manager._sets)
    
    def test_get_all_sets(self):
        """Test getting all Conflux sets."""
        manager = ConfluxManager(enable_health_monitoring=False)
        set1 = manager.create_set()
        set2 = manager.create_set()
        
        all_sets = manager.get_all_sets()
        
        self.assertEqual(len(all_sets), 2)
        self.assertIn(set1, all_sets)
        self.assertIn(set2, all_sets)
    
    def test_context_manager(self):
        """Test using ConfluxManager as context manager."""
        with ConfluxManager(enable_health_monitoring=False) as manager:
            conflux_set = manager.create_set()
            self.assertIsNotNone(conflux_set)
        
        # Manager should be stopped after context exit
        self.assertFalse(manager._health_monitor_running)
    
    def test_health_monitoring_start_stop(self):
        """Test starting and stopping health monitoring."""
        manager = ConfluxManager(enable_health_monitoring=False)
        self.assertFalse(manager._health_monitor_running)
        
        manager.start_health_monitoring()
        self.assertTrue(manager._health_monitor_running)
        
        manager.stop_health_monitoring()
        self.assertFalse(manager._health_monitor_running)
    
    def test_get_total_stats(self):
        """Test getting total statistics."""
        manager = ConfluxManager(enable_health_monitoring=False)
        
        set1 = manager.create_set()
        mock_circuit = Mock()
        mock_circuit.id = 0x1234
        set1.add_circuit(mock_circuit)
        set1.update_circuit_stats(mock_circuit, bytes_sent=1000)
        
        stats = manager.get_total_stats()
        
        self.assertEqual(stats['total_sets'], 1)
        self.assertEqual(stats['total_circuits'], 1)
        self.assertEqual(stats['total_bytes'], 1000)
        self.assertIn('health_monitoring', stats)


class TestConfluxCongestionControl(unittest.TestCase):
    """Test AIMD congestion control algorithm."""
    
    def test_slow_start_phase(self):
        """Test slow start (exponential growth)."""
        conflux_set = ConfluxCircuitSet()
        mock_circuit = Mock()
        mock_circuit.id = 0x1234
        conflux_set.add_circuit(mock_circuit)
        
        circuit_id = id(mock_circuit)
        initial_cwnd = conflux_set._circuit_cwnd[circuit_id]
        ssthresh = conflux_set._circuit_ssthresh[circuit_id]
        
        # In slow start, CWND grows by 1 per ACK
        for _ in range(5):
            conflux_set.mark_packet_sent(mock_circuit)
            conflux_set.mark_packet_acked(mock_circuit)
        
        final_cwnd = conflux_set._circuit_cwnd[circuit_id]
        self.assertGreater(final_cwnd, initial_cwnd)
        self.assertLess(final_cwnd, ssthresh)  # Still in slow start
    
    def test_congestion_avoidance_phase(self):
        """Test congestion avoidance (linear growth)."""
        conflux_set = ConfluxCircuitSet()
        mock_circuit = Mock()
        mock_circuit.id = 0x1234
        conflux_set.add_circuit(mock_circuit)
        
        circuit_id = id(mock_circuit)
        
        # Set CWND above ssthresh to enter congestion avoidance
        conflux_set._circuit_cwnd[circuit_id] = 110
        conflux_set._circuit_ssthresh[circuit_id] = 100
        
        cwnd_before = conflux_set._circuit_cwnd[circuit_id]
        
        conflux_set.mark_packet_sent(mock_circuit)
        conflux_set.mark_packet_acked(mock_circuit)
        
        cwnd_after = conflux_set._circuit_cwnd[circuit_id]
        
        # Growth should be slower than slow start
        self.assertGreater(cwnd_after, cwnd_before)
        self.assertLess(cwnd_after - cwnd_before, 1.0)  # Linear growth
    
    def test_cwnd_never_exceeds_max(self):
        """Test that CWND never exceeds MAX_CWND."""
        conflux_set = ConfluxCircuitSet()
        mock_circuit = Mock()
        mock_circuit.id = 0x1234
        conflux_set.add_circuit(mock_circuit)
        
        circuit_id = id(mock_circuit)
        conflux_set._circuit_cwnd[circuit_id] = MAX_CWND - 1
        
        for _ in range(10):
            conflux_set.mark_packet_sent(mock_circuit)
            conflux_set.mark_packet_acked(mock_circuit)
        
        final_cwnd = conflux_set._circuit_cwnd[circuit_id]
        self.assertLessEqual(final_cwnd, MAX_CWND)
    
    def test_cwnd_never_below_min(self):
        """Test that CWND never goes below MIN_CWND."""
        conflux_set = ConfluxCircuitSet()
        mock_circuit = Mock()
        mock_circuit.id = 0x1234
        conflux_set.add_circuit(mock_circuit)
        
        circuit_id = id(mock_circuit)
        conflux_set._circuit_cwnd[circuit_id] = MIN_CWND + 1
        
        for _ in range(10):
            conflux_set.mark_packet_sent(mock_circuit)
            conflux_set.mark_packet_lost(mock_circuit)
        
        final_cwnd = conflux_set._circuit_cwnd[circuit_id]
        self.assertGreaterEqual(final_cwnd, MIN_CWND)


if __name__ == '__main__':
    unittest.main()
