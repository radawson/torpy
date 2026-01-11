#!/usr/bin/env python3
"""
Quick verification script for full Conflux implementation.
Tests key features without requiring actual Tor circuits.
"""

from torpy.conflux import (
    ConfluxCircuitSet,
    ConfluxManager,
    ConfluxAlgorithm,
    INITIAL_CWND,
)
from unittest.mock import Mock

def verify_basic_features():
    """Verify basic Conflux features work."""
    print("Testing basic Conflux features...")
    
    # Create mock circuits
    circuit1 = Mock()
    circuit1.id = 0x1234
    circuit2 = Mock()
    circuit2.id = 0x5678
    
    # Test sequence tracking
    conflux_set = ConfluxCircuitSet()
    seq1 = conflux_set.allocate_sequence_number()
    seq2 = conflux_set.allocate_sequence_number()
    assert seq1 == 0 and seq2 == 1, "Sequence allocation failed"
    print("✓ Sequence tracking works")
    
    # Test circuit addition with congestion control
    conflux_set.add_circuit(circuit1)
    assert conflux_set._circuit_cwnd[id(circuit1)] == INITIAL_CWND, "CWND initialization failed"
    print("✓ Congestion control initialization works")
    
    # Test AIMD increase
    conflux_set.mark_packet_sent(circuit1)
    conflux_set.mark_packet_acked(circuit1)
    new_cwnd = conflux_set._circuit_cwnd[id(circuit1)]
    assert new_cwnd > INITIAL_CWND, "AIMD increase failed"
    print("✓ AIMD congestion window increase works")
    
    # Test AIMD decrease
    for _ in range(10):
        conflux_set.mark_packet_sent(circuit1)
        conflux_set.mark_packet_acked(circuit1)
    cwnd_before = conflux_set._circuit_cwnd[id(circuit1)]
    conflux_set.mark_packet_sent(circuit1)
    conflux_set.mark_packet_lost(circuit1)
    cwnd_after = conflux_set._circuit_cwnd[id(circuit1)]
    assert cwnd_after < cwnd_before, "AIMD decrease failed"
    print("✓ AIMD congestion window decrease works")
    
    # Test out-of-order delivery
    conflux_set2 = ConfluxCircuitSet()
    delivered = conflux_set2.receive_data(0, b'Packet 0')
    assert len(delivered) == 1, "In-order delivery failed"
    
    delivered = conflux_set2.receive_data(2, b'Packet 2')
    assert len(delivered) == 0, "Out-of-order buffering failed"
    
    delivered = conflux_set2.receive_data(1, b'Packet 1')
    assert len(delivered) == 2, "Out-of-order reordering failed"
    print("✓ Out-of-order packet handling works")
    
    # Test circuit selection algorithms
    for algo in ConfluxAlgorithm:
        cs = ConfluxCircuitSet(algorithm=algo)
        cs.add_circuit(circuit1)
        cs.add_circuit(circuit2)
        selected = cs.select_circuit()
        assert selected is not None, f"Algorithm {algo.name} failed"
    print("✓ All traffic distribution algorithms work")
    
    # Test linking
    conflux_set3 = ConfluxCircuitSet()
    conflux_set3.add_circuit(circuit1)
    conflux_set3.add_circuit(circuit2)
    result = conflux_set3.link_circuits()
    assert result is True, "Circuit linking failed"
    assert conflux_set3.is_linked, "Circuit linking state failed"
    print("✓ Circuit linking works")
    
    # Test statistics
    stats = conflux_set3.get_stats()
    assert 'next_seq_send' in stats, "Statistics missing sequence info"
    assert 'circuits' in stats, "Statistics missing circuit info"
    assert 'cwnd' in stats['circuits'][0], "Statistics missing CWND"
    print("✓ Statistics collection works")
    
    print("\n✅ All basic features verified!")


def verify_manager():
    """Verify ConfluxManager features."""
    print("\nTesting ConfluxManager...")
    
    manager = ConfluxManager(enable_health_monitoring=False)
    
    # Test set creation
    set1 = manager.create_set(algorithm=ConfluxAlgorithm.WEIGHTED)
    assert set1.set_id in manager._sets, "Set creation failed"
    print("✓ Set creation works")
    
    # Test set retrieval
    retrieved = manager.get_set(set1.set_id)
    assert retrieved == set1, "Set retrieval failed"
    print("✓ Set retrieval works")
    
    # Test total stats
    stats = manager.get_total_stats()
    assert stats['total_sets'] == 1, "Total stats failed"
    print("✓ Total statistics work")
    
    # Test context manager
    with ConfluxManager(enable_health_monitoring=False) as mgr:
        conflux_set = mgr.create_set()
        assert conflux_set is not None, "Context manager failed"
    print("✓ Context manager works")
    
    print("\n✅ Manager features verified!")


if __name__ == '__main__':
    try:
        verify_basic_features()
        verify_manager()
        print("\n" + "="*60)
        print("🎉 Full Conflux implementation verified successfully!")
        print("="*60)
    except AssertionError as e:
        print(f"\n❌ Verification failed: {e}")
        exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
