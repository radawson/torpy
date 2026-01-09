#!/usr/bin/env python3
"""
Example demonstrating full Conflux implementation with:
- Sequence tracking for ordered delivery
- AIMD congestion control
- Circuit health monitoring
- Multiple traffic distribution algorithms
"""

import time
import logging
from torpy import TorClient
from torpy.conflux import ConfluxManager, ConfluxAlgorithm

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def example_basic_conflux():
    """Basic Conflux example with two circuits."""
    print("\n=== Basic Conflux Example ===")
    
    with TorClient() as tor:
        # Create two circuits to the same destination
        print("Building first circuit...")
        circuit1 = tor.create_circuit(3)
        
        print("Building second circuit...")
        circuit2 = tor.create_circuit(3)
        
        # Create Conflux manager
        with ConfluxManager() as manager:
            # Create a Conflux set with round-robin algorithm
            conflux_set = manager.create_set(algorithm=ConfluxAlgorithm.ROUND_ROBIN)
            
            # Add circuits to the set
            conflux_set.add_circuit(circuit1)
            conflux_set.add_circuit(circuit2)
            
            # Link circuits together
            if conflux_set.link_circuits():
                print(f"Successfully linked {conflux_set.circuit_count} circuits")
            
            # Simulate sending data
            for i in range(10):
                # Allocate sequence number
                seq = conflux_set.allocate_sequence_number()
                
                # Select circuit using algorithm
                circuit = conflux_set.select_circuit()
                
                # Mark packet as sent (for congestion control)
                conflux_set.mark_packet_sent(circuit)
                
                print(f"Sending packet {seq} on circuit #{circuit.id}")
                
                # Simulate RTT and acknowledgment
                time.sleep(0.01)
                conflux_set.update_circuit_stats(circuit, bytes_sent=512, rtt=0.05)
                conflux_set.mark_packet_acked(circuit)
            
            # Get statistics
            stats = conflux_set.get_stats()
            print(f"\nConflux Set Statistics:")
            print(f"  Total bytes: {stats['total_bytes']}")
            print(f"  Total cells: {stats['total_cells']}")
            print(f"  Algorithm: {stats['algorithm']}")
            print(f"  Buffered packets: {stats['buffered_packets']}")
            
            for circuit_stats in stats['circuits']:
                print(f"\n  Circuit #{circuit_stats['circuit_id']:x}:")
                print(f"    Bytes sent: {circuit_stats['bytes_sent']}")
                print(f"    Cells sent: {circuit_stats['cells_sent']}")
                print(f"    RTT: {circuit_stats['rtt']:.4f}s" if circuit_stats['rtt'] else "    RTT: N/A")
                print(f"    CWND: {circuit_stats['cwnd']:.1f}")
                print(f"    In-flight: {circuit_stats['in_flight']}")


def example_weighted_conflux():
    """Conflux with weighted algorithm based on RTT."""
    print("\n=== Weighted Conflux Example ===")
    
    with TorClient() as tor:
        # Create three circuits
        circuits = [tor.create_circuit(3) for _ in range(3)]
        
        with ConfluxManager() as manager:
            # Create set with weighted algorithm
            conflux_set = manager.create_set(algorithm=ConfluxAlgorithm.WEIGHTED)
            
            # Add circuits
            for circuit in circuits:
                conflux_set.add_circuit(circuit)
            
            conflux_set.link_circuits()
            
            # Simulate different RTTs
            for i, circuit in enumerate(circuits):
                rtt = 0.05 + (i * 0.02)  # Different RTTs: 50ms, 70ms, 90ms
                conflux_set.update_circuit_stats(circuit, rtt=rtt)
                print(f"Circuit #{circuit.id:x}: RTT = {rtt*1000:.0f}ms")
            
            # Send data - weighted algorithm favors lower RTT circuits
            print("\nSending packets with weighted selection...")
            circuit_usage = {id(c): 0 for c in circuits}
            
            for _ in range(100):
                seq = conflux_set.allocate_sequence_number()
                circuit = conflux_set.select_circuit()
                circuit_usage[id(circuit)] += 1
                conflux_set.mark_packet_sent(circuit)
                conflux_set.mark_packet_acked(circuit)
            
            print("\nCircuit usage distribution:")
            for circuit in circuits:
                usage = circuit_usage[id(circuit)]
                print(f"  Circuit #{circuit.id:x}: {usage} packets ({usage}%)")


def example_congestion_control():
    """Demonstrate AIMD congestion control."""
    print("\n=== AIMD Congestion Control Example ===")
    
    with TorClient() as tor:
        circuits = [tor.create_circuit(3) for _ in range(2)]
        
        with ConfluxManager() as manager:
            conflux_set = manager.create_set(algorithm=ConfluxAlgorithm.MIN_RTT_CWND)
            
            for circuit in circuits:
                conflux_set.add_circuit(circuit)
            
            conflux_set.link_circuits()
            
            # Simulate successful transmissions (CWND grows)
            print("Phase 1: Successful transmissions (CWND increases)")
            for i in range(20):
                circuit = conflux_set.select_circuit()
                conflux_set.mark_packet_sent(circuit)
                conflux_set.mark_packet_acked(circuit)
                
                stats = conflux_set.get_stats()
                cwnd = stats['circuits'][0]['cwnd']
                if i % 5 == 0:
                    print(f"  After {i} packets: CWND = {cwnd:.1f}")
            
            # Simulate packet loss (CWND decreases)
            print("\nPhase 2: Packet loss detected (CWND decreases)")
            circuit = circuits[0]
            initial_cwnd = conflux_set._circuit_cwnd[id(circuit)]
            
            conflux_set.mark_packet_sent(circuit)
            conflux_set.mark_packet_lost(circuit)  # Trigger multiplicative decrease
            
            final_cwnd = conflux_set._circuit_cwnd[id(circuit)]
            print(f"  CWND before loss: {initial_cwnd:.1f}")
            print(f"  CWND after loss: {final_cwnd:.1f}")
            print(f"  Reduction: {(1 - final_cwnd/initial_cwnd)*100:.1f}%")
            
            # Recovery phase
            print("\nPhase 3: Recovery (CWND increases again)")
            for i in range(10):
                conflux_set.mark_packet_sent(circuit)
                conflux_set.mark_packet_acked(circuit)
                
                cwnd = conflux_set._circuit_cwnd[id(circuit)]
                if i % 3 == 0:
                    print(f"  After {i} packets: CWND = {cwnd:.1f}")


def example_out_of_order_delivery():
    """Demonstrate out-of-order packet handling."""
    print("\n=== Out-of-Order Delivery Example ===")
    
    with TorClient() as tor:
        circuits = [tor.create_circuit(3) for _ in range(2)]
        
        with ConfluxManager() as manager:
            conflux_set = manager.create_set()
            
            for circuit in circuits:
                conflux_set.add_circuit(circuit)
            
            # Simulate out-of-order arrival
            print("Simulating out-of-order packet arrival:")
            
            # Packets arrive in order: 0, 2, 1, 3
            data_packets = [
                (0, b'Packet 0'),
                (2, b'Packet 2'),
                (1, b'Packet 1'),
                (3, b'Packet 3'),
            ]
            
            for seq, data in data_packets:
                delivered = conflux_set.receive_data(seq, data)
                
                if delivered:
                    print(f"  Received seq={seq}: Delivered {len(delivered)} packets")
                    for pkt in delivered:
                        print(f"    -> {pkt.decode()}")
                else:
                    print(f"  Received seq={seq}: Buffered (out of order)")
            
            stats = conflux_set.get_stats()
            print(f"\nFinal state:")
            print(f"  Next expected seq: {stats['next_seq_recv']}")
            print(f"  Buffered packets: {stats['buffered_packets']}")


def example_health_monitoring():
    """Demonstrate automatic circuit health monitoring."""
    print("\n=== Circuit Health Monitoring Example ===")
    
    with TorClient() as tor:
        circuits = [tor.create_circuit(3) for _ in range(3)]
        
        # Enable health monitoring
        with ConfluxManager(enable_health_monitoring=True) as manager:
            conflux_set = manager.create_set()
            
            for circuit in circuits:
                conflux_set.add_circuit(circuit)
            
            print(f"Added {len(circuits)} circuits to Conflux set")
            
            # Simulate activity on some circuits
            print("\nSimulating circuit activity...")
            conflux_set.update_circuit_stats(circuits[0], bytes_sent=1000)
            conflux_set.update_circuit_stats(circuits[1], bytes_sent=1000)
            # circuits[2] has no activity
            
            # Wait for health check
            print("Waiting for health monitoring...")
            time.sleep(6)  # HEALTH_CHECK_INTERVAL is 5 seconds
            
            # Check which circuits remain
            stats = conflux_set.get_stats()
            print(f"\nCircuits after health check: {stats['circuit_count']}")
            
            # Get manager statistics
            total_stats = manager.get_total_stats()
            print(f"\nManager Statistics:")
            print(f"  Total sets: {total_stats['total_sets']}")
            print(f"  Total circuits: {total_stats['total_circuits']}")
            print(f"  Health monitoring: {total_stats['health_monitoring']}")


def main():
    """Run all examples."""
    examples = [
        example_basic_conflux,
        example_weighted_conflux,
        example_congestion_control,
        example_out_of_order_delivery,
        example_health_monitoring,
    ]
    
    for example in examples:
        try:
            example()
            print("\n" + "="*60)
        except Exception as e:
            logger.exception(f"Error in {example.__name__}: {e}")


if __name__ == '__main__':
    main()
