#!/usr/bin/env python3
"""
Example demonstrating full Vanguards implementation with:
- Bandwidth-weighted node selection
- Circuit tracking and statistics
- Manual rotation capabilities
- Circuit purpose differentiation
"""

import time
import logging
from torpy import TorClient
from torpy.vanguards import VanguardManager, CircuitPurpose, VanguardLayer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def example_basic_vanguards():
    """Basic vanguards example with automatic rotation."""
    print("\n=== Basic Vanguards Example ===")
    
    with TorClient() as tor:
        consensus = tor.get_consensus()
        
        # Use context manager for automatic cleanup
        with VanguardManager(consensus) as vanguards:
            print(f"Vanguards enabled: {vanguards.is_enabled}")
            
            # Get statistics after initialization
            stats = vanguards.get_stats()
            print(f"\nLayer 2: {stats['layer2']['node_count']} nodes")
            print(f"Layer 3: {stats['layer3']['node_count']} nodes")
            
            # Show bandwidth distribution
            print("\nLayer 2 Vanguards:")
            for node_stats in stats['layer2']['nodes'][:3]:  # Show first 3
                print(f"  {node_stats['nickname']}: "
                      f"{node_stats['bandwidth_kb']:.0f} KB/s, "
                      f"Guard={node_stats['has_guard_flag']}")
            
            print("\nLayer 3 Vanguards:")
            for node_stats in stats['layer3']['nodes'][:3]:  # Show first 3
                print(f"  {node_stats['nickname']}: "
                      f"{node_stats['bandwidth_kb']:.0f} KB/s, "
                      f"Guard={node_stats['has_guard_flag']}")
            
            # Simulate getting nodes for circuit building
            print("\n--- Simulating Circuit Building ---")
            l2_node = vanguards.get_layer2_node()
            l3_node = vanguards.get_layer3_node()
            
            if l2_node and l3_node:
                print(f"Selected Layer 2: {l2_node.router.nickname}")
                print(f"Selected Layer 3: {l3_node.router.nickname}")
                
                # Mark circuit usage
                vanguards.mark_circuit_use(
                    VanguardLayer.LAYER2, 
                    l2_node.fingerprint,
                    purpose=CircuitPurpose.CLIENT_REND,
                    success=True
                )
                vanguards.mark_circuit_use(
                    VanguardLayer.LAYER3,
                    l3_node.fingerprint,
                    purpose=CircuitPurpose.CLIENT_REND,
                    success=True
                )
                
                print("Circuit usage tracked successfully")


def example_circuit_purposes():
    """Demonstrate different circuit purposes with vanguards."""
    print("\n=== Circuit Purpose Differentiation ===")
    
    with TorClient() as tor:
        consensus = tor.get_consensus()
        
        with VanguardManager(consensus) as vanguards:
            # Test different circuit purposes
            purposes = [
                CircuitPurpose.CLIENT_REND,
                CircuitPurpose.CLIENT_INTRO,
                CircuitPurpose.CLIENT_HSDIR,
                CircuitPurpose.SERVICE_REND,
            ]
            
            print("\nCircuit purpose requirements:")
            for purpose in purposes:
                path_info = vanguards.get_vanguard_path(purpose)
                extra_hop = "YES" if path_info['needs_extra_hop'] else "NO"
                print(f"  {purpose:20s}: Extra middle hop = {extra_hop}")
                
                # Track the usage
                if path_info.get('layer2'):
                    vanguards.mark_circuit_use(
                        VanguardLayer.LAYER2,
                        path_info['layer2'].fingerprint,
                        purpose=purpose
                    )
            
            # Show purpose statistics
            stats = vanguards.get_stats()
            print("\nCircuit purpose usage:")
            for purpose, count in stats['circuit_purposes'].items():
                print(f"  {purpose}: {count} circuits")


def example_bandwidth_weighting():
    """Show bandwidth-weighted selection in action."""
    print("\n=== Bandwidth-Weighted Selection ===")
    
    with TorClient() as tor:
        consensus = tor.get_consensus()
        
        with VanguardManager(consensus) as vanguards:
            stats = vanguards.get_stats()
            
            # Analyze bandwidth distribution
            l2_bandwidths = [n['bandwidth_kb'] for n in stats['layer2']['nodes']]
            l3_bandwidths = [n['bandwidth_kb'] for n in stats['layer3']['nodes']]
            
            print(f"\nLayer 2 bandwidth statistics:")
            print(f"  Average: {sum(l2_bandwidths) / len(l2_bandwidths):.0f} KB/s")
            print(f"  Min: {min(l2_bandwidths):.0f} KB/s")
            print(f"  Max: {max(l2_bandwidths):.0f} KB/s")
            
            print(f"\nLayer 3 bandwidth statistics:")
            print(f"  Average: {sum(l3_bandwidths) / len(l3_bandwidths):.0f} KB/s")
            print(f"  Min: {min(l3_bandwidths):.0f} KB/s")
            print(f"  Max: {max(l3_bandwidths):.0f} KB/s")
            
            # Show Guard flag distribution
            l2_guards = sum(1 for n in stats['layer2']['nodes'] if n['has_guard_flag'])
            l3_guards = sum(1 for n in stats['layer3']['nodes'] if n['has_guard_flag'])
            
            print(f"\nGuard flag distribution:")
            print(f"  Layer 2: {l2_guards}/{len(stats['layer2']['nodes'])} nodes have Guard flag")
            print(f"  Layer 3: {l3_guards}/{len(stats['layer3']['nodes'])} nodes have Guard flag")


def example_rotation_and_tracking():
    """Demonstrate rotation and usage tracking."""
    print("\n=== Rotation and Usage Tracking ===")
    
    with TorClient() as tor:
        consensus = tor.get_consensus()
        
        with VanguardManager(consensus) as vanguards:
            # Simulate circuit usage
            print("\nSimulating circuit usage...")
            for i in range(10):
                l2_node = vanguards.get_layer2_node()
                l3_node = vanguards.get_layer3_node()
                
                if l2_node and l3_node:
                    # Simulate success/failure (90% success rate)
                    success = (i % 10 != 0)
                    
                    vanguards.mark_circuit_use(
                        VanguardLayer.LAYER2,
                        l2_node.fingerprint,
                        success=success
                    )
                    vanguards.mark_circuit_use(
                        VanguardLayer.LAYER3,
                        l3_node.fingerprint,
                        success=success
                    )
            
            # Show usage statistics
            stats = vanguards.get_stats()
            print(f"\nTotal circuits tracked: {stats['total_circuits']}")
            print(f"Total failures: {stats['total_failures']}")
            print(f"Overall success rate: {100 * (1 - stats['total_failures'] / max(stats['total_circuits'], 1)):.1f}%")
            
            # Show most-used vanguards
            print("\nMost-used Layer 2 vanguards:")
            l2_sorted = sorted(stats['layer2']['nodes'], 
                             key=lambda n: n['circuit_count'], 
                             reverse=True)
            for node in l2_sorted[:3]:
                print(f"  {node['nickname']}: {node['circuit_count']} circuits, "
                      f"{node['failed_count']} failures")
            
            # Manual rotation
            print("\nTriggering manual rotation with flag check...")
            vanguards.force_rotation()
            
            stats_after = vanguards.get_stats()
            if stats_after['layer2']['last_rotation'] != stats['layer2']['last_rotation']:
                print("Layer 2 rotation completed")
            if stats_after['layer3']['last_rotation'] != stats['layer3']['last_rotation']:
                print("Layer 3 rotation completed")


def example_expiry_tracking():
    """Show vanguard expiry times and rotation scheduling."""
    print("\n=== Expiry Tracking and Rotation Schedule ===")
    
    with TorClient() as tor:
        consensus = tor.get_consensus()
        
        with VanguardManager(consensus) as vanguards:
            stats = vanguards.get_stats()
            
            # Layer 2 expiry times
            print("\nLayer 2 vanguard expiry times:")
            l2_expiries = sorted(
                [(n['nickname'], n['time_until_expiry_hours']) 
                 for n in stats['layer2']['nodes']],
                key=lambda x: x[1]
            )
            for nickname, hours in l2_expiries[:5]:
                days = hours / 24
                print(f"  {nickname:20s}: {days:.1f} days")
            
            # Layer 3 expiry times
            print("\nLayer 3 vanguard expiry times:")
            l3_expiries = sorted(
                [(n['nickname'], n['time_until_expiry_hours']) 
                 for n in stats['layer3']['nodes']],
                key=lambda x: x[1]
            )
            for nickname, hours in l3_expiries[:5]:
                print(f"  {nickname:20s}: {hours:.1f} hours")
            
            # Show average lifetimes (demonstrates max(X,X) distribution)
            l2_avg = sum(n['time_until_expiry_hours'] for n in stats['layer2']['nodes']) / len(stats['layer2']['nodes'])
            l3_avg = sum(n['time_until_expiry_hours'] for n in stats['layer3']['nodes']) / len(stats['layer3']['nodes'])
            
            l2_range_avg = (vanguards.layer2.lifetime_min + vanguards.layer2.lifetime_max) / 2
            l3_range_avg = (vanguards.layer3.lifetime_min + vanguards.layer3.lifetime_max) / 2
            
            print(f"\nLifetime statistics (demonstrates max(X,X) distribution):")
            print(f"  Layer 2: Average={l2_avg/24:.1f} days (range midpoint={l2_range_avg/24:.1f} days)")
            print(f"  Layer 3: Average={l3_avg/24:.1f} days (range midpoint={l3_range_avg/24:.1f} days)")
            print(f"  Note: max(X,X) skews averages toward higher values for better security")


def example_flag_monitoring():
    """Demonstrate flag-based node monitoring."""
    print("\n=== Flag-Based Node Monitoring ===")
    
    with TorClient() as tor:
        consensus = tor.get_consensus()
        
        with VanguardManager(consensus) as vanguards:
            stats = vanguards.get_stats()
            
            print("\nChecking vanguard node flags:")
            print("\nLayer 2:")
            for node in stats['layer2']['nodes'][:3]:
                flags_ok = "✓" if node['has_required_flags'] else "✗"
                print(f"  {node['nickname']:20s}: Flags {flags_ok}, "
                      f"BW={node['bandwidth_kb']:.0f} KB/s")
            
            print("\nLayer 3:")
            for node in stats['layer3']['nodes'][:3]:
                flags_ok = "✓" if node['has_required_flags'] else "✗"
                print(f"  {node['nickname']:20s}: Flags {flags_ok}, "
                      f"BW={node['bandwidth_kb']:.0f} KB/s")
            
            print("\nNote: Nodes that lose Fast or Stable flags will be")
            print("      automatically replaced during the next rotation check.")


def main():
    """Run all examples."""
    examples = [
        example_basic_vanguards,
        example_circuit_purposes,
        example_bandwidth_weighting,
        example_rotation_and_tracking,
        example_expiry_tracking,
        example_flag_monitoring,
    ]
    
    for example in examples:
        try:
            example()
            print("\n" + "="*60)
        except KeyboardInterrupt:
            print("\n\nInterrupted by user")
            break
        except Exception as e:
            logger.exception(f"Error in {example.__name__}: {e}")


if __name__ == '__main__':
    main()
