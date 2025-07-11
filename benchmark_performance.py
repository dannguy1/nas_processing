#!/usr/bin/env python3
"""
Performance Benchmarking Script for NAS Log Processing System

This script tests the performance of the parser with different log sizes
and configurations to help users understand expected processing times.
"""

import time
import os
import tempfile
import subprocess
import sys
from pathlib import Path

def create_test_log(size_kb, output_file):
    """Create a test log file of specified size by repeating sample content."""
    sample_content = """2025 Jun  2  22:51:24.347 LTE NAS EMM ESM Plain OTA Outgoing Message  --  Attach request Msg
Bearer ID = 5
qci = 9
mcc_1 = 3
mcc_2 = 1
mcc_3 = 0
mnc_1 = 1
mnc_2 = 0
mnc_3 = 1
2025 Jun  2  22:51:24.459 LTE NAS EMM ESM Plain OTA Incoming Message  --  ESM information request Msg
Bearer ID = 5
qci = 9
2025 Jun  2  22:51:24.891 LTE NAS EMM ESM Plain OTA Incoming Message  --  Attach accept Msg
Bearer ID = 5
qci = 9
"""
    
    # Calculate how many repetitions needed to reach target size
    sample_size = len(sample_content.encode('utf-8'))
    repetitions = (size_kb * 1024) // sample_size
    
    with open(output_file, 'w') as f:
        for i in range(repetitions):
            f.write(sample_content)
    
    actual_size = os.path.getsize(output_file) / 1024
    return actual_size

def run_benchmark(log_file, output_file):
    """Run the parser and measure performance."""
    start_time = time.time()
    
    try:
        result = subprocess.run([
            sys.executable, '-m', 'src.main', 'parse',
            '-i', log_file,
            '-o', output_file
        ], capture_output=True, text=True, timeout=300)  # 5 minute timeout
        
        end_time = time.time()
        duration = end_time - start_time
        
        if result.returncode == 0:
            # Extract statistics from output
            lines = result.stdout.split('\n')
            stats = {}
            for line in lines:
                if 'Total lines processed:' in line:
                    stats['total_lines'] = int(line.split(':')[1].strip().replace(',', ''))
                elif 'Messages extracted:' in line:
                    stats['messages_extracted'] = int(line.split(':')[1].strip().replace(',', ''))
                elif 'Validation errors:' in line:
                    stats['validation_errors'] = int(line.split(':')[1].strip())
                elif 'File size:' in line:
                    stats['file_size_mb'] = float(line.split(':')[1].strip().replace(' MB', ''))
            
            return {
                'success': True,
                'duration': duration,
                'stats': stats,
                'error': None
            }
        else:
            return {
                'success': False,
                'duration': duration,
                'stats': {},
                'error': result.stderr
            }
    
    except subprocess.TimeoutExpired:
        return {
            'success': False,
            'duration': 300,
            'stats': {},
            'error': 'Timeout after 5 minutes'
        }
    except Exception as e:
        return {
            'success': False,
            'duration': 0,
            'stats': {},
            'error': str(e)
        }

def main():
    """Run performance benchmarks with different log sizes."""
    print("🚀 NAS Log Processing System - Performance Benchmark")
    print("=" * 60)
    
    # Test sizes in KB
    test_sizes = [1, 10, 100, 1000, 10000]  # 1KB to 10MB
    
    results = []
    
    for size_kb in test_sizes:
        print(f"\n📊 Testing {size_kb}KB log file...")
        
        # Create test log file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            log_file = f.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            output_file = f.name
        
        try:
            # Create test log
            actual_size = create_test_log(size_kb, log_file)
            print(f"   Created {actual_size:.1f}KB test log")
            
            # Run benchmark
            result = run_benchmark(log_file, output_file)
            
            if result['success']:
                stats = result['stats']
                lines_per_second = stats.get('total_lines', 0) / result['duration'] if result['duration'] > 0 else 0
                messages_per_second = stats.get('messages_extracted', 0) / result['duration'] if result['duration'] > 0 else 0
                
                print(f"   ✅ Success: {result['duration']:.3f}s")
                print(f"   📈 Performance: {lines_per_second:.0f} lines/sec, {messages_per_second:.0f} messages/sec")
                print(f"   📊 Results: {stats.get('messages_extracted', 0)} messages, {stats.get('validation_errors', 0)} errors")
                
                results.append({
                    'size_kb': actual_size,
                    'duration': result['duration'],
                    'lines_per_second': lines_per_second,
                    'messages_per_second': messages_per_second,
                    'messages_extracted': stats.get('messages_extracted', 0),
                    'validation_errors': stats.get('validation_errors', 0)
                })
            else:
                print(f"   ❌ Failed: {result['error']}")
                results.append({
                    'size_kb': actual_size,
                    'duration': result['duration'],
                    'lines_per_second': 0,
                    'messages_per_second': 0,
                    'messages_extracted': 0,
                    'validation_errors': 0,
                    'error': result['error']
                })
        
        finally:
            # Clean up temporary files
            try:
                os.unlink(log_file)
                os.unlink(output_file)
            except:
                pass
    
    # Print summary
    print("\n" + "=" * 60)
    print("📈 PERFORMANCE SUMMARY")
    print("=" * 60)
    print(f"{'Size (KB)':<10} {'Time (s)':<10} {'Lines/sec':<12} {'Msg/sec':<10} {'Messages':<10} {'Errors':<8}")
    print("-" * 60)
    
    for result in results:
        if 'error' in result:
            print(f"{result['size_kb']:<10.1f} {'FAILED':<10} {'-':<12} {'-':<10} {'-':<10} {'-':<8}")
        else:
            print(f"{result['size_kb']:<10.1f} {result['duration']:<10.3f} {result['lines_per_second']:<12.0f} {result['messages_per_second']:<10.0f} {result['messages_extracted']:<10} {result['validation_errors']:<8}")
    
    # Performance recommendations
    print("\n💡 PERFORMANCE RECOMMENDATIONS:")
    print("-" * 40)
    
    successful_results = [r for r in results if 'error' not in r]
    if successful_results:
        avg_lines_per_second = sum(r['lines_per_second'] for r in successful_results) / len(successful_results)
        avg_messages_per_second = sum(r['messages_per_second'] for r in successful_results) / len(successful_results)
        
        print(f"• Average processing speed: {avg_lines_per_second:.0f} lines/second")
        print(f"• Average message extraction: {avg_messages_per_second:.0f} messages/second")
        print(f"• For 1MB logs: Expect ~{1000/avg_lines_per_second:.1f} seconds")
        print(f"• For 10MB logs: Expect ~{10000/avg_lines_per_second:.1f} seconds")
        print(f"• For 100MB logs: Expect ~{100000/avg_lines_per_second:.1f} seconds")
    
    print("\n✅ Benchmark completed!")

if __name__ == "__main__":
    main() 