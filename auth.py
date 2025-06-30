#!/usr/bin/env python3
"""
Comprehensive MerkonDB Server Debugging Tools
"""

import socket
import struct
import json
import sys
import time
import threading
import select

class ServerDebugger:
    def __init__(self, host="localhost", port=8080):
        self.host = host
        self.port = port
    
    def test_connection_only(self):
        """Test basic TCP connection without sending data"""
        print("=== Testing Basic Connection ===")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            print(f"Connecting to {self.host}:{self.port}...")
            sock.connect((self.host, self.port))
            print("✓ TCP connection established")
            
            # Just wait a bit to see if server closes connection immediately
            time.sleep(1)
            print("✓ Connection remained open for 1 second")
            
            sock.close()
            return True
        except Exception as e:
            print(f"✗ Connection failed: {e}")
            return False
    
    def test_with_timeout_and_monitoring(self):
        """Test with detailed monitoring of what's happening"""
        print("\n=== Testing with Detailed Monitoring ===")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)  # 10 second timeout
            sock.connect((self.host, self.port))
            print("✓ Connected successfully")
            
            # Prepare auth message
            auth_msg = {
                "auth": {
                    "username": "admin", 
                    "password": "pass"
                }
            }
            msg_json = json.dumps(auth_msg)
            msg_bytes = msg_json.encode('utf-8')
            length_bytes = struct.pack('!I', len(msg_bytes))
            
            print(f"Sending auth message: {msg_json}")
            print(f"Message length: {len(msg_bytes)} bytes")
            
            # Send length prefix
            print("Sending length prefix...")
            sock.send(length_bytes)
            time.sleep(0.1)  # Small delay
            
            # Send message
            print("Sending message body...")
            sock.send(msg_bytes)
            
            print("Message sent, waiting for response...")
            
            # Use select to monitor socket with timeout
            ready, _, _ = select.select([sock], [], [], 5.0)
            
            if ready:
                print("Server has data to send!")
                try:
                    # Try to read response length
                    length_data = sock.recv(4)
                    if len(length_data) == 0:
                        print("✗ Server closed connection")
                        return False
                    elif len(length_data) < 4:
                        print(f"✗ Got incomplete length: {len(length_data)} bytes: {length_data.hex()}")
                        return False
                    else:
                        response_length = struct.unpack('!I', length_data)[0]
                        print(f"✓ Response length: {response_length} bytes")
                        
                        # Read response body
                        response_data = sock.recv(response_length)
                        response = response_data.decode('utf-8')
                        print(f"✓ Response: {response}")
                        
                        # Parse JSON response
                        try:
                            response_json = json.loads(response)
                            print(f"✓ Parsed response: {response_json}")
                            return True
                        except json.JSONDecodeError as e:
                            print(f"✗ Invalid JSON in response: {e}")
                            return False
                except Exception as e:
                    print(f"✗ Error reading response: {e}")
                    return False
            else:
                print("✗ No response from server within 5 seconds")
                return False
                
        except Exception as e:
            print(f"✗ Test failed: {e}")
            return False
        finally:
            if 'sock' in locals():
                sock.close()
    
    def test_malformed_requests(self):
        """Test how server handles malformed requests"""
        print("\n=== Testing Server Error Handling ===")
        
        test_cases = [
            ("Empty message", ""),
            ("Invalid JSON", "not json"),
            ("Missing auth", '{"operation": "test"}'),
            ("Invalid auth structure", '{"auth": "invalid"}'),
            ("Missing username", '{"auth": {"password": "pass"}}'),
            ("Missing password", '{"auth": {"username": "admin"}}'),
        ]
        
        for test_name, test_msg in test_cases:
            print(f"\nTesting: {test_name}")
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((self.host, self.port))
                
                if test_msg:
                    msg_bytes = test_msg.encode('utf-8')
                    length_bytes = struct.pack('!I', len(msg_bytes))
                    sock.send(length_bytes + msg_bytes)
                
                # Try to get response
                ready, _, _ = select.select([sock], [], [], 2.0)
                if ready:
                    try:
                        length_data = sock.recv(4)
                        if len(length_data) == 4:
                            response_length = struct.unpack('!I', length_data)[0]
                            response_data = sock.recv(response_length)
                            response = response_data.decode('utf-8')
                            print(f"  Server response: {response}")
                        else:
                            print(f"  Server closed connection or sent invalid length")
                    except Exception as e:
                        print(f"  Error reading response: {e}")
                else:
                    print(f"  No response from server")
                
                sock.close()
                
            except Exception as e:
                print(f"  Test failed: {e}")
    
    def monitor_server_behavior(self, duration=10):
        """Monitor server behavior over time"""
        print(f"\n=== Monitoring Server Behavior for {duration} seconds ===")
        
        def test_connection():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((self.host, self.port))
                sock.close()
                return True
            except:
                return False
        
        start_time = time.time()
        success_count = 0
        failure_count = 0
        
        while time.time() - start_time < duration:
            if test_connection():
                success_count += 1
                print(".", end="", flush=True)
            else:
                failure_count += 1
                print("X", end="", flush=True)
            time.sleep(0.5)
        
        print(f"\nResults: {success_count} successful connections, {failure_count} failures")
        return success_count > 0

def check_server_process():
    """Check if server process is running"""
    print("=== Checking Server Process ===")
    import subprocess
    try:
        # Check for server process
        result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
        lines = result.stdout.split('\n')
        server_processes = [line for line in lines if 'server' in line.lower() and 'grep' not in line]
        
        if server_processes:
            print("Found potential server processes:")
            for proc in server_processes:
                print(f"  {proc}")
        else:
            print("No server processes found")
        
        # Check port
        result = subprocess.run(['netstat', '-tulpn'], capture_output=True, text=True)
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            port_lines = [line for line in lines if ':8080' in line]
            if port_lines:
                print("Port 8080 usage:")
                for line in port_lines:
                    print(f"  {line}")
            else:
                print("Port 8080 not found in netstat output")
        else:
            print("Could not run netstat")
            
    except Exception as e:
        print(f"Error checking processes: {e}")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 debug_server.py <command> [host] [port]")
        print("Commands:")
        print("  check     - Check if server process is running")
        print("  connect   - Test basic connection")
        print("  auth      - Test authentication")
        print("  errors    - Test error handling")
        print("  monitor   - Monitor server behavior")
        print("  all       - Run all tests")
        sys.exit(1)
    
    command = sys.argv[1]
    host = sys.argv[2] if len(sys.argv) > 2 else "localhost"
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 8080
    
    if command == "check":
        check_server_process()
    elif command == "connect":
        debugger = ServerDebugger(host, port)
        debugger.test_connection_only()
    elif command == "auth":
        debugger = ServerDebugger(host, port)
        debugger.test_with_timeout_and_monitoring()
    elif command == "errors":
        debugger = ServerDebugger(host, port)
        debugger.test_malformed_requests()
    elif command == "monitor":
        debugger = ServerDebugger(host, port)
        debugger.monitor_server_behavior()
    elif command == "all":
        check_server_process()
        debugger = ServerDebugger(host, port)
        if debugger.test_connection_only():
            debugger.test_with_timeout_and_monitoring()
            debugger.test_malformed_requests()
            debugger.monitor_server_behavior()
    else:
        print(f"Unknown command: {command}")

if __name__ == "__main__":
    main()