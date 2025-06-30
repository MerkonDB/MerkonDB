import socket
import json
import cmd
import sys
import struct
import re
from colorama import Fore, Style

class MerkonDBClient(cmd.Cmd):
    prompt = f"{Fore.CYAN}(mdb){Style.RESET_ALL} "
    intro = f"{Fore.GREEN}Welcome to MerkonDB Shell. Type help or ? to list commands.{Style.RESET_ALL}\n"

    def __init__(self, host, port, username, password):
        super().__init__()
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.sock = None
        self.current_db = None
        self.connect()

    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
            print(f"{Fore.GREEN}✓ Connected to {self.host}:{self.port}{Style.RESET_ALL}")
            # Send authentication message
            self.send_auth()
        except Exception as e:
            print(f"{Fore.RED}✗ Connection failed: {e}{Style.RESET_ALL}")
            sys.exit(1)

    def send_auth(self):
        try:
            message = json.dumps({
                "auth": {
                    "username": self.username,
                    "password": self.password
                }
            })
            length = len(message)
            self.sock.sendall(struct.pack('!I', length))
            self.sock.sendall(message.encode('utf-8'))
            
            # Set timeout for response
            self.sock.settimeout(5.0)
            
            # Receive authentication response
            response_length_data = self.sock.recv(4)
            if len(response_length_data) != 4:
                raise ValueError("Incomplete response length received")
            response_length = struct.unpack('!I', response_length_data)[0]
            
            response = self.sock.recv(response_length).decode('utf-8')
            resp_json = json.loads(response)
            print("Auth response:", resp_json)
            
            if resp_json.get("status") != "success":
                print(f"{Fore.RED}✗ Authentication failed: {resp_json.get('error_message', 'Unknown error')}{Style.RESET_ALL}")
                sys.exit(1)
                
            print(f"{Fore.GREEN}✓ Authentication successful{Style.RESET_ALL}")
            # Reset timeout after auth
            self.sock.settimeout(None)
            
        except socket.timeout:
            print(f"{Fore.RED}✗ Authentication timeout{Style.RESET_ALL}")
            sys.exit(1)
        except Exception as e:
            print(f"{Fore.RED}✗ Authentication error: {e}{Style.RESET_ALL}")
            sys.exit(1)

    def send_command(self, operation, params):
        try:
            # Include authentication in every message
            message = json.dumps({
                "operation": operation,
                "params": params,
                "auth": {
                    "username": self.username,
                    "password": self.password
                }
            })
            length = len(message)
            self.sock.sendall(struct.pack('!I', length))
            self.sock.sendall(message.encode('utf-8'))

            # Receive response length
            response_length_data = self.sock.recv(4)
            if len(response_length_data) != 4:
                raise ValueError("Incomplete response length received")
            response_length = struct.unpack('!I', response_length_data)[0]

            # Receive and parse response
            response = self.sock.recv(response_length).decode('utf-8')
            resp_json = json.loads(response)

            # Handle successful responses
            if resp_json.get("status") == "success":
                if "databases" in resp_json:
                    print(f"{Fore.GREEN}Available databases:{Style.RESET_ALL}", ", ".join(resp_json["databases"]))
                elif "collections" in resp_json:
                    print(f"{Fore.GREEN}Available collections:{Style.RESET_ALL}", ", ".join(resp_json["collections"]))
                elif "value" in resp_json:
                    print(f"{Fore.GREEN}Record value:{Style.RESET_ALL}", resp_json["value"])
                elif "exists" in resp_json:
                    status = "exists" if resp_json["exists"] else "does not exist"
                    print(f"{Fore.GREEN}Status:{Style.RESET_ALL} {status}")
                elif "valid" in resp_json:
                    validity = "valid" if resp_json["valid"] else "invalid"
                    print(f"{Fore.GREEN}Proof verification:{Style.RESET_ALL} {validity}")
                elif "proof" in resp_json:
                    print(f"{Fore.GREEN}Generated proof:{Style.RESET_ALL}", json.dumps(resp_json["proof"], indent=2))
                elif "stats" in resp_json:
                    print(f"{Fore.GREEN}Database statistics:{Style.RESET_ALL}", json.dumps(resp_json["stats"], indent=2))
                elif "keys" in resp_json:
                    print(f"{Fore.GREEN}Collection records:{Style.RESET_ALL}")
                    for k, v in zip(resp_json["keys"], resp_json["values"]):
                        print(f"  {Fore.CYAN}{k}:{Style.RESET_ALL} {v}")
                elif "root_hash" in resp_json:
                    print(f"{Fore.GREEN}Current root hash:{Style.RESET_ALL}", resp_json["root_hash"])
                elif "verification_results" in resp_json:
                    print(f"{Fore.GREEN}Integrity verification results:{Style.RESET_ALL}")
                    for result in resp_json["verification_results"]:
                        collection = result.get("collection", "Unknown")
                        root_hash = result.get("root_hash", "N/A")
                        print(f"  Collection: {collection}, Root Hash: {root_hash}")
                else:
                    print(f"{Fore.GREEN}✓ Operation completed successfully{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}✗ Error: {resp_json.get('error_message', 'Unknown error')}{Style.RESET_ALL}")

        except json.JSONDecodeError as e:
            print(f"{Fore.RED}✗ Communication error: Invalid response format ({e}){Style.RESET_ALL}")
            self.sock.close()
            self.connect()
            self.send_auth()
        except ConnectionError as e:
            print(f"{Fore.RED}✗ Communication error: Connection issue ({e}){Style.RESET_ALL}")
            self.sock.close()
            self.connect()
            self.send_auth()
        except Exception as e:
            print(f"{Fore.RED}✗ Communication error: {e}{Style.RESET_ALL}")
            self.sock.close()
            self.connect()
            self.send_auth()

    def do_use(self, arg):
        """Switch to a specific database
Usage: use <db_name>"""
        if not arg:
            print(f"{Fore.RED}✗ Error: Database name required{Style.RESET_ALL}")
            return
        self.current_db = arg
        print(f"{Fore.GREEN}✓ Now using database: {arg}{Style.RESET_ALL}")

    def do_create(self, arg):
        """Create a new database or collection
Usage: create database <db_name>
       create collection <collection_name>"""
        args = arg.split()
        if len(args) < 2:
            print(f"{Fore.RED}✗ Error: Usage: create database <db_name> or create collection <collection_name>{Style.RESET_ALL}")
            return
        
        if args[0] == "database":
            if len(args) != 2:
                print(f"{Fore.RED}✗ Error: Usage: create database <db_name>{Style.RESET_ALL}")
                return
            self.send_command("db_create", {"db_name": args[1]})
        elif args[0] == "collection":
            if not self.current_db:
                print(f"{Fore.RED}✗ Error: No database selected. Use 'use <db_name>' first.{Style.RESET_ALL}")
                return
            if len(args) != 2:
                print(f"{Fore.RED}✗ Error: Usage: create collection <collection_name>{Style.RESET_ALL}")
                return
            self.send_command("db_create_collection", {"db_name": self.current_db, "collection_name": args[1]})
        else:
            print(f"{Fore.RED}✗ Error: Usage: create database <db_name> or create collection <collection_name>{Style.RESET_ALL}")

    def do_open(self, arg):
        """Open an existing database
Usage: open <db_name>"""
        if not arg:
            print(f"{Fore.RED}✗ Error: Database name required{Style.RESET_ALL}")
            return
        self.send_command("db_open", {"db_name": arg})

    def do_close(self, arg):
        """Close a database
Usage: close <db_name>"""
        if not arg:
            print(f"{Fore.RED}✗ Error: Database name required{Style.RESET_ALL}")
            return
        self.send_command("db_close", {"db_name": arg})

    def do_drop(self, arg):
        """Drop a database or collection
Usage: drop database <db_name>
       drop collection <collection_name>"""
        args = arg.split()
        if len(args) < 1 or args[0] not in ["database", "collection"]:
            print(f"{Fore.RED}✗ Error: Usage: drop database <db_name> or drop collection <collection_name>{Style.RESET_ALL}")
            return
        if args[0] == "database":
            if len(args) != 2:
                print(f"{Fore.RED}✗ Error: Usage: drop database <db_name>{Style.RESET_ALL}")
                return
            self.send_command("db_drop", {"db_name": args[1]})
        else:
            if not self.current_db:
                print(f"{Fore.RED}✗ Error: No database selected. Use 'use <db_name>' first.{Style.RESET_ALL}")
                return
            if len(args) != 2:
                print(f"{Fore.RED}✗ Error: Usage: drop collection <collection_name>{Style.RESET_ALL}")
                return
            self.send_command("db_drop_collection", {"db_name": self.current_db, "collection_name": args[1]})

    def do_exists(self, arg):
        """Check if a database or collection exists
Usage: exists database <db_name>
       exists collection <collection_name>"""
        args = arg.split()
        if len(args) < 1 or args[0] not in ["database", "collection"]:
            print(f"{Fore.RED}✗ Error: Usage: exists database <db_name> or exists collection <collection_name>{Style.RESET_ALL}")
            return
        if args[0] == "database":
            if len(args) != 2:
                print(f"{Fore.RED}✗ Error: Usage: exists database <db_name>{Style.RESET_ALL}")
                return
            self.send_command("db_exists", {"db_name": args[1]})
        else:
            if not self.current_db:
                print(f"{Fore.RED}✗ Error: No database selected. Use 'use <db_name>' first.{Style.RESET_ALL}")
                return
            if len(args) != 2:
                print(f"{Fore.RED}✗ Error: Usage: exists collection <collection_name>{Style.RESET_ALL}")
                return
            self.send_command("db_collection_exists", {"db_name": self.current_db, "collection_name": args[1]})

    def do_list(self, arg):
        """List databases or collections
Usage: list databases
       list collections"""
        args = arg.split()
        if len(args) == 0 or args[0] not in ["databases", "collections"]:
            print(f"{Fore.RED}✗ Error: Usage: list databases or list collections{Style.RESET_ALL}")
            return
        if args[0] == "databases":
            self.send_command("db_list", {})
        else:
            if not self.current_db:
                print(f"{Fore.RED}✗ Error: No database selected. Use 'use <db_name>' first.{Style.RESET_ALL}")
                return
            self.send_command("db_list_collections", {"db_name": self.current_db})

    def do_stats(self, arg):
        """Get database statistics
Usage: stats [<db_name>]"""
        if not arg and not self.current_db:
            print(f"{Fore.RED}✗ Error: Usage: stats <db_name> or select a database with 'use'{Style.RESET_ALL}")
            return
        db_name = arg or self.current_db
        self.send_command("db_get_stats", {"db_name": db_name})

    def do_insert(self, arg):
        """Insert a record into a collection
Usage: insert <collection_name> <key> <value>"""
        args = arg.split(maxsplit=2)
        if len(args) != 3:
            print(f"{Fore.RED}✗ Error: Usage: insert <collection_name> <key> <value>{Style.RESET_ALL}")
            return
        if not self.current_db:
            print(f"{Fore.RED}✗ Error: No database selected. Use 'use <db_name>' first.{Style.RESET_ALL}")
            return
        self.send_command("db_insert", {
            "db_name": self.current_db,
            "collection_name": args[0],
            "key": args[1],
            "value": args[2]
        })

    def do_find(self, arg):
        """Find a record in a collection or find all records
Usage: find <collection_name> <key>
       find all <collection_name>"""
        args = arg.split()
        if len(args) < 1:
            print(f"{Fore.RED}✗ Error: Usage: find <collection_name> <key> or find all <collection_name>{Style.RESET_ALL}")
            return
        if not self.current_db:
            print(f"{Fore.RED}✗ Error: No database selected. Use 'use <db_name>' first.{Style.RESET_ALL}")
            return
        
        if args[0] == "all":
            if len(args) != 2:
                print(f"{Fore.RED}✗ Error: Usage: find all <collection_name>{Style.RESET_ALL}")
                return
            self.send_command("db_find_all", {
                "db_name": self.current_db,
                "collection_name": args[1]
            })
        else:
            if len(args) != 2:
                print(f"{Fore.RED}✗ Error: Usage: find <collection_name> <key>{Style.RESET_ALL}")
                return
            self.send_command("db_find", {
                "db_name": self.current_db,
                "collection_name": args[0],
                "key": args[1]
            })

    def do_update(self, arg):
        """Update a record in a collection
Usage: update <collection_name> <key> <value>"""
        args = arg.split(maxsplit=2)
        if len(args) != 3:
            print(f"{Fore.RED}✗ Error: Usage: update <collection_name> <key> <value>{Style.RESET_ALL}")
            return
        if not self.current_db:
            print(f"{Fore.RED}✗ Error: No database selected. Use 'use <db_name>' first.{Style.RESET_ALL}")
            return
        self.send_command("db_update", {
            "db_name": self.current_db,
            "collection_name": args[0],
            "key": args[1],
            "value": args[2]
        })

    def do_delete(self, arg):
        """Delete a record from a collection
Usage: delete <collection_name> <key>"""
        args = arg.split()
        if len(args) != 2:
            print(f"{Fore.RED}✗ Error: Usage: delete <collection_name> <key>{Style.RESET_ALL}")
            return
        if not self.current_db:
            print(f"{Fore.RED}✗ Error: No database selected. Use 'use <db_name>' first.{Style.RESET_ALL}")
            return
        self.send_command("db_delete", {
            "db_name": self.current_db,
            "collection_name": args[0],
            "key": args[1]
        })

    def do_batch(self, arg):
        """Batch operations
Usage: batch insert <collection_name> <key1>=<value1> <key2>=<value2> ..."""
        args = arg.split(maxsplit=2)
        if len(args) < 3 or args[0] != "insert":
            print(f"{Fore.RED}✗ Error: Usage: batch insert <collection_name> <key1>=<value1> <key2>=<value2> ...{Style.RESET_ALL}")
            return
        if not self.current_db:
            print(f"{Fore.RED}✗ Error: No database selected. Use 'use <db_name>' first.{Style.RESET_ALL}")
            return

        collection_name = args[1]
        pairs = args[2].split()
        keys = []
        values = []
        for pair in pairs:
            if '=' not in pair:
                print(f"{Fore.RED}✗ Error: Invalid key-value pair format: {pair}{Style.RESET_ALL}")
                return
            key, value = pair.split('=', 1)
            keys.append(key)
            values.append(value)
        
        self.send_command("db_batch_insert", {
            "db_name": self.current_db,
            "collection_name": collection_name,
            "keys": keys,
            "values": values
        })

    def do_root(self, arg):
        """Get the root hash of a collection
Usage: root <collection_name>"""
        if not arg:
            print(f"{Fore.RED}✗ Error: Collection name required{Style.RESET_ALL}")
            return
        if not self.current_db:
            print(f"{Fore.RED}✗ Error: No database selected. Use 'use <db_name>' first.{Style.RESET_ALL}")
            return
        self.send_command("db_get_root_hash", {
            "db_name": self.current_db,
            "collection_name": arg
        })

    def do_proof(self, arg):
        """Generate a membership proof for a key
Usage: proof <collection_name> <key>"""
        args = arg.split()
        if len(args) != 2:
            print(f"{Fore.RED}✗ Error: Usage: proof <collection_name> <key>{Style.RESET_ALL}")
            return
        if not self.current_db:
            print(f"{Fore.RED}✗ Error: No database selected. Use 'use <db_name>' first.{Style.RESET_ALL}")
            return
        self.send_command("db_generate_proof", {
            "db_name": self.current_db,
            "collection_name": args[0],
            "key": args[1]
        })

    def do_verify(self, arg):
        """Verify a membership proof
Usage: verify <collection_name> <key> <value> <proof_json>"""
        args = arg.split(maxsplit=3)
        if len(args) != 4:
            print(f"{Fore.RED}✗ Error: Usage: verify <collection_name> <key> <value> <proof_json>{Style.RESET_ALL}")
            return
        if not self.current_db:
            print(f"{Fore.RED}✗ Error: No database selected. Use 'use <db_name>' first.{Style.RESET_ALL}")
            return
        try:
            proof = json.loads(args[3])
            self.send_command("db_verify_proof", {
                "db_name": self.current_db,
                "collection_name": args[0],
                "key": args[1],
                "value": args[2],
                "proof": proof
            })
        except json.JSONDecodeError:
            print(f"{Fore.RED}✗ Error: Invalid proof JSON format{Style.RESET_ALL}")

    def do_save(self, arg):
        """Save a database or all databases
Usage: save [<db_name>]
       save all"""
        if not arg:
            if not self.current_db:
                print(f"{Fore.RED}✗ Error: Usage: save <db_name> or save all, or select a database with 'use'{Style.RESET_ALL}")
                return
            self.send_command("db_save", {"db_name": self.current_db})
        elif arg == "all":
            self.send_command("db_save_all", {})
        else:
            self.send_command("db_save", {"db_name": arg})

    def do_load(self, arg):
        """Load a database or all databases
Usage: load [<db_name>]
       load all"""
        if not arg:
            if not self.current_db:
                print(f"{Fore.RED}✗ Error: Usage: load <db_name> or load all, or select a database with 'use'{Style.RESET_ALL}")
                return
            self.send_command("db_load", {"db_name": self.current_db})
        elif arg == "all":
            self.send_command("db_load_all", {})
        else:
            self.send_command("db_load", {"db_name": arg})

    def do_compact(self, arg):
        """Compact a database
Usage: compact [<db_name>]"""
        if not arg and not self.current_db:
            print(f"{Fore.RED}✗ Error: Usage: compact <db_name> or select a database with 'use'{Style.RESET_ALL}")
            return
        db_name = arg or self.current_db
        self.send_command("db_compact", {"db_name": db_name})

    def do_verify_integrity(self, arg):
        """Verify database integrity
Usage: verify_integrity [<db_name>]"""
        if not arg and not self.current_db:
            print(f"{Fore.RED}✗ Error: Usage: verify_integrity <db_name> or select a database with 'use'{Style.RESET_ALL}")
            return
        db_name = arg or self.current_db
        self.send_command("db_verify_integrity", {"db_name": db_name})

    def do_add_user(self, arg):
        """Add a new user (requires admin permissions)
Usage: add_user <username> <password>"""
        args = arg.split()
        if len(args) != 2:
            print(f"{Fore.RED}✗ Error: Usage: add_user <username> <password>{Style.RESET_ALL}")
            return
        self.send_command("rbac_add_user", {
            "username": args[0],
            "password": args[1]
        })

    def do_remove_user(self, arg):
        """Remove a user (requires admin permissions)
Usage: remove_user <username>"""
        if not arg:
            print(f"{Fore.RED}✗ Error: Usage: remove_user <username>{Style.RESET_ALL}")
            return
        self.send_command("rbac_remove_user", {"username": arg})

    def do_add_role(self, arg):
        """Add a new role (requires admin permissions)
Usage: add_role <role_name> <permissions>
       Permissions: read,write,create,delete,admin (comma-separated)"""
        args = arg.split(maxsplit=1)
        if len(args) != 2:
            print(f"{Fore.RED}✗ Error: Usage: add_role <role_name> <permissions>{Style.RESET_ALL}")
            return
        permissions_str = args[1].split(',')
        perm_value = 0
        perm_map = {
            "read": 1,
            "write": 2,
            "create": 4,
            "delete": 8,
            "admin": 16
        }
        for p in permissions_str:
            p = p.strip().lower()
            if p in perm_map:
                perm_value |= perm_map[p]
            else:
                print(f"{Fore.RED}✗ Error: Invalid permission: {p}{Style.RESET_ALL}")
                return
        self.send_command("rbac_add_role", {
            "role_name": args[0],
            "permissions": perm_value
        })

    def do_remove_role(self, arg):
        """Remove a role (requires admin permissions)
Usage: remove_role <role_name>"""
        if not arg:
            print(f"{Fore.RED}✗ Error: Usage: remove_role <role_name>{Style.RESET_ALL}")
            return
        self.send_command("rbac_remove_role", {"role_name": arg})

    def do_assign_role(self, arg):
        """Assign a role to a user (requires admin permissions)
Usage: assign_role <username> <role_name>"""
        args = arg.split()
        if len(args) != 2:
            print(f"{Fore.RED}✗ Error: Usage: assign_role <username> <role_name>{Style.RESET_ALL}")
            return
        self.send_command("rbac_assign_role", {
            "username": args[0],
            "role_name": args[1]
        })

    def do_revoke_role(self, arg):
        """Revoke a role from a user (requires admin permissions)
Usage: revoke_role <username> <role_name>"""
        args = arg.split()
        if len(args) != 2:
            print(f"{Fore.RED}✗ Error: Usage: revoke_role <username> <role_name>{Style.RESET_ALL}")
            return
        self.send_command("rbac_revoke_role", {
            "username": args[0],
            "role_name": args[1]
        })

    def do_exit(self, arg):
        """Exit the shell"""
        print(f"{Fore.GREEN}✓ Goodbye{Style.RESET_ALL}")
        self.sock.close()
        return True

    def do_quit(self, arg):
        """Exit the shell"""
        return self.do_exit(arg)

if __name__ == '__main__':
    if len(sys.argv) != 5:
        print(f"{Fore.RED}✗ Usage: {sys.argv[0]} <host> <port> <username> <password>{Style.RESET_ALL}")
        sys.exit(1)
    
    host = sys.argv[1]
    try:
        port = int(sys.argv[2])
    except ValueError:
        print(f"{Fore.RED}✗ Error: Port must be a number{Style.RESET_ALL}")
        sys.exit(1)
    username = sys.argv[3]
    password = sys.argv[4]
    
    try:
        client = MerkonDBClient(host, port, username, password)
        # Add this line to ensure proper prompt display:
        client.prompt = f"{Fore.CYAN}(mdb){Style.RESET_ALL} "
        client.cmdloop(intro='' if client.intro else None)
    except Exception as e:
        print(f"{Fore.RED}✗ Error in cmdloop: {e}{Style.RESET_ALL}")
        sys.exit(1)