import socket
import json
import cmd
import sys
import struct
import re
from colorama import Fore, Style

class MerkonDBClient(cmd.Cmd):
    prompt = f"{Fore.CYAN}(mdb){Style.RESET_ALL} "
    intro = f"""{Fore.GREEN}Welcome to MerkonDB Shell. Type help or ? to list commands.{Style.RESET_ALL}"""

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
            
            self.sock.settimeout(5.0)
            
            response_length_data = self.sock.recv(4)
            if len(response_length_data) != 4:
                raise ValueError("Incomplete response length received")
            response_length = struct.unpack('!I', response_length_data)[0]
            
            response = self.sock.recv(response_length).decode('utf-8')
            resp_json = json.loads(response)
            
            if resp_json.get("status") != "success":
                print(f"{Fore.RED}✗ Authentication failed: {resp_json.get('error_message', 'Unknown error')}{Style.RESET_ALL}")
                sys.exit(1)
                
            print(f"{Fore.GREEN}✓ Authentication successful{Style.RESET_ALL}")
            self.sock.settimeout(None)
            
        except socket.timeout:
            print(f"{Fore.RED}✗ Authentication timeout{Style.RESET_ALL}")
            sys.exit(1)
        except Exception as e:
            print(f"{Fore.RED}✗ Authentication error: {e}{Style.RESET_ALL}")
            sys.exit(1)

    def send_command(self, operation, params):
        try:
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

            response_length_data = self.sock.recv(4)
            if len(response_length_data) != 4:
                raise ValueError("Incomplete response length received")
            response_length = struct.unpack('!I', response_length_data)[0]

            response = self.sock.recv(response_length).decode('utf-8')
            resp_json = json.loads(response)

            if resp_json.get("status") == "success":
                if "databases" in resp_json:
                    print(f"{Fore.GREEN}Available databases:{Style.RESET_ALL}\n", json.dumps(resp_json["databases"], indent=2))
                elif "collections" in resp_json:
                    print(f"{Fore.GREEN}Available collections:{Style.RESET_ALL}\n", json.dumps(resp_json["collections"], indent=2))
                elif "value" in resp_json:
                    print(f"{Fore.GREEN}Record value:{Style.RESET_ALL}")
                    try:
                        parsed_value = json.loads(resp_json["value"])
                        print(json.dumps(parsed_value, indent=2))
                    except (json.JSONDecodeError, TypeError):
                        print(json.dumps(resp_json["value"], indent=2))
                elif "exists" in resp_json:
                    status = "exists" if resp_json["exists"] else "does not exist"
                    print(f"{Fore.GREEN}Status:{Style.RESET_ALL} {status}")
                elif "valid" in resp_json:
                    validity = "valid" if resp_json["valid"] else "invalid"
                    print(f"{Fore.GREEN}Proof verification:{Style.RESET_ALL} {validity}")
                elif "proof" in resp_json:
                    print(f"{Fore.GREEN}Generated proof:{Style.RESET_ALL}\n", json.dumps(resp_json["proof"], indent=2))
                elif "stats" in resp_json:
                    print(f"{Fore.GREEN}Database statistics:{Style.RESET_ALL}\n", json.dumps(resp_json["stats"], indent=2))
                elif "keys" in resp_json and "values" in resp_json:
                    print(f"{Fore.GREEN}Collection records:{Style.RESET_ALL}")
                    records = {}
                    for k, v in zip(resp_json["keys"], resp_json["values"]):
                        try:
                            parsed_value = json.loads(v)
                            records[k] = parsed_value
                        except (json.JSONDecodeError, TypeError):
                            records[k] = v
                    print(json.dumps(records, indent=2))
                elif "root_hash" in resp_json:
                    print(f"{Fore.GREEN}Current root hash:{Style.RESET_ALL}\n", json.dumps(resp_json["root_hash"], indent=2))
                elif "verification_results" in resp_json:
                    print(f"{Fore.GREEN}Integrity verification results:{Style.RESET_ALL}\n", json.dumps(resp_json["verification_results"], indent=2))
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

    def precmd(self, line):
        """Handle commands with spaces by converting them to underscores"""
        space_commands = {
            'add user': 'add_user',
            'add role': 'add_role',
            'remove user': 'remove_user',
            'remove role': 'remove_role',
            'assign role': 'assign_role',
            'revoke role': 'revoke_role',
            'verify integrity': 'verify_integrity',
            'create database': 'create_database',
            'create collection': 'create_collection',
            'drop database': 'drop_database',
            'drop collection': 'drop_collection',
            'exists database': 'exists_database',
            'exists collection': 'exists_collection',
            'list databases': 'list_databases',
            'list collections': 'list_collections',
            'batch insert': 'batch_insert',
            'save all': 'save_all',
            'load all': 'load_all',
            #'find all': 'find_all',
        }
        
        for cmd, replacement in space_commands.items():
            if line.startswith(cmd):
                return replacement + ' ' + line[len(cmd):].strip()
        
        return line

    def do_use(self, arg):
        """Switch to a specific database
Usage: use <db_name>"""
        if not arg:
            print(f"{Fore.RED}✗ Error: Database name required{Style.RESET_ALL}")
            return
        self.current_db = arg
        print(f"{Fore.GREEN}✓ Now using database: {arg}{Style.RESET_ALL}")

    def do_create_database(self, arg):
        """Create a new database
Usage: create database <db_name>"""
        if not arg:
            print(f"{Fore.RED}✗ Error: Database name required{Style.RESET_ALL}")
            return
        self.send_command("db_create", {"db_name": arg})

    def do_create_collection(self, arg):
        """Create a new collection
Usage: create collection <collection_name>"""
        if not arg:
            print(f"{Fore.RED}✗ Error: Collection name required{Style.RESET_ALL}")
            return
        if not self.current_db:
            print(f"{Fore.RED}✗ Error: No database selected. Use 'use <db_name>' first.{Style.RESET_ALL}")
            return
        self.send_command("db_create_collection", {
            "db_name": self.current_db,
            "collection_name": arg
        })

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

    def do_drop_database(self, arg):
        """Drop a database
Usage: drop database <db_name>"""
        if not arg:
            print(f"{Fore.RED}✗ Error: Database name required{Style.RESET_ALL}")
            return
        self.send_command("db_drop", {"db_name": arg})

    def do_drop_collection(self, arg):
        """Drop a collection
Usage: drop collection <collection_name>"""
        if not arg:
            print(f"{Fore.RED}✗ Error: Collection name required{Style.RESET_ALL}")
            return
        if not self.current_db:
            print(f"{Fore.RED}✗ Error: No database selected. Use 'use <db_name>' first.{Style.RESET_ALL}")
            return
        self.send_command("db_drop_collection", {
            "db_name": self.current_db,
            "collection_name": arg
        })

    def do_exists_database(self, arg):
        """Check if a database exists
Usage: exists database <db_name>"""
        if not arg:
            print(f"{Fore.RED}✗ Error: Database name required{Style.RESET_ALL}")
            return
        self.send_command("db_exists", {"db_name": arg})

    def do_exists_collection(self, arg):
        """Check if a collection exists
Usage: exists collection <collection_name>"""
        if not arg:
            print(f"{Fore.RED}✗ Error: Collection name required{Style.RESET_ALL}")
            return
        if not self.current_db:
            print(f"{Fore.RED}✗ Error: No database selected. Use 'use <db_name>' first.{Style.RESET_ALL}")
            return
        self.send_command("db_collection_exists", {
            "db_name": self.current_db,
            "collection_name": arg
        })

    def do_list_databases(self, arg):
        """List all databases
Usage: list databases"""
        self.send_command("db_list", {})

    def do_list_collections(self, arg):
        """List collections in current database
Usage: list collections"""
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
        """Find a record in a collection
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

    def do_batch_insert(self, arg):
        """Batch insert records
Usage: batch insert <collection_name> <key1>=<value1> <key2>=<value2> ..."""
        args = arg.split(maxsplit=2)
        if len(args) < 3:
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
        """Save a database
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
        """Load a database
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

    def do_save_all(self, arg):
        """Save all databases
Usage: save all"""
        self.do_save("all")

    def do_load_all(self, arg):
        """Load all databases
Usage: load all"""
        self.do_load("all")

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
Usage: verify integrity [<db_name>]"""
        if not arg and not self.current_db:
            print(f"{Fore.RED}✗ Error: Usage: verify integrity <db_name> or select a database with 'use'{Style.RESET_ALL}")
            return
        db_name = arg or self.current_db
        self.send_command("db_verify_integrity", {"db_name": db_name})

    def do_add_user(self, arg):
        """Add a new user (requires admin permissions)
Usage: add user <username> <password>"""
        args = arg.split()
        if len(args) != 2:
            print(f"{Fore.RED}✗ Error: Usage: add user <username> <password>{Style.RESET_ALL}")
            return
        self.send_command("rbac_add_user", {
            "username": args[0],
            "password": args[1]
        })

    def do_remove_user(self, arg):
        """Remove a user (requires admin permissions)
Usage: remove user <username>"""
        if not arg:
            print(f"{Fore.RED}✗ Error: Usage: remove user <username>{Style.RESET_ALL}")
            return
        self.send_command("rbac_remove_user", {"username": arg})

    def do_add_role(self, arg):
        """Add a new role (requires admin permissions)
Usage: add role <role_name> <permissions>
       Permissions: read,write,create,delete,admin (comma-separated)"""
        args = arg.split(maxsplit=1)
        if len(args) != 2:
            print(f"{Fore.RED}✗ Error: Usage: add role <role_name> <permissions>{Style.RESET_ALL}")
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
Usage: remove role <role_name>"""
        if not arg:
            print(f"{Fore.RED}✗ Error: Usage: remove role <role_name>{Style.RESET_ALL}")
            return
        self.send_command("rbac_remove_role", {"role_name": arg})

    def do_assign_role(self, arg):
        """Assign a role to a user (requires admin permissions)
Usage: assign role <username> <role_name>"""
        args = arg.split()
        if len(args) != 2:
            print(f"{Fore.RED}✗ Error: Usage: assign role <username> <role_name>{Style.RESET_ALL}")
            return
        self.send_command("rbac_assign_role", {
            "username": args[0],
            "role_name": args[1]
        })

    def do_revoke_role(self, arg):
        """Revoke a role from a user (requires admin permissions)
Usage: revoke role <username> <role_name>"""
        args = arg.split()
        if len(args) != 2:
            print(f"{Fore.RED}✗ Error: Usage: revoke role <username> <role_name>{Style.RESET_ALL}")
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

    def do_help(self, arg):
        """List available commands with 'help' or detailed help with 'help cmd'."""
        if arg:
            cmd_name = arg.replace(' ', '_')
            try:
                func = getattr(self, 'do_' + cmd_name)
            except AttributeError:
                print(f"{Fore.RED}✗ No help on {arg}{Style.RESET_ALL}")
                return
            doc = func.__doc__
            if doc:
                print(f"\n{Fore.CYAN}MerkonDB Query Language(MQL) Help:{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}{doc}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}✗ No help available for {arg}{Style.RESET_ALL}")
        else:
            # Command groups with descriptions
            command_groups = {
                "Database Operations": [
                    ("use <db_name>", "Set active database"),
                    ("create database <name>", "Create new database"),
                    ("open <db_name>", "Open database"),
                    ("close <db_name>", "Close database"),
                    ("drop database <name>", "Permanently delete database"),
                    ("exists database <name>", "Check database existence"),
                    ("list databases", "Show all databases"),
                    ("stats [<db_name>]", "View database statistics")
                ],
                "Collection Operations": [
                    ("create collection <name>", "Create new collection"),
                    ("drop collection <name>", "Delete collection"),
                    ("exists collection <name>", "Check collection existence"),
                    ("list collections", "List collections in current DB")
                ],
                "Data Operations": [
                    ("insert <col> <key> <val>", "Insert key-value pair"),
                    ("find <col> <key>", "Retrieve value by key"),
                    ("find all <col>", "Get all records in collection"),
                    ("update <col> <key> <val>", "Modify existing record"),
                    ("delete <col> <key>", "Remove record"),
                    ("batch insert <col> <k=v>...", "Insert multiple records")
                ],
                "Integrity Verification": [
                    ("root <collection>", "Get Merkle root hash"),
                    ("proof <col> <key>", "Generate cryptographic proof"),
                    ("verify <col> <k> <v> <proof>", "Verify data integrity"),
                    ("verify integrity [<db>]", "Full database verification")
                ],
                "Persistence": [
                    ("save [<db_name>]", "Persist database to disk"),
                    ("save all", "Save all databases"),
                    ("load [<db_name>]", "Load database from disk"),
                    ("load all", "Load all databases")
                ],
                "Administration": [
                    ("add user <name> <pass>", "Create new user account"),
                    ("remove user <name>", "Delete user account"),
                    ("add role <name> <perms>", "Create role (comma-separated perms)"),
                    ("remove role <name>", "Delete role"),
                    ("assign role <user> <role>", "Grant role to user"),
                    ("revoke role <user> <role>", "Remove role from user")
                ],
                "System": [
                    ("compact [<db_name>]", "Optimize database storage"),
                    ("help", "Show this reference"),
                    ("help <command>", "Detailed command help"),
                    ("exit/quit", "Exit the query interface")
                ]
            }

        print(f"\n{Fore.CYAN}MerkonDB Query Language(MQL) Reference{Style.RESET_ALL}")
        print(f"{Fore.CYAN}========================================{Style.RESET_ALL}")
        
        for group, commands in command_groups.items():
            print(f"\n{Fore.YELLOW}{group}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}{'-'*len(group)}{Style.RESET_ALL}")
            for cmd, desc in commands:
                print(f"{Fore.GREEN}{cmd.ljust(30)}{Style.RESET_ALL} {desc}")

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
        client.cmdloop()
    except Exception as e:
        print(f"{Fore.RED}✗ Error in cmdloop: {e}{Style.RESET_ALL}")
        sys.exit(1)