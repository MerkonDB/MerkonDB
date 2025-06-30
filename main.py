import ctypes
import json
import cmd
import os
import sys

# Load the shared library
lib = ctypes.CDLL('./libsmt_db.so')

# Define constants
HASH_SIZE = 32
DB_SUCCESS = 0

# Define MembershipProof structure
class MembershipProof(ctypes.Structure):
    _fields_ = [
        ("layer_priority", ctypes.c_int),
        ("element_index", ctypes.c_int),
        ("layer_root", ctypes.c_ubyte * HASH_SIZE),
        ("layer_proof", ctypes.POINTER(ctypes.c_ubyte)),
        ("layer_proof_len", ctypes.c_size_t),
        ("top_level_proof", ctypes.POINTER(ctypes.c_ubyte)),
        ("top_level_proof_len", ctypes.c_size_t),
    ]

# Load libc for memory freeing
if os.name == 'posix':
    libc = ctypes.CDLL('libc.so.6')
else:
    libc = ctypes.CDLL('msvcrt.dll')
libc.free.argtypes = [ctypes.c_void_p]
libc.free.restype = None

# Function prototypes
lib.db_manager_init.argtypes = [ctypes.c_char_p]
lib.db_manager_init.restype = ctypes.c_int

lib.db_create.argtypes = [ctypes.c_char_p]
lib.db_create.restype = ctypes.c_int

lib.db_open.argtypes = [ctypes.c_char_p]
lib.db_open.restype = ctypes.c_int

lib.db_close.argtypes = [ctypes.c_char_p]
lib.db_close.restype = ctypes.c_int

lib.db_drop.argtypes = [ctypes.c_char_p]
lib.db_drop.restype = ctypes.c_int

lib.db_list.argtypes = [ctypes.POINTER(ctypes.POINTER(ctypes.c_char_p)), ctypes.POINTER(ctypes.c_size_t)]
lib.db_list.restype = ctypes.c_int

lib.db_create_collection.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
lib.db_create_collection.restype = ctypes.c_int

lib.db_drop_collection.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
lib.db_drop_collection.restype = ctypes.c_int

lib.db_list_collections.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.POINTER(ctypes.c_char_p)), ctypes.POINTER(ctypes.c_size_t)]
lib.db_list_collections.restype = ctypes.c_int

lib.db_insert.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
lib.db_insert.restype = ctypes.c_int

lib.db_find.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_char_p)]
lib.db_find.restype = ctypes.c_int

lib.db_update.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
lib.db_update.restype = ctypes.c_int

lib.db_delete.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
lib.db_delete.restype = ctypes.c_int

lib.db_generate_proof.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(MembershipProof)]
lib.db_generate_proof.restype = ctypes.c_int

lib.db_verify_proof.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(MembershipProof), ctypes.POINTER(ctypes.c_int)]
lib.db_verify_proof.restype = ctypes.c_int

lib.db_get_root_hash.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
lib.db_get_root_hash.restype = ctypes.c_int

lib.db_save.argtypes = [ctypes.c_char_p]
lib.db_save.restype = ctypes.c_int

lib.db_load.argtypes = [ctypes.c_char_p]
lib.db_load.restype = ctypes.c_int

lib.db_save_all.argtypes = []
lib.db_save_all.restype = ctypes.c_int

lib.db_load_all.argtypes = []
lib.db_load_all.restype = ctypes.c_int

lib.membership_proof_cleanup.argtypes = [ctypes.POINTER(MembershipProof)]
lib.membership_proof_cleanup.restype = None

lib.db_error_string.argtypes = [ctypes.c_int]
lib.db_error_string.restype = ctypes.c_char_p

lib.db_free_list.argtypes = [ctypes.POINTER(ctypes.c_char_p), ctypes.c_size_t]
lib.db_free_list.restype = None

# Helper functions
def check_error(err):
    if err != DB_SUCCESS:
        error_str = lib.db_error_string(err).decode()
        raise Exception(error_str)

def bytes_to_hex(bytes_array):
    return ''.join(f'{b:02x}' for b in bytes_array)

def proof_to_json(proof):
    return json.dumps({
        "layer_priority": proof.layer_priority,
        "element_index": proof.element_index,
        "layer_root": bytes_to_hex(proof.layer_root),
        "layer_proof": bytes_to_hex(ctypes.string_at(proof.layer_proof, proof.layer_proof_len)) if proof.layer_proof else "",
        "top_level_proof": bytes_to_hex(ctypes.string_at(proof.top_level_proof, proof.top_level_proof_len)) if proof.top_level_proof else ""
    }, indent=2)

def json_to_proof(json_str):
    data = json.loads(json_str)
    proof = MembershipProof()
    proof.layer_priority = data["layer_priority"]
    proof.element_index = data["element_index"]
    layer_root_bytes = bytes.fromhex(data["layer_root"])
    for i, b in enumerate(layer_root_bytes):
        proof.layer_root[i] = b
    layer_proof_bytes = bytes.fromhex(data["layer_proof"]) if data["layer_proof"] else b''
    proof.layer_proof_len = len(layer_proof_bytes)
    if proof.layer_proof_len > 0:
        proof.layer_proof = (ctypes.c_ubyte * proof.layer_proof_len).from_buffer_copy(layer_proof_bytes)
    else:
        proof.layer_proof = None
    top_level_proof_bytes = bytes.fromhex(data["top_level_proof"]) if data["top_level_proof"] else b''
    proof.top_level_proof_len = len(top_level_proof_bytes)
    if proof.top_level_proof_len > 0:
        proof.top_level_proof = (ctypes.c_ubyte * proof.top_level_proof_len).from_buffer_copy(top_level_proof_bytes)
    else:
        proof.top_level_proof = None
    return proof

# Shell class
class SMTShell(cmd.Cmd):
    intro = 'Welcome to MerkonDB Shell. Type help or ? to list commands.\n'
    prompt = '(merk) '
    
    def __init__(self, persistence_path):
        super().__init__()
        self.current_db = None
        err = lib.db_manager_init(persistence_path.encode())
        check_error(err)
    
    def do_use(self, arg):
        """Use a database: use <db_name>"""
        if not arg:
            print("Usage: use <db_name>")
            return
        err = lib.db_open(arg.encode())
        if err == DB_SUCCESS:
            self.current_db = arg
            print(f"Switched to database '{arg}'")
        else:
            print(f"Error: {lib.db_error_string(err).decode()}")
    
    def do_create(self, arg):
        """Create a database or collection: create database <db_name> | create collection <collection_name>"""
        parts = arg.split()
        if len(parts) < 2:
            print("Usage: create database <db_name> | create collection <collection_name>")
            return
        if parts[0] == "database":
            db_name = parts[1]
            err = lib.db_create(db_name.encode())
            if err == DB_SUCCESS:
                print(f"Database '{db_name}' created")
            else:
                print(f"Error: {lib.db_error_string(err).decode()}")
        elif parts[0] == "collection":
            if not self.current_db:
                print("No database selected. Use 'use <db_name>' first.")
                return
            collection_name = parts[1]
            err = lib.db_create_collection(self.current_db.encode(), collection_name.encode())
            if err == DB_SUCCESS:
                print(f"Collection '{collection_name}' created")
            else:
                print(f"Error: {lib.db_error_string(err).decode()}")
    
    def do_drop(self, arg):
        """Drop a database or collection: drop database <db_name> | drop collection <collection_name>"""
        parts = arg.split()
        if len(parts) < 2:
            print("Usage: drop database <db_name> | drop collection <collection_name>")
            return
        if parts[0] == "database":
            db_name = parts[1]
            err = lib.db_drop(db_name.encode())
            if err == DB_SUCCESS:
                print(f"Database '{db_name}' dropped")
                if self.current_db == db_name:
                    self.current_db = None
            else:
                print(f"Error: {lib.db_error_string(err).decode()}")
        elif parts[0] == "collection":
            if not self.current_db:
                print("No database selected. Use 'use <db_name>' first.")
                return
            collection_name = parts[1]
            err = lib.db_drop_collection(self.current_db.encode(), collection_name.encode())
            if err == DB_SUCCESS:
                print(f"Collection '{collection_name}' dropped")
            else:
                print(f"Error: {lib.db_error_string(err).decode()}")
    
    def do_list(self, arg):
        """List databases or collections: list databases | list collections"""
        parts = arg.split()
        if not parts:
            print("Usage: list databases | list collections")
            return
        
        if parts[0] == "databases":
            db_names_ptr = ctypes.POINTER(ctypes.c_char_p)()
            count = ctypes.c_size_t()
            
            err = lib.db_list(ctypes.byref(db_names_ptr), ctypes.byref(count))
            if err == DB_SUCCESS:
                if db_names_ptr and count.value > 0:
                    print("Databases:")
                    db_names = []
                    for i in range(count.value):
                        if db_names_ptr[i]:
                            # Fixed: db_names_ptr[i] is already a bytes object when dereferenced
                            db_names.append(db_names_ptr[i].decode())
                    for name in db_names:
                        print(f"  {name}")
                    # Delegate freeing to C library
                    lib.db_free_list(db_names_ptr, count)
                else:
                    print("No databases found")
            else:
                print(f"Error: {lib.db_error_string(err).decode()}")
        
        elif parts[0] == "collections":
            if not self.current_db:
                print("No database selected. Use 'use <db_name>' first.")
                return
            
            col_names_ptr = ctypes.POINTER(ctypes.c_char_p)()
            count = ctypes.c_size_t()
            
            err = lib.db_list_collections(self.current_db.encode(), ctypes.byref(col_names_ptr), ctypes.byref(count))
            if err == DB_SUCCESS:
                if col_names_ptr and count.value > 0:
                    print("Collections:")
                    col_names = []
                    for i in range(count.value):
                        if col_names_ptr[i]:
                            # Fixed: col_names_ptr[i] is already a bytes object when dereferenced
                            col_names.append(col_names_ptr[i].decode())
                    for name in col_names:
                        print(f"  {name}")
                    # Delegate freeing to C library
                    lib.db_free_list(col_names_ptr, count)
                else:
                    print("No collections found")
            else:
                print(f"Error: {lib.db_error_string(err).decode()}")
        else:
            print("Usage: list databases | list collections")
    
    def do_insert(self, arg):
        """Insert a key-value pair: insert <collection> <key> <value>"""
        if not self.current_db:
            print("No database selected. Use 'use <db_name>' first.")
            return
        parts = arg.split(maxsplit=2)
        if len(parts) < 3:
            print("Usage: insert <collection> <key> <value>")
            return
        collection, key, value = parts
        err = lib.db_insert(self.current_db.encode(), collection.encode(), key.encode(), value.encode())
        if err == DB_SUCCESS:
            print("Inserted successfully")
        else:
            print(f"Error: {lib.db_error_string(err).decode()}")
    
    def do_find(self, arg):
        """Find a value by key: find <collection> <key>"""
        if not self.current_db:
            print("No database selected. Use 'use <db_name>' first.")
            return
        parts = arg.split()
        if len(parts) != 2:
            print("Usage: find <collection> <key>")
            return
        collection, key = parts
        value_ptr = ctypes.c_char_p()
        err = lib.db_find(self.current_db.encode(), collection.encode(), key.encode(), ctypes.byref(value_ptr))
        if err == DB_SUCCESS:
            if value_ptr:
                value = value_ptr.value.decode()
                print(f"Value: {value}")
                libc.free(value_ptr)
            else:
                print("Key not found")
        else:
            print(f"Error: {lib.db_error_string(err).decode()}")
    
    def do_update(self, arg):
        """Update a key-value pair: update <collection> <key> <value>"""
        if not self.current_db:
            print("No database selected. Use 'use <db_name>' first.")
            return
        parts = arg.split(maxsplit=2)
        if len(parts) < 3:
            print("Usage: update <collection> <key> <value>")
            return
        collection, key, value = parts
        err = lib.db_update(self.current_db.encode(), collection.encode(), key.encode(), value.encode())
        if err == DB_SUCCESS:
            print("Updated successfully")
        else:
            print(f"Error: {lib.db_error_string(err).decode()}")
    
    def do_delete(self, arg):
        """Delete a key: delete <collection> <key>"""
        if not self.current_db:
            print("No database selected. Use 'use <db_name>' first.")
            return
        parts = arg.split()
        if len(parts) != 2:
            print("Usage: delete <collection> <key>")
            return
        collection, key = parts
        err = lib.db_delete(self.current_db.encode(), collection.encode(), key.encode())
        if err == DB_SUCCESS:
            print("Deleted successfully")
        else:
            print(f"Error: {lib.db_error_string(err).decode()}")
    
    def do_generate_proof(self, arg):
        """Generate proof for a key: generate_proof <collection> <key>"""
        if not self.current_db:
            print("No database selected. Use 'use <db_name>' first.")
            return
        parts = arg.split()
        if len(parts) != 2:
            print("Usage: generate_proof <collection> <key>")
            return
        collection, key = parts
        proof = MembershipProof()
        err = lib.db_generate_proof(self.current_db.encode(), collection.encode(), key.encode(), ctypes.byref(proof))
        if err == DB_SUCCESS:
            print("Proof generated:")
            print(proof_to_json(proof))
            lib.membership_proof_cleanup(ctypes.byref(proof))
        else:
            print(f"Error: {lib.db_error_string(err).decode()}")
    
    def do_verify_proof(self, arg):
        """Verify proof for a key-value pair: verify_proof <collection> <key> <value> <proof_json>"""
        if not self.current_db:
            print("No database selected. Use 'use <db_name>' first.")
            return
        parts = arg.split(maxsplit=3)
        if len(parts) != 4:
            print("Usage: verify_proof <collection> <key> <value> <proof_json>")
            return
        collection, key, value, proof_json = parts
        proof = json_to_proof(proof_json)
        valid = ctypes.c_int()
        err = lib.db_verify_proof(self.current_db.encode(), collection.encode(), key.encode(), value.encode(), ctypes.byref(proof), ctypes.byref(valid))
        if err == DB_SUCCESS:
            print(f"Proof valid: {bool(valid.value)}")
        else:
            print(f"Error: {lib.db_error_string(err).decode()}")
        lib.membership_proof_cleanup(ctypes.byref(proof))
    
    def do_get_root_hash(self, arg):
        """Get root hash of a collection: get_root_hash <collection>"""
        if not self.current_db:
            print("No database selected. Use 'use <db_name>' first.")
            return
        parts = arg.split()
        if len(parts) != 1:
            print("Usage: get_root_hash <collection>")
            return
        collection = parts[0]
        root_hash = (ctypes.c_ubyte * HASH_SIZE)()
        err = lib.db_get_root_hash(self.current_db.encode(), collection.encode(), root_hash)
        if err == DB_SUCCESS:
            print(f"Root hash: {bytes_to_hex(root_hash)}")
        else:
            print(f"Error: {lib.db_error_string(err).decode()}")
    
    def do_save(self, arg):
        """Save current database: save"""
        if not self.current_db:
            print("No database selected. Use 'use <db_name>' first.")
            return
        err = lib.db_save(self.current_db.encode())
        if err == DB_SUCCESS:
            print("Database saved")
        else:
            print(f"Error: {lib.db_error_string(err).decode()}")
    
    def do_load(self, arg):
        """Load a database: load <db_name>"""
        if not arg:
            print("Usage: load <db_name>")
            return
        err = lib.db_load(arg.encode())
        if err == DB_SUCCESS:
            print(f"Database '{arg}' loaded")
        else:
            print(f"Error: {lib.db_error_string(err).decode()}")
    
    def do_save_all(self, arg):
        """Save all databases: save_all"""
        err = lib.db_save_all()
        if err == DB_SUCCESS:
            print("All databases saved")
        else:
            print(f"Error: {lib.db_error_string(err).decode()}")
    
    def do_load_all(self, arg):
        """Load all databases: load_all"""
        err = lib.db_load_all()
        if err == DB_SUCCESS:
            print("All databases loaded")
        else:
            print(f"Error: {lib.db_error_string(err).decode()}")
    
    def do_exit(self, arg):
        """Exit the shell"""
        print("Goodbye")
        return True

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py <persistence_path>")
        sys.exit(1)
    persistence_path = sys.argv[1]
    SMTShell(persistence_path).cmdloop()