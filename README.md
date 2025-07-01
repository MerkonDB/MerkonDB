# MerkonDB

A cryptographically secure, Merkle Tree-based key-value database system with role-based access control and verifiable data integrity.

## Overview

MerkonDB is a modern database system that combines the security of cryptographic proofs with the efficiency of specialized indexing structures. Built around the innovative PMAT (Partitioned Merkle Array Tree) architecture, it provides:

- **Cryptographic Integrity Verification** - Every operation is cryptographically verifiable
- **Role-Based Access Control (RBAC)** - Fine-grained permission management
- **Membership Proofs** - Generate and verify inclusion proofs for any key
- **Interactive CLI Shell** - Color-coded terminal interface for database management
- **Multi-Database Support** - Organize data across multiple named databases and collections

## Architecture

```mermaid
graph TD
    A[Client Shell<br/>(client.py)] -->|JSON over TCP| B[Socket API<br/>(TCP)]

    B --> C1[Authentication & RBAC<br/>(rbac.c)]
    B --> C2[Database Engine<br/>(smt.c + smt_db.c)]

    C2 --> D[PMAT Indexing Structure<br/>(Partitioned Merkle Array Tree)]
    C2 --> E[File Storage]

    style A fill:#d1ecf1,stroke:#31708f
    style B fill:#fef3c7,stroke:#b45309
    style C1 fill:#f3e8ff,stroke:#7e22ce
    style C2 fill:#e0f2fe,stroke:#0369a1
    style D fill:#ecfccb,stroke:#15803d
    style E fill:#fef9c3,stroke:#ca8a04
```

## PMAT (Partitioned Merkle Array Tree)

PMAT is the core data structure powering MerkonDB's performance and security guarantees:

- **Efficient Search**: O(log k) complexity where k = n / partitions
- **Fast Modifications**: O(k) insertion and deletion operations  
- **Integrity Proofs**: Generate compact cryptographic proofs for any operation
- **Distributed Ready**: Verifiable operations across distributed environments

## Components

### Client Shell (`client.py`)
- Interactive terminal-based interface built with `cmd.Cmd`
- Handles authentication and TCP communication
- Supports MQL (MerkonDB Query Language) commands
- Manages database/collection switching and user roles
- Provides Merkle proof generation and verification

### Server (`server.c`)
- Main command dispatcher and request router
- Handles multiple concurrent client connections
- JSON-based serialization for all communications
- Integrates authentication with database operations

### RBAC Module (`rbac.c`)
- User and role management system
- Permission modeling with bitmasks (read, write, create, delete, admin)
- Access control enforcement for all protected operations

### Database Engine (`smt.c` & `smt_db.c`)
- PMAT structure implementation
- Key-value operations (insert, update, delete, find)
- Cryptographic proof generation and root hash computation
- Persistence and bulk operation support

## Installation

### Prerequisites
- GCC compiler
- `json-c` library
- `pthread` library  
- Python 3 with `colorama` package

### Build Server
```bash
gcc -o server server.c smt.c smt_db.c rbac.c -ljson-c -lpthread
```

### Install Client Dependencies
```bash
pip3 install colorama
```

## Usage

### Start Server
```bash
./server <host> <port>
```

### Connect Client
```bash
python3 client.py <host> <port> <username> <password>
```

## MQL Commands

### Database Operations
```sql
-- Switch to database
use testdb

-- Create collection
create collection users

-- Insert key-value pair
insert users john {"email": "john@example.com", "role": "admin"}

-- Find value by key
find users john

-- Get collection statistics
stats users

-- Get root hash
root users
```

### Cryptographic Proofs
```sql
-- Generate inclusion proof
proof users john

-- Verify proof
verify users john {"email": "john@example.com"} <proof_data>
```

### Data Management
```sql
-- Save all data to disk
save all

-- Compact storage
compact users

-- Show database info
show databases
```

## Key Features

| Feature | Description |
|---------|-------------|
| **RBAC** | Fine-grained access control using roles and permissions |
| **Multi-DB Support** | Multiple named databases with collections |
| **Verifiable Storage** | Merkle hashing ensures data integrity |
| **Membership Proofs** | Cryptographic inclusion proofs for any key |
| **Persistence** | Reliable save/load operations to/from disk |
| **Statistics** | Detailed collection and database usage metrics |
| **Compacting** | Storage space optimization |
| **CLI Shell** | Color-coded, user-friendly terminal interface |

## Security Model

MerkonDB implements a multi-layered security approach:

1. **Authentication**: Username/password based session management
2. **Authorization**: Role-based permissions with granular access control
3. **Integrity**: Merkle tree-based cryptographic verification
4. **Auditability**: All operations generate verifiable proofs

## Performance Characteristics

- **Search Complexity**: O(log k) where k = keys per partition
- **Insert/Delete**: O(k) complexity for modifications
- **Proof Generation**: Compact proofs with minimal overhead
- **Memory Efficiency**: Partitioned structure reduces memory pressure

