import os
import hashlib
import random
from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator
from quantcrypt.internal.pqa.dss import FastSphincs
from quantcrypt.internal.pqa.errors import DSSSignFailedError, DSSVerifyFailedError

# Paths for saving keys
PRIVATE_KEY_PATH = "private_key.pem"
PUBLIC_KEY_PATH = "public_key.pem"

def generate_quantum_hash():
    """
    Generates a quantum-enhanced hash using a quantum circuit.
    """
    circuit = QuantumCircuit(8, 8)  # 8 qubits, 8 classical bits
    circuit.h(range(8))  # Apply Hadamard gate for superposition
    circuit.barrier()
    circuit.cx(0, 1)  
    circuit.cx(2, 3)  
    circuit.cx(4, 5)  
    circuit.cx(6, 7)  
    circuit.barrier()
    circuit.h(range(8))  # Apply Hadamard gate again for interference
    circuit.measure_all()
    
    simulator = AerSimulator()
    result = simulator.run(circuit, shots=1).result()
    counts = result.get_counts()
    
    # Get the first measurement result and ensure it's a clean binary string
    measured_state = list(counts.keys())[0].replace(" ", "")  # Remove spaces

    return int(measured_state, 2).to_bytes((len(measured_state) + 7) // 8, byteorder='big')

def bb84_qkd():
    """
    Simulates a simple BB84 Quantum Key Distribution protocol.
    """
    alice_basis = [random.choice(['+', 'x']) for _ in range(8)]
    alice_bits = [random.randint(0, 1) for _ in range(8)]
    
    bob_basis = [random.choice(['+', 'x']) for _ in range(8)]
    
    # Alice prepares her qubits
    alice_circuit = QuantumCircuit(8, 8)
    for i in range(8):
        if alice_basis[i] == '+':
            if alice_bits[i] == 1:
                alice_circuit.x(i)
        else:
            if alice_bits[i] == 1:
                alice_circuit.h(i)
    
    # Bob measures the qubits
    bob_circuit = alice_circuit.copy()
    for i in range(8):
        if bob_basis[i] == 'x':
            bob_circuit.h(i)
    bob_circuit.measure(range(8), range(8))
    
    simulator = AerSimulator()
    result = simulator.run(bob_circuit, shots=1).result()
    counts = result.get_counts()
    bob_bits = list(counts.keys())[0]
    
    # Key sifting
    shared_key = []
    for i in range(8):
        if alice_basis[i] == bob_basis[i]:
            shared_key.append(bob_bits[i])
    
    return ''.join(shared_key)

def encrypt_with_key(data, key):
    """
    Encrypts data using the shared key from BB84.
    """
    key_bytes = key.encode('utf-8')  # Convert the string key to bytes
    encrypted_data = bytes([data[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(data))])
    return encrypted_data

def decrypt_with_key(encrypted_data, key):
    """
    Decrypts data using the shared key from BB84.
    """
    return encrypt_with_key(encrypted_data, key)  # XOR is symmetric

def generate_signature(password):
    """
    Generates a signature for a given password using quantum randomness and BB84 encryption.
    """
    quantum_hash = generate_quantum_hash()
    salt = os.urandom(16)

    # Generate shared key using BB84
    shared_key = bb84_qkd()
    print(f"Shared key from BB84: {shared_key}")

    # Encrypt the password hash with the shared key
    password_hash = hashlib.sha256(salt + quantum_hash + password.encode()).digest()
    encrypted_hash = encrypt_with_key(password_hash, shared_key)

    # Generate post-quantum cryptographic keys
    fast_sphincs = FastSphincs()
    public_key, private_key = fast_sphincs.keygen()

    # Save keys
    with open(PRIVATE_KEY_PATH, "wb") as private_file:
        private_file.write(private_key)
    with open(PUBLIC_KEY_PATH, "wb") as public_file:
        public_file.write(public_key)

    # Sign the encrypted hash
    try:
        signature = fast_sphincs.sign(private_key, encrypted_hash)
    except DSSSignFailedError as e:
        print(f"Signature generation failed: {e}")
        return None, None, None, None, None

    return public_key, signature, salt, quantum_hash, shared_key

def verify_signature(signature, password, salt, quantum_hash, shared_key):
    """
    Verifies the given signature against the password using the public key and BB84 decryption.
    """
    password_hash = hashlib.sha256(salt + quantum_hash + password.encode()).digest()
    encrypted_hash = encrypt_with_key(password_hash, shared_key)

    # Load the public key
    with open(PUBLIC_KEY_PATH, "rb") as public_file:
        public_key = public_file.read()

    fast_sphincs = FastSphincs()

    try:
        is_valid = fast_sphincs.verify(public_key, encrypted_hash, signature)
        return is_valid
    except DSSVerifyFailedError as e:
        print(f"Verification failed: {e}")
        return False

# eg:
if __name__ == "__main__":
    password = "securepassword123"
    pub_key, sig, salt, q_hash, shared_key = generate_signature(password)

    if pub_key and sig:
        print("Signature generated successfully.")

        if verify_signature(sig, password, salt, q_hash, shared_key):
            print("Signature verified successfully.")
        else:
            print("Signature verification failed.")