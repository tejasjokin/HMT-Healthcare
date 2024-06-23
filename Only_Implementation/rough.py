import tkinter as tk
from tkinter import messagebox
from datetime import datetime
import random
import string
import os
import json
import time as tm
import psutil
import hashlib
import time


def hash_data(data):
    # Encode the data to bytes
    data_bytes = data.encode('utf-8')
    # Create a SHA-256 hash object
    sha256_hash = hashlib.sha256()
    # Update the hash object with the data bytes
    sha256_hash.update(data_bytes)
    # Get the hexadecimal representation of the hash
    hashed_data = sha256_hash.hexdigest()
    return hashed_data
def submit_transaction(transaction_data):
    print("Transaction submitted:", transaction_data)
start_time = time.time()


# Simulated ABE key generation (placeholder)
def abe_key_gen(attributes):
    attributes_string = json.dumps(attributes, sort_keys=True)
    return f"ABEKey_{hash(attributes_string)}"


def generate_user_keys(attributes, key_size):
    private_key, public_key = Certificate_Authorities.KeyGen(key_size)
    abe_key = ABE('').generate_master_key(key_size)
    return private_key, public_key, abe_key


class Certificate_Authorities:
    def __init__(self=None):
        # Initialize the dictionary to store participants' attributes
        self.participants = {}

    from cryptography.fernet import Fernet as abe
    @staticmethod
    def create_CA():
        print('The certificate authority is created')

    @staticmethod
    def requset_recevied(user):
        print('The CA received request from AA')
        ca = []
        ca.append(user)
        print('The CA accepts the request')

    @staticmethod
    def verify_request(user):
        print('The CA verified with AA')

    @staticmethod
    def KeyGen(key_size):
        # Generate a "private key" as a random integer with key_size bits
        private_key = os.urandom(key_size // 8)

        # Generate a "public key" as a random integer with key_size bits
        public_key = os.urandom(key_size // 8)

        # Convert the keys to hexadecimal strings for easy display and handling
        private_key_hex = private_key.hex()
        public_key_hex = public_key.hex()

        return public_key_hex, private_key_hex

    @staticmethod
    def share_key(key_size, user):
        Certificate_Authorities.requset_recevied(user)
        public_key, private_key = Certificate_Authorities.KeyGen(key_size)
        print('Key is shared...')
        return public_key, private_key


class Blockchain:
    def __init__(self):
        self.chain = []
        self.current_transactions = []
        self.new_block(previous_hash='1', proof=100)

    def new_block(self, proof, previous_hash=None):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': tm.time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }
        self.current_transactions = []
        self.chain.append(block)
        return block

    def new_request(self, user, proof, previous_hash=None):
        print(f"Data user {user[0]} request accepted in BC.")
        block = {
            'user': user[0],
            'password': user[1],
            'index': len(self.chain) + 1,
            'timestamp': tm.time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }
        self.chain.append(block)
        print(f"Data user {user[0]} verified in BC")
    def save_data1(self, user, patient_data):
        block = {
            'Data owner': user,
            'Patient Data': patient_data,
            # 'Encrypted Data': encrypted_data
        }
        self.chain.append(block)
        print(f"Encrypted data for user {user} saved successfully in BC")

    def save_data(self, user, patient_data, encrypted_data):
        block = {
            'Data owner': user,
            'Patient Data': patient_data,
            'Encrypted Data': encrypted_data
        }
        self.chain.append(block)
        print(f"Encrypted data for user {user} saved successfully in BC")
    def save_data_1(self, user, patient_data, encrypted_data,decrpted_data):
        block = {
            'Data owner': user,
            'Patient Data': patient_data,
            'Encrypted Data': encrypted_data,
            'Decrypted Data': decrypted_data
        }
        self.chain.append(block)
        print(f"decrypted data for user {user} saved successfully in BC")
    def get_data(self, user, patient_data, encrypted_data):
        block = {
            'Data owner': user,
            'Patient Data': patient_data,
            'Encrypted Data': encrypted_data
        }
        # self.chain.append(block)
        print(f"Encrypted data for user {user} saved successfully in BC")
        return encrypted_data
    def new_transaction(self, sender, recipient, amount):
        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
        })
        return self.last_block['index'] + 1

    @staticmethod
    def hash(block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    @property
    def last_block(self):
        return self.chain[-1]

    def proof_of_work(self, last_proof):
        proof = 0
        while self.valid_proof(last_proof, proof) is False:
            proof += 1
        return proof

    @staticmethod
    def valid_proof(last_proof, proof):
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"


class AttributeAuthority:
    def __init__(self):
        self.participants = {}

    def add_participant(self, participant_info):
        participant_id, password = participant_info
        if participant_id not in self.participants:
            self.participants[participant_id] = {"Password": password}
            print(f"Participant {participant_id} added.")
        else:
            print(f"Participant {participant_id} already exists.")
        print('The data owner is requested with AA')

    def verification_process(self, participant_info):
        participant_id, _ = participant_info
        if participant_id in self.participants:
            print(f"Participant {participant_id} verified successfully in AA.")

    def share_key(self, key_size, user):
        public_key, private_key = Certificate_Authorities.share_key(key_size, user)
        return public_key, private_key


class PatientRegistrationApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Patient Registration")
        self.create_widgets()

    def create_widgets(self):
        tk.Label(self.root, text="Patient ID:").grid(row=0, column=0, sticky=tk.W)
        self.patient_id_entry = tk.Entry(self.root)
        self.patient_id_entry.grid(row=0, column=1)

        tk.Label(self.root, text="Date:").grid(row=1, column=0, sticky=tk.W)
        self.date_entry = tk.Entry(self.root)
        self.date_entry.grid(row=1, column=1)
        self.date_entry.insert(0, datetime.now().strftime("%Y-%m-%d"))

        tk.Label(self.root, text="Age (years):").grid(row=2, column=0, sticky=tk.W)
        self.age_entry = tk.Entry(self.root)
        self.age_entry.grid(row=2, column=1)

        tk.Label(self.root, text="Heart Rate (bpm):").grid(row=3, column=0, sticky=tk.W)
        self.heart_rate_entry = tk.Entry(self.root)
        self.heart_rate_entry.grid(row=3, column=1)

        tk.Label(self.root, text="Blood Pressure (mmHg):").grid(row=4, column=0, sticky=tk.W)
        self.blood_pressure_entry = tk.Entry(self.root)
        self.blood_pressure_entry.grid(row=4, column=1)

        tk.Label(self.root, text="Weight (Kg):").grid(row=5, column=0, sticky=tk.W)
        self.weight_entry = tk.Entry(self.root)
        self.weight_entry.grid(row=5, column=1)

        tk.Label(self.root, text="Height (cm):").grid(row=6, column=0, sticky=tk.W)
        self.height_entry = tk.Entry(self.root)
        self.height_entry.grid(row=6, column=1)

        tk.Label(self.root, text="Symptoms:").grid(row=7, column=0, sticky=tk.W)
        self.symptoms_entry = tk.Entry(self.root)
        self.symptoms_entry.grid(row=7, column=1)

        tk.Label(self.root, text="Diagnosis:").grid(row=8, column=0, sticky=tk.W)
        self.diagnosis_entry = tk.Entry(self.root)
        self.diagnosis_entry.grid(row=8, column=1)

        tk.Label(self.root, text="Medicine:").grid(row=9, column=0, sticky=tk.W)
        self.medicine_entry = tk.Entry(self.root)
        self.medicine_entry.grid(row=9, column=1)

        tk.Label(self.root, text="Password:").grid(row=10, column=0, sticky=tk.W)
        self.password_var = tk.StringVar()
        self.password_entry = tk.Entry(self.root, textvariable=self.password_var, state='disabled')
        self.password_entry.grid(row=10, column=1)

        self.register_button = tk.Button(self.root, text="Register", command=self.register_patient)
        self.register_button.grid(row=11, columnspan=2)

    def generate_password(self):
        length = 8
        chars = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(chars) for i in range(length))

    def register_patient(self):
        password = self.generate_password()
        self.password_var.set(password)
        patient_data = {
            "Patient ID": self.patient_id_entry.get(),
            "Date": self.date_entry.get(),
            "Age": self.age_entry.get(),
            "Heart Rate": self.heart_rate_entry.get(),
            "Blood Pressure": self.blood_pressure_entry.get(),
            "Weight": self.weight_entry.get(),
            "Height": self.height_entry.get(),
            "Symptoms": self.symptoms_entry.get(),
            "Diagnosis": self.diagnosis_entry.get(),
            "Medicine": self.medicine_entry.get(),
            "Password": password
        }

        print("Patient Data:", patient_data)
        messagebox.showinfo("Success", "Patient registered successfully")
        self.disable_entry_fields()

        try:
            with open("patient_data.json", "r") as file:
                existing_data = json.load(file)
        except FileNotFoundError:
            existing_data = []

        existing_data.append(patient_data)

        with open("patient_data.json", "w") as file:
            json.dump(existing_data, file)

        self.root.destroy()

    def disable_entry_fields(self):
        for entry in (self.patient_id_entry, self.date_entry, self.age_entry, self.heart_rate_entry,
                      self.blood_pressure_entry, self.weight_entry, self.height_entry, self.symptoms_entry,
                      self.diagnosis_entry, self.medicine_entry, self.password_entry):
            entry.config(state='disabled')

def on_button_click():
    label.config(text="Button Clicked!")
    app_frame.pack_forget()
    PatientRegistrationApp(root)
def create_data_user():
    return random.randint(1,10)

class ABE:
    def __init__(self, master_key):
        self.master_key = master_key

    def encrypt(self, message, attributes):
        shared_key = self.generate_shared_key(attributes)
        encrypted_message = self.xor(message, shared_key)
        return encrypted_message

    def decrypt(self, encrypted_message, attributes):
        shared_key = self.generate_shared_key(attributes)
        decrypted_message = self.xor(encrypted_message, shared_key)
        return decrypted_message

    def generate_master_key(self, key_size):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=key_size))

    def generate_shared_key(self, attributes):
        shared_key = hashlib.sha256(self.master_key.encode()).digest()
        for attribute in attributes:
            shared_key += hashlib.sha256(attribute.encode()).digest()
        # Truncate the key to 16 bytes
        shared_key = shared_key[:16]
        return shared_key

    def xor(self, message, key):
        # Simple XOR operation
        return bytes([message[i] ^ key[i % len(key)] for i in range(len(message))])


if __name__ == "__main__":
    root = tk.Tk()
    root.title("User Registration")

    app_frame = tk.Frame(root)
    app_frame.pack(pady=20, padx=20)

    label = tk.Label(app_frame, text="Hello, click here to register")
    label.pack(pady=10)

    button = tk.Button(app_frame, text="Click", command=on_button_click)
    button.pack(pady=10)
    root.mainloop()

    try:
        with open("patient_data.json", "r") as file:
            existing_data = json.load(file)
    except FileNotFoundError:
        existing_data = []

    if existing_data:
        aa = AttributeAuthority()
        user1 = [existing_data[0]['Patient ID'], existing_data[0]['Password']]
        aa.add_participant(user1)
        aa.verification_process(user1)
        print('The data owner is registered with AA')
        ###create data user
        u = create_data_user()
        aa.add_participant(user1)
        aa.verification_process(user1)
        print('The data user is registered with AA')
        blockchain = Blockchain()
        proof = blockchain.proof_of_work(blockchain.last_block['proof'])
        blockchain.new_block(proof)
        blockchain.new_request(user1, proof)
        blockchain.save_data1(user1,existing_data)

        Certificate_Authorities.create_CA()
        Certificate_Authorities.requset_recevied(user1)
        Certificate_Authorities.verify_request(user1)

        key_size = 16
        private_key, public_key = Certificate_Authorities.share_key(key_size, user1)
        print('Key is shared with AA')
        k1, k2 = aa.share_key(key_size, user1)
        print('The generated key is shared with the data owner')
        # combined the key with abe algorithm
        private_key, public_key, abe_key = generate_user_keys(existing_data[0], key_size)
        print('Keys generated and shared')
        # signature = sign_data(u, private_key)

        ###### Encrypt the data and stored in BC
        # Define the attributes
        attributes = ["admin", "user"]
        # Initialize the ABE object
        abe = ABE(abe_key)
        # message = existing_data
        message_bytes = json.dumps(existing_data).encode('utf-8')
        encrypted_data = abe.encrypt(message_bytes, attributes)
        print("Encrypted Data:",encrypted_data)
        ####encrypted data stored in BC
        blockchain.save_data(user1, existing_data, encrypted_data)
        ###### the dU send request to BC

        encrypted_data=Blockchain.get_data(user1,u, existing_data, encrypted_data)
        submit_transaction(existing_data)
        decrypted_data = abe.decrypt(encrypted_data, attributes)
        decrypted_data_dict = json.loads(decrypted_data.decode('utf-8'))

        print("Decrypted Data:", decrypted_data)
        blockchain.save_data_1(user1, existing_data[0], encrypted_data,decrypted_data)
        end_time = time.time()
        execution_time = end_time - start_time

        print("Execution time:", execution_time, "seconds")
        memory = psutil.virtual_memory()
        print("Total Memory:", memory.total)
        print("Available Memory:", memory.available)
        print("Used Memory:", memory.used)
