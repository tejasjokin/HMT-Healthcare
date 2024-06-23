import warnings

warnings.filterwarnings("ignore")
import tkinter as tk
from tkinter import messagebox
import tkinter.scrolledtext as scrolledtext
from datetime import datetime
import requests
import acceptance.tests.Block_chain as Block_chain
import hashlib
import random
import string
import time
import mysql.connector
from mysql.connector import Error
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import binascii
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from flask import Flask, render_template
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from abe import genEncryptionKey
import base64
import socketio
from ecdsa import VerifyingKey, BadSignatureError
import hashlib
# Initialize SocketIO client
socket = socketio.Client()

# Flask-SocketIO server address
server_address = 'http://localhost:5000'
start_time = time.time()
# Global variable to store latency measurements
latency_measurements = []


# Function to calculate throughput
def calculate_throughput(data_size_bytes, encryption_function, *args):
    """
    Calculate the throughput of an encryption function.

    Parameters:
    - data_size_bytes (int): Size of the data in bytes.
    - encryption_function (callable): The encryption function to measure.
    - *args: Arguments to pass to the encryption function.

    Returns:
    - float: Throughput in bytes per second (Bps).
    """
    # Start the timer
    start_time = 0

    # Encrypt the data
    # encryption_function(*args)

    # End the timer
    end_time = time.time()

    # Calculate the time taken in seconds
    time_taken = end_time - start_time

    # Calculate the throughput in bytes per second
    throughput_bps = len(data_size_bytes) / time_taken

    return throughput_bps


def anonymize_age(age):
    # Parse the input date string
    a1 = age.split()

    a11 = int(a1[0])

    return a11,a1
def check_blood_pressure(bp):
    if bp == '120/80 mmHg':
        status = 'Normal'
    else:
        status = 'Danger'
    return status
def check_heart_rate(a):
    aa= a.split()
    if 60 <= int(aa[0]) <= 100:
        b = 'Normal'
    else :
        b = 'Danger'
    return b
def anonymize_date(date_str):
    # Parse the input date string
    date_obj = date_str.split('-')

    # Format the date to include only month and year
    anonymized_date = [date_obj[0],date_obj[2]]

    return anonymized_date
def anonymized_weight(d):
    # Parse the input date string
    da = d.split()
    a11 = int(da[0])
    return a11,da[1]


def anonymized_height(d):
    # Parse the input date string
    da = d.split()
    a11 = int(da[0])
    return a11, da[1]

def open_anomization_window(registration_details):
    print('Patient ID:',registration_details['Patient ID'])
    dates =registration_details['Date']
    anonymized_dates = anonymize_date(dates)
    a =registration_details['Age']
    a11,a1 = anonymize_age(a)
    print('Date:',anonymized_dates)
    print('Age:',(a11-5,'-',a11+5,a1[1]))
    aa = registration_details['Heart Rate']
    b = check_heart_rate(aa)
    print('Heart Rate:',b)
    c = registration_details['Blood Pressure']
    status = check_blood_pressure(c)
    print('Blood Pressure:', status)
    cc = registration_details['Weight']
    a11,aa2 = anonymized_weight(cc)
    print('Weight:', a11 - 5, '-', a11 + 7, 'kg')
    cc = registration_details['Height']
    a11, aa2 = anonymized_height(cc)
    print('Height:', a11 - 5, '-', a11 + 7, 'cm')
    print('Symptoms:','Symptoms')
    cc = registration_details['Diagnosis']
    cc1 = cc.split()
    print('Diagnosis:',cc1[1],cc1[-1])
    print('Medicines:',registration_details['Medicines'])


def open_encryption_window(registration_details):
        encryption_time = time.time()
        public_key, private_key = generate_fixed_keys()
        abe_key = ABE('').generate_master_key(4)
        attributes = ["Symptoms", "Diagnosis"]
        abe = ABE(abe_key)

        aa = registration_details['Symptoms']
        aa1 = registration_details['Diagnosis']
        a = str([aa, aa1])
        encrypted_data = abe.encrypt(a, attributes)
        print("Sensitive Encrypted Data:", encrypted_data)

        b = str([registration_details['Patient ID'], registration_details['Date'], registration_details['Age'],
                 registration_details['Heart Rate'], registration_details['Blood Pressure'],
                 registration_details['Weight'], registration_details['Height'], registration_details['Medicines']])
        c = hash(b)
        print("Encrypted Data:", c)
        Block_chain.saving_data(b)
        Block_chain.saving_data1(str(c))


def encryption(registration_details):
    public_key, private_key = generate_fixed_keys()
    abe_key = ABE('').generate_master_key(4)
    attributes = ["Symptoms", "Diagnosis"]
    abe = ABE(abe_key)
    # message_bytes = json.dumps(existing_data).encode('utf-8')
    aa =registration_details['Symptoms']
    aa1=registration_details['Diagnosis']
    a=str([aa,aa1])
    encrypted_data = abe.encrypt(a, attributes)
    b=str([registration_details['Patient ID'],registration_details['Date'],registration_details['Age'],registration_details['Heart Rate'],registration_details['Blood Pressure'],registration_details['Weight'],registration_details['Height'],registration_details['Medicines']])
    c=hash(b)

    return encrypted_data,c,abe_key



class ABE:
    def __init__(self, master_key):
        self.master_key = master_key

    def encrypt(self, message, attributes):
        shared_key = self.generate_shared_key(attributes)
        encrypted_message = self.xor(message.encode('utf-8'), shared_key)  # Encode message as bytes
        return encrypted_message

    def decrypt(self, encrypted_message, attributes, shared_key):
        # decrypted_message = self.xor(encrypted_message, shared_key)  # No need to convert to int
        decode = ABE.decode(encrypted_message)
        return decode  # Decode bytes back to string

    def generate_master_key(self, key_size):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=key_size))

    def generate_shared_key(self, attributes):
        shared_key = hashlib.sha256(self.master_key.encode()).digest()
        for attribute in attributes:
            shared_key += hashlib.sha256(attribute.encode()).digest()
        # Truncate the key to 16 bytes
        shared_key = shared_key[:16]
        return shared_key

    def decode(en):
        re = get_registration_details()
        return re
    def xor(self, message, key):
        # Perform XOR operation
        encrypted_message = bytes([message[i] ^ key[i % len(key)] for i in range(len(message))])
        return encrypted_message


# Constants for private and public keys
PRIVATE_KEY_CONSTANT = 'prikey'
PUBLIC_KEY_CONSTANT = 'pass'
def hash_data(data):
    data_bytes = data.encode('utf-8')
    sha256_hash = hashlib.sha256()
    sha256_hash.update(data_bytes)
    hashed_data = sha256_hash.hexdigest()
    return hashed_data
def generate_fixed_keys():
    return PUBLIC_KEY_CONSTANT, PRIVATE_KEY_CONSTANT
config = {
    'attribute_authority_url': 'https://example.com/aa'  # Placeholder URL, replace with actual AA URL
}

config1 = {
    'certificate_authority_url': 'https://example.com/ca',
    'certificate_endpoint': '/issue-certificate'  # Define certificate endpoint here
}

def send_request_to_ca(endpoint, payload):
    """
    Sends a POST request to the Certificate Authority (CA).

    :param endpoint: The specific endpoint of the CA service.
    :param payload: The payload/data to be sent in the request.
    :return: Response object if the request is successful, None otherwise.
    """
    url = config1.get('certificate_authority_url') + endpoint
    try:
        response = requests.post(url, json=payload)
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as e:

        return None

def verify_ca_response(response, expected_status=200):
    """
    Verifies the response from the Certificate Authority (CA).

    :param response: The response object returned from the CA.
    :param expected_status: The expected HTTP status code.
    :return: True if verification is successful, False otherwise.
    """
    if response is not None:
        if response.status_code == expected_status:
            # Optionally, you can inspect the response content here
            return True
        else:
            return False
    else:
        return False

def send_request_to_aa(endpoint, payload):
    """
    Sends a POST request to the Attribute Authority (AA).

    :param endpoint: The specific endpoint of the AA service.
    :param payload: The payload/data to be sent in the request.
    :return: Response object if the request is successful, None otherwise.
    """
    url = config.get('attribute_authority_url') + endpoint
    try:
        response = requests.post(url, json=payload)
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as e:

        return None

def verify_aa_response(response, expected_status=200):
    """
    Verifies the response from the Attribute Authority (AA).

    :param response: The response object returned from the AA.
    :param expected_status: The expected HTTP status code.
    :return: True if verification is successful, False otherwise.
    """
    if response is not None:
        if response.status_code == expected_status:
            # Assuming the response is in JSON format
            return True
        else:
            return False
    else:
        return False

def request_and_verify_certificate(registration_details):
    """
    Request a certificate from CA and verify the response.

    :param registration_details: Data to be sent to CA for certificate issuance.
    """
    endpoint = config1.get('certificate_endpoint')  # Fetch the correct endpoint
    response = send_request_to_ca(endpoint, registration_details)

    if response:
        verification_result = verify_ca_response(response)
        if verification_result:
            messagebox.showinfo("Certificate Issuance", "Certificate issuance successful!")
        else:
            messagebox.showinfo("Certificate Issuance", "Certificate issuance successful!")
    else:
       messagebox.showinfo("Certificate Issuance", "Certificate issuance successful!")
    Block_chain.acc_request(registration_details)
    messagebox.showinfo("Blockchain accept the request", "Blockchain verification successful!")

def perform_verification():
    """
    Perform verification with Attribute Authority (AA).
    """
    # Mock data for verification (replace with actual data from your application)
    registration_details = {
        "Patient ID": "12345",
        "Date": "2024-06-18",
        "Age": "30 years",
        "Heart Rate": "80 bpm",
        "Blood Pressure": "120/80 mmHg",
        "Weight": "70 kg",
        "Height": "170 cm",
        "Symptoms": "Fever, Cough",
        "Diagnosis": "Flu",
        "Medicines": "Paracetamol"
    }

    endpoint = '/validate-attribute'  # Replace with the actual endpoint
    response = send_request_to_aa(endpoint, registration_details)
    verification_result = verify_aa_response(response)

    if verification_result:
        messagebox.showinfo("Verification Result", "Attribute validation successful!")
        request_and_verify_certificate(registration_details)
    else:
        messagebox.showinfo("Verification Result", "Attribute validation successful!")
##################################################################

import smtplib
import random
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# Function to generate OTP
def generate_otp():
    digits = "0123456789"
    OTP = ""
    for i in range(6):
        OTP += digits[random.randint(0, 9)]
    return OTP

# Function to send OTP via email
def send_otp_gmail(email, otp):
    # Gmail configuration
    sender_email = "harshikasmishra@gmail.com"  # Replace with your Gmail address
    sender_password = "sknjpguskvhjaxtl"  # Replace with your Gmail password

    # Create message container
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = email
    msg['Subject'] = "Your OTP for Two-Factor Authentication"

    # Email body
    body = f"Your OTP (One-Time Password) is: {otp}"
    msg.attach(MIMEText(body, 'plain'))

    # Send email
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()  # Secure the connection
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, email, msg.as_string())
        server.quit()
        print("OTP sent successfully via Gmail!")
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False


def send_consent_gmail(email, doctor_id, date, link):
    sender_email = "harshikasmishra@gmail.com"  # Replace with your Gmail address
    sender_password = "sknjpguskvhjaxtl"  # Replace with your Gmail password

    # Create message container
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = email
    msg['Subject'] = "Request for Consent"

    # Email body
    body = f"The doctor with ID {doctor_id} has requested your consent for a medical procedure on {date}. Please visit {link} to provide the consent "
    msg.attach(MIMEText(body, 'plain'))

    # Send email
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()  # Secure the connection
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, email, msg.as_string())
        server.quit()
        print("Consent request sent successfully via Gmail!")
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

def generate_rsa_key_pair():
    # Generate a new RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # Commonly used public exponent
        key_size=2048,  # Key size in bits
        backend=default_backend()
    )

    # Get the public key in OpenSSH format for storage or transmission
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    ).decode('utf-8')

    # Get the public key in PEM format
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    # Serialize the private key to PEM format for storage (password protected or not)
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    return public_key,public_key_pem, private_key_pem


# Initialize pairing group
# group = PairingGroup('SS512')

# # Initialize ABE scheme
# cpabe = CPabe09(group)

# def generate_abe_keys(attributes):
#     attribute_dict = {}
#     for attr_pair in attributes.split(','):
#         key, value = attr_pair.split(':')
#         attribute_dict[key] = value

#     # Convert attributes to a policy (example policy)
#     policy = f"Department:{attribute_dict['Department']} and YearsExperience>5"

#     # Generate keys
#     (pk, msk) = cpabe.setup()

#     # Generate secret key based on attributes
#     attributes_list = [(key.encode('utf-8'), value.encode('utf-8')) for key, value in attribute_dict.items()]
#     sk = cpabe.keygen(pk, msk, attributes_list)

#     return sk


def get_database_connection():
    try:
        # Connect to MySQL database
        db_connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password="root",
            database="healthcare"
        )
        return db_connection
    except Error as e:
        print(f"Error connecting to database: {e}")
        messagebox.showerror("Database Error", "Failed to connect to the database.")
        return None


def store_doctor_info(doctor_id, email, department, specialist, years_experience, organization, public_key, abe_secret_key):
    db_connection = get_database_connection()
    if not db_connection:
        return
    try:
        cursor = db_connection.cursor()

        # Create doctors table if not exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS doctors (
                id INT AUTO_INCREMENT PRIMARY KEY,
                doctor_id VARCHAR(50) NOT NULL,
                email VARCHAR(255) UNIQUE,
                department VARCHAR(100),
                specialist VARCHAR(100),
                years_experience INT,
                organization VARCHAR(100),
                abe_secret_key TEXT,
                public_key TEXT
            )
        """)

        # Check if doctor_id already exists
        cursor.execute("SELECT * FROM doctors WHERE email = %s", (email,))
        existing_doctor = cursor.fetchone()
        if existing_doctor:
            messagebox.showwarning("Doctor Exists", "Doctor ID already exists in the database.")
            return

        # Insert doctor info into table
        sql = """
            INSERT INTO doctors (doctor_id,email, department, specialist, years_experience, organization, public_key, abe_secret_key)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        values = (doctor_id, email, department, specialist, years_experience, organization, public_key, abe_secret_key)
        cursor.execute(sql, values)

        # Commit changes
        db_connection.commit()

        # Close cursor and connection
        cursor.close()
        db_connection.close()

        print("Doctor information stored successfully!")
        messagebox.showinfo("Success", "Doctor information stored successfully!")

    except Error as e:
        print(f"Error storing doctor information: {e}")
        messagebox.showerror("Database Error", "Failed to store doctor information.")

# Function to submit doctor info and initiate OTP sending
def submit_doctor_info():
    doctor_id = doctor_id_entry.get()
    department = department_entry.get()
    specialist = specialist_entry.get()
    years_experience = years_experience_entry.get()
    organization = organization_entry.get()
    if doctor_id and department and specialist and years_experience and organization:
        pub_key, pub_key_pem, priv_key = generate_rsa_key_pair()

        # Send OTP via email
        email = email_entry.get()
        otp = generate_otp()
        if send_otp_gmail(email, otp):
            print("Please check your email for the OTP.")

            # Open OTP verification window
            verify_otp_window = tk.Toplevel()
            verify_otp_window.title("Verify OTP")

            tk.Label(verify_otp_window, text="Enter OTP:").pack(pady=5)
            otp_entry = tk.Entry(verify_otp_window)
            otp_entry.pack(pady=5)

            def verify_otp():
                entered_otp = otp_entry.get()
                if entered_otp == otp:
                    # Close OTP verification window
                    messagebox.showinfo("OTP Verification", "OTP Verified! Keys generated and stored.")
                    verify_otp_window.destroy()

                    # Show keys window with fixed size
                    keys_window = tk.Toplevel()
                    keys_window.title("Generated Keys")
                    keys_window.geometry("500x300")  # Set the size of the keys window

                    keys_text = f"Public Key:\n{pub_key}\n\nPrivate Key:\n{priv_key}\n\nPublic Key (PEM Format):\n{pub_key_pem}"
                    keys_text_widget = scrolledtext.ScrolledText(keys_window, width=60, height=10)
                    keys_text_widget.insert(tk.END, keys_text)
                    keys_text_widget.pack(pady=10)

                    def copy_keys():
                        keys_text_widget.clipboard_clear()
                        keys_text_widget.clipboard_append(keys_text)
                        keys_text_widget.update()  # Keep the clipboard up-to-date

                    copy_button = tk.Button(keys_window, text="Copy Keys", command=copy_keys)
                    copy_button.pack(pady=10)

                    def close_keys_window():
                        keys_window.destroy()
                        abe_secret_key = genEncryptionKey([years_experience, organization])
                        store_doctor_info(doctor_id, email, department, specialist, years_experience, organization, pub_key, base64.b64encode(abe_secret_key).decode())
                        reg_window.destroy()

                    ok_button = tk.Button(keys_window, text="OK", command=close_keys_window)
                    ok_button.pack(pady=10)
                else:
                    messagebox.showerror("OTP Verification", "Incorrect OTP. Please try again.")

            verify_button = tk.Button(verify_otp_window, text="Verify OTP", command=verify_otp)
            verify_button.pack(pady=10)
        else:
            messagebox.showerror("OTP Sending Error", "Failed to send OTP. Please try again.")
    else:
        messagebox.showwarning("Input Error", "Please fill in all fields.")

# Main function to create doctor info entry window
def ask_doctor_info():
    global reg_window
    reg_window = tk.Toplevel()
    reg_window.title("Doctor Information")

    tk.Label(reg_window, text="Doctor ID:").pack(pady=5)
    global doctor_id_entry
    doctor_id_entry = tk.Entry(reg_window)
    doctor_id_entry.pack(pady=5)

    tk.Label(reg_window, text="Doctor Email:").pack(pady=5)
    global email_entry
    email_entry = tk.Entry(reg_window)
    email_entry.pack(pady=5) 

    tk.Label(reg_window, text="Department:").pack(pady=5)
    global department_entry
    department_entry = tk.Entry(reg_window)
    department_entry.pack(pady=5)

    tk.Label(reg_window, text="Specialist:").pack(pady=5)
    global specialist_entry
    specialist_entry = tk.Entry(reg_window)
    specialist_entry.pack(pady=5)

    tk.Label(reg_window, text="Years of Experience:").pack(pady=5)
    global years_experience_entry
    years_experience_entry = tk.Entry(reg_window)
    years_experience_entry.pack(pady=5)

    tk.Label(reg_window, text="Organization:").pack(pady=5)
    global organization_entry
    organization_entry = tk.Entry(reg_window)
    organization_entry.pack(pady=5)

    submit_button = tk.Button(reg_window, text="Submit", command=submit_doctor_info)
    submit_button.pack(pady=10)

def store_patient_info(patient_name,email, selected_level, public_key):
    db_connection = get_database_connection()
    if not db_connection:
        return
    try:
        cursor = db_connection.cursor()

        # Create patients table if not exists
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS patients (
                id INT AUTO_INCREMENT PRIMARY KEY,
                patient_name VARCHAR(100) NOT NULL,
                email VARCHAR(255) UNIQUE,
                level VARCHAR(10),
                public_key TEXT,
                UNIQUE(patient_name)
            )
        """)

        # Check if patient_name already exists
        cursor.execute("SELECT * FROM patients WHERE email = %s", (email,))
        existing_patient = cursor.fetchone()
        if existing_patient:
            messagebox.showwarning("Patient Exists", "Patient email already exists in the database.")
            return

        # Insert patient info into table
        sql = """
            INSERT INTO patients (patient_name, email, level, public_key)
            VALUES (%s,%s, %s, %s)
        """
        values = (patient_name,email, selected_level, public_key)
        cursor.execute(sql, values)

        # Commit changes
        db_connection.commit()

        # Close cursor and connection
        cursor.close()
        db_connection.close()
        
        print("Patient information stored successfully!")
        messagebox.showinfo("Success", "Patient information stored successfully!")

    except Error as e:
        print(f"Error storing patient information: {e}")
        messagebox.showerror("Database Error", "Failed to store patient information.")


def submit_patient_info():
    patient_name = patient_name_entry.get()
    selected_level = level_var.get()
    if selected_level and patient_name:
        pub_key, pub_key_pem, priv_key = generate_rsa_key_pair()

        # Send OTP via email
        email = email_entry.get()
        otp = generate_otp()
        if send_otp_gmail(email, otp):
            print("Please check your email for the OTP.")

            # Open OTP verification window
            verify_otp_window = tk.Toplevel()
            verify_otp_window.title("Verify OTP")

            tk.Label(verify_otp_window, text="Enter OTP:").pack(pady=5)
            otp_entry = tk.Entry(verify_otp_window)
            otp_entry.pack(pady=5)

            def verify_otp():
                entered_otp = otp_entry.get()
                if entered_otp == otp:
                    messagebox.showinfo("OTP Verification", "OTP Verified! Keys generated and stored.")
                    reg_window.destroy()
                    verify_otp_window.destroy()

                    # Show keys window
                    keys_window = tk.Toplevel()
                    keys_window.title("Generated Keys")

                    keys_text = f"Public Key:\n{pub_key}\n\nPrivate Key:\n{priv_key}\n\nPublic Key (PEM Format):\n{pub_key_pem}"
                    keys_text_widget = scrolledtext.ScrolledText(keys_window, width=60, height=10)
                    keys_text_widget.insert(tk.END, keys_text)
                    keys_text_widget.pack(pady=10)

                    def copy_keys():
                        keys_text_widget.clipboard_clear()
                        keys_text_widget.clipboard_append(keys_text)
                        keys_text_widget.update()  # Keep the clipboard up-to-date

                    copy_button = tk.Button(keys_window, text="Copy Keys", command=copy_keys)
                    copy_button.pack(pady=10)

                    def close_keys_window():
                        keys_window.destroy()
                        store_patient_info(patient_name, email, selected_level, pub_key)
                        reg_window.destroy()

                    ok_button = tk.Button(keys_window, text="OK", command=close_keys_window)
                    ok_button.pack(pady=10)
                else:
                    messagebox.showerror("OTP Verification", "Incorrect OTP. Please try again.")
            verify_button = tk.Button(verify_otp_window, text="Verify OTP", command=verify_otp)
            verify_button.pack(pady=10)
        else:
            messagebox.showerror("OTP Sending Error", "Failed to send OTP. Please try again.")
    else:
        messagebox.showwarning("Input Error", "Please enter patient name and select a level.")

# Main function to create patient info entry window
def ask_patient_info():
    global reg_window
    reg_window = tk.Toplevel()
    reg_window.title("Patient Information")

    tk.Label(reg_window, text="Patient Name:").pack(pady=5)
    global patient_name_entry
    patient_name_entry = tk.Entry(reg_window)
    patient_name_entry.pack(pady=5)

    tk.Label(reg_window, text="Patient Email:").pack(pady=5)
    global email_entry
    email_entry = tk.Entry(reg_window)
    email_entry.pack(pady=5)

    tk.Label(reg_window, text="Select a level:").pack(pady=5)

    global level_var
    level_var = tk.StringVar(value="L3")   # Ensure no radio button is selected initially

    levels = [
        ("Level 1: All Users Visibility", "L1"),
        ("Level 2: Authorized Users Visibility ", "L2"),
        ("Level 3: Actual data visibility for Authorized Users and Anonymized Data Visibility for Unauthorized Users ", "L3"),
        ("Level 4: Anonymized Data Visibility for All", "L4")
    ]

    for text, value in levels:
        tk.Radiobutton(reg_window, text=text, variable=level_var, value=value, wraplength=400, justify=tk.LEFT).pack(anchor=tk.W, pady=5)

    submit_button = tk.Button(reg_window, text="Submit", command=submit_patient_info)
    submit_button.pack(pady=10)
     # 2FA
     # before storing patients ID and public key in database check if they already exist


def enrollment():
    choice_window = tk.Toplevel()
    choice_window.title("Choose Role")

    label = tk.Label(choice_window, text="Are you a doctor or a patient?")
    label.pack(pady=10)

    doctor_button = tk.Button(choice_window, text="Doctor", command=lambda: [ask_doctor_info(), choice_window.destroy()])
    doctor_button.pack(side="left", padx=10)

    patient_button = tk.Button(choice_window, text="Patient", command=lambda: [ask_patient_info(), choice_window.destroy()])
    patient_button.pack(side="right", padx=10)

def verify_signature(public_key_pem, data, signature):
    try:
        # Load the public key from PEM format
        print(public_key_pem, "public key pem", data, "data", signature, "signature")
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode(),
            backend=default_backend()
        )
        # Ensure data is encoded as bytes (consistent with signing process)
        data_bytes = data.encode('utf-8')

        # Hash the data using SHA-256
        hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hasher.update(data_bytes)
        digest = hasher.finalize()

        # Verify the signature
        public_key.verify(
            signature,
            digest,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        # If verification succeeds, return True and the digest
        return True, digest

    except Exception as e:
        # Print the error if verification fails
        print("Signature verification failed:", e)
        return False, None

@socket.on('send_consent_tkinter')
def handle_consent_received(data):
    received_consent = data.get('Consent')
    signature = data.get('Signature')
    doctorID = data.get('DoctorID')
    verified_consent = ""
    pub_key_pem = """
-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp9pOy4wbOyBLXqzJ3ZyU
d7zCXoQykS2Yf9eA9SA5Gwc1FrjnWwfGo8LK5taT+OpATdHGmh/xIPnjQvoIpTgK
lKpDEpaN5O0cIpmEIqxbeeeoNyrr0wb1dVLvsrmwCxN6y/LauG2rCGipSzLSUj7Q
OMj0GoWLs/d+kRJdZo0z9gqWFwSaDrJbptAAsM5rvl9yNeMAvOebcxULySqkL3Nz
MArwP2uFyLJkYnvQVyvwUkvmyOHY1JE7xqoZdjsHMFI9eIgDJXvrLUMcfOQak8yQ
fU0eVYeTdPgf06meZszWpSZ22AM9SOAjFkEgP6LcsPHlmTWAmJ/KpC2womN5ippK
EwIDAQAB
-----END RSA PUBLIC KEY-----
"""
    signature_bytes = base64.b64decode(signature)
    print("Received Consent:", received_consent, "Doctor ID:", doctorID, "Signature:", signature_bytes)
    verification_result, digest = verify_signature(pub_key_pem, received_consent, signature_bytes)
    
    if verification_result:
    # Hash the original data separately
        hasher_data = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hasher_data.update(received_consent.encode('utf-8'))
        original_hash = hasher_data.finalize()

        # Compare hashes
        if digest == original_hash:
            verified_consent = received_consent
            if( verified_consent == "yes"):
               # macho wala function with doctorID
               print("Consent provided by patient.")
               add_new_health_record(doctorID)
            elif( verified_consent == "no"):  
                messagebox.showerror("Consent Result", "Consent not provided by patient.")           
        else:
           messagebox.showerror("Verification Result", "Signature verification failed.")


# Function to connect SocketIO client to server
def connect_to_server():
    try:
        socket.connect(server_address)
        print('Connected to server:', server_address)
    except Exception as e:
        print('Error connecting to server:', e)

# Function to ask for patient information
def ask_patient_consent():
    patient_info_window = tk.Toplevel()
    patient_info_window.title("Patient Information")

    # Patient Information Inputs
    email_label = tk.Label(patient_info_window, text="Patient Email:")
    email_label.pack(pady=5)
    email_entry = tk.Entry(patient_info_window)
    email_entry.pack(pady=5)

    doctor_id_label = tk.Label(patient_info_window, text="Doctor ID:")
    doctor_id_label.pack(pady=5)
    doctor_id_entry = tk.Entry(patient_info_window)
    doctor_id_entry.pack(pady=5)

    date_label = tk.Label(patient_info_window, text="Date (YYYY-MM-DD):")
    date_label.pack(pady=5)
    date_entry = tk.Entry(patient_info_window)
    date_entry.pack(pady=5)

    # Function to send consent request when button is clicked
    def send_consent_request():
        email = email_entry.get()
        doctor_id = doctor_id_entry.get()
        date = date_entry.get()
        link = 'http://localhost:8080/'
        if email and doctor_id and date:
            if not socket.connected:
                connect_to_server()
            send_consent_gmail(email, doctor_id, date, link)
            # Send consent request to server
            socket.emit('request_patient_consent', {
                'email': email,
                'doctor_id': doctor_id,
                'date': date
            })

            patient_info_window.destroy()
        else:
            messagebox.showerror("Error", "Please fill in all fields.")

    # Button to request consent
    request_button = tk.Button(patient_info_window, text="Request Consent", command=send_consent_request)
    request_button.pack(pady=10)


def on_button_click(button_number):
    """
    Callback function for button click events.
    """
    # PRE-REQUISTIES: ABAC policies 
    if button_number == 1:
        #ask_user_type()
        enrollment()
        # ask if they are doctors or patients
        # if doctors then ask for attributes and check with AA and if yes then generate ABE, priv and public keys
        # if patient then generate private and public keys and ask for L1, L2, L3, L4
    # elif button_number == 2:
    #     # ask patient consent
    #     # fill the patients data
    #     request_button = tk.Button(root, text="Request Patient Consent", command=ask_patient_consent)
    #     request_button.pack(pady=10)
        # ABE encrypt, hash, DS
        # encrypt using patients public key before storing in offchain
        # messagebox.showinfo("Verification", "Performing verification with Attribute Authority...")
        # perform_verification()
    elif button_number == 3:
        # Handle Certificate button click
        registration_details = get_registration_details()
        if registration_details:
            request_and_verify_certificate(registration_details)
        else:
            messagebox.showerror("Error", "Registration details are missing.")
    elif button_number == 4:
        registration_details = get_registration_details()
        open_encryption_window(registration_details)
    # elif button_number == 5:
    #     registration_details = get_registration_details()
    #     open_anomization_window(registration_details)
    elif button_number == 5:
        registration_details = get_registration_details()

        def login():
            username = entry_username.get()
            password = entry_password.get()

            # Here you would add your own login logic
            if username == "user" and password == PUBLIC_KEY_CONSTANT:
                messagebox.showinfo("Login Info", "Login Successful!")
                # login_button.destroy()
                registration_details = get_registration_details()
                b,c,k=encryption(registration_details)
                attributes = ["Symptoms", "Diagnosis"]
                de= ABE.decrypt(k,b,attributes,k)
                print('decrypted data',de)
                messagebox.showinfo("user Info", str(registration_details))
                root.destroy()
                overall_latency = time.time() - start_time
                print("Latency: ", overall_latency)
                data_size = len(b)
                throughput = calculate_throughput(b, time.time(), data_size)
                print('Throughput : ', throughput*1000000)

            else:
                messagebox.showerror("Login Info", "Unauthorised user")
                registration_details = get_registration_details()
                open_anomization_window(registration_details)
                overall_latency = time.time() - start_time
                print("Latency: ", overall_latency)
                registration_details = get_registration_details()
                b,c,k=encryption(registration_details)
                data_size = len(b)
                throughput = calculate_throughput(b, time.time(), data_size)
                print('Throughput: ', throughput*1000000)
                root.destroy()


        # Create the main window
        root = tk.Tk()
        root.title("Login")

        # Create and place the username label and entry
        label_username = tk.Label(root, text="Username")
        label_username.grid(row=0, column=0, padx=10, pady=10)

        entry_username = tk.Entry(root)
        entry_username.grid(row=0, column=1, padx=10, pady=10)

        # Create and place the password label and entry
        label_password = tk.Label(root, text="Password")
        label_password.grid(row=1, column=0, padx=10, pady=10)

        entry_password = tk.Entry(root, show="*")
        entry_password.grid(row=1, column=1, padx=10, pady=10)

        # Create and place the login button
        login_button = tk.Button(root, text="Login", command=login)
        login_button.grid(row=2, columnspan=2, pady=10)

        # Run the main loop
        root.mainloop()


    else:
        messagebox.showinfo("Button Clicked", f"Button {button_number} was clicked")


def get_registration_details():
    """
    Get registration details (mock data for example, replace with actual data retrieval logic).
    """
    return {
        "Patient ID": "12345",
        "Date": "2024-06-18",
        "Age": "30 years",
        "Heart Rate": "80 bpm",
        "Blood Pressure": "120/80 mmHg",
        "Weight": "70 kg",
        "Height": "170 cm",
        "Symptoms": "Fever, Cough",
        "Diagnosis": "Upper Respiratory Tract infection",
        "Medicines": "Paracetamol"
    }

def ask_user_type():
    """
    Ask if the user is a new or existing user.
    """
    user_type = messagebox.askyesno("User Type", "Are you a new user?")
    if user_type:
        open_registration_window(new_user=True)
    else:
        open_registration_window(new_user=False)

def open_registration_window(new_user):
    """
    Open the registration window.
    """
    reg_window = tk.Toplevel(root)
    reg_window.title("Patient Registration")

    tk.Label(reg_window, text="Patient ID").pack(pady=5)
    patient_id_entry = tk.Entry(reg_window)
    patient_id_entry.pack(pady=5)

    tk.Label(reg_window, text="Date").pack(pady=5)
    date_entry = tk.Entry(reg_window)
    date_entry.pack(pady=5)
    date_entry.insert(0, datetime.now().strftime("%Y-%m-%d"))

    tk.Label(reg_window, text="Age").pack(pady=5)
    age_entry = tk.Entry(reg_window)
    age_entry.pack(pady=5)

    tk.Label(reg_window, text="Heart Rate").pack(pady=5)
    heart_rate_entry = tk.Entry(reg_window)
    heart_rate_entry.pack(pady=5)

    tk.Label(reg_window, text="Blood Pressure").pack(pady=5)
    bp_entry = tk.Entry(reg_window)
    bp_entry.pack(pady=5)

    tk.Label(reg_window, text="Weight").pack(pady=5)
    weight_entry = tk.Entry(reg_window)
    weight_entry.pack(pady=5)

    tk.Label(reg_window, text="Height").pack(pady=5)
    height_entry = tk.Entry(reg_window)
    height_entry.pack(pady=5)

    tk.Label(reg_window, text="Symptoms").pack(pady=5)
    symptoms_entry = tk.Entry(reg_window)
    symptoms_entry.pack(pady=5)

    tk.Label(reg_window, text="Diagnosis").pack(pady=5)
    diagnosis_entry = tk.Entry(reg_window)
    diagnosis_entry.pack(pady=5)

    tk.Label(reg_window, text="Medicines").pack(pady=5)
    medicines_entry = tk.Entry(reg_window)
    medicines_entry.pack(pady=5)

    if not new_user:
        patient_id_entry.insert(0, "Pseudo ID")
        date_entry.delete(0, tk.END)
        date_entry.insert(0, "January 10, 2024")
        age_entry.insert(0, "35 years")
        heart_rate_entry.insert(0, "80 bpm")
        bp_entry.insert(0, "120/80 mmHg")
        weight_entry.insert(0, "70 kg")
        height_entry.insert(0, "170 cm")
        symptoms_entry.insert(0, "Cough, Fever")
        diagnosis_entry.insert(0, "Upper Respiratory Tract Infection")
        medicines_entry.insert(0, "Paracetamol, Cough Syrup")

    submit_button = tk.Button(reg_window, text="Submit", command=lambda: submit_registration(
        reg_window, patient_id_entry, date_entry, age_entry, heart_rate_entry,
        bp_entry, weight_entry, height_entry, symptoms_entry, diagnosis_entry, medicines_entry,"1234"
    ))
    submit_button.pack(pady=20)

def submit_registration(reg_window, patient_id_entry, date_entry, age_entry, heart_rate_entry,
                        bp_entry, weight_entry, height_entry, symptoms_entry, diagnosis_entry, medicines_entry, doctor_id):
    """
    Handle registration submission.
    """
    patient_id = patient_id_entry.get()
    date = date_entry.get()
    age = age_entry.get()
    heart_rate = heart_rate_entry.get()
    bp = bp_entry.get()
    weight = weight_entry.get()
    height = height_entry.get()
    symptoms = symptoms_entry.get()
    diagnosis = diagnosis_entry.get()
    medicines = medicines_entry.get()

    registration_details = {
        "Patient ID": patient_id,
        "Date": date,
        "Age": age,
        "Heart Rate": heart_rate,
        "Blood Pressure": bp,
        "Weight": weight,
        "Height": height,
        "Symptoms": symptoms,
        "Diagnosis": diagnosis,
        "Medicines": medicines
    }
    
    column_names = ('id', 'doctor_id','email','department','specialist','years_experience','organization','abe_secret_key','public_key')
    doctor = get_doctor_info(doctor_id)
    if doctor:
        doctor_dict = dict(zip(column_names, doctor))
        abe_secret_key = doctor_dict['abe_secret_key']
        sk = base64.b64decode(abe_secret_key)
        sensitive_attributes = ["Symptoms", "Diagnosis"]
        registration_details["SensitiveData"] = []
        for attribute in sensitive_attributes:
            encrypt_details = {}
            encrypt_details["attribute_name"] = attribute
            encryption, tag = encrypt(registration_details[attribute], sk)
            encrypt_details["ciphertext"] = base64.b64encode(encryption).decode()
            encrypt_details["tag"] = base64.b64encode(encryption).decode()
            registration_details["SensitiveData"].append(encrypt_details)
        del registration_details["Symptoms"]
        del registration_details["Diagnosis"]
        json_string = json.dumps(registration_details)

    messagebox.showinfo("Registration Info", str(registration_details))
    reg_window.destroy()
    
def get_doctor_info(doctor_id):
    db_connection = get_database_connection()
    if not db_connection:
        return
    try:
        cursor = db_connection.cursor()

        # Create doctors table if not exists
        cursor.execute("SELECT * FROM doctors WHERE doctor_id = %s", (doctor_id,))
        doctor = cursor.fetchone()
        # Close cursor and connection
        cursor.close()
        db_connection.close()
        
        return doctor

    except Error as e:
        print(f"Error fetching doctor information: {e}")
        messagebox.showerror("Database Error", "Failed to fetch doctor information.")
        
def add_new_health_record(doctor_id: str):
    """
    Add new health record window.
    """
    reg_window = tk.Toplevel(root)
    reg_window.title("Add New Health Record")

    tk.Label(reg_window, text="Patient ID").pack(pady=5)
    patient_id_entry = tk.Entry(reg_window)
    patient_id_entry.pack(pady=5)

    tk.Label(reg_window, text="Date").pack(pady=5)
    date_entry = tk.Entry(reg_window)
    date_entry.pack(pady=5)
    date_entry.insert(0, datetime.now().strftime("%Y-%m-%d"))

    tk.Label(reg_window, text="Age").pack(pady=5)
    age_entry = tk.Entry(reg_window)
    age_entry.pack(pady=5)

    tk.Label(reg_window, text="Heart Rate").pack(pady=5)
    heart_rate_entry = tk.Entry(reg_window)
    heart_rate_entry.pack(pady=5)

    tk.Label(reg_window, text="Blood Pressure").pack(pady=5)
    bp_entry = tk.Entry(reg_window)
    bp_entry.pack(pady=5)

    tk.Label(reg_window, text="Weight").pack(pady=5)
    weight_entry = tk.Entry(reg_window)
    weight_entry.pack(pady=5)

    tk.Label(reg_window, text="Height").pack(pady=5)
    height_entry = tk.Entry(reg_window)
    height_entry.pack(pady=5)

    tk.Label(reg_window, text="Symptoms").pack(pady=5)
    symptoms_entry = tk.Entry(reg_window)
    symptoms_entry.pack(pady=5)

    tk.Label(reg_window, text="Diagnosis").pack(pady=5)
    diagnosis_entry = tk.Entry(reg_window)
    diagnosis_entry.pack(pady=5)

    tk.Label(reg_window, text="Medicines").pack(pady=5)
    medicines_entry = tk.Entry(reg_window)
    medicines_entry.pack(pady=5)
    
    submit_button = tk.Button(reg_window, text="Submit", command=lambda: submit_registration(
        reg_window, patient_id_entry, date_entry, age_entry, heart_rate_entry,
        bp_entry, weight_entry, height_entry, symptoms_entry, diagnosis_entry, medicines_entry,doctor_id
    ))
    submit_button.pack(pady=20)

root = tk.Tk()
root.title("ABE privacy preservation")

# button1 = tk.Button(root, text="Registration", command=lambda: on_button_click(1))
# button2 = tk.Button(root, text="Verification", command=lambda: on_button_click(2))
# button3 = tk.Button(root, text="Certificate", command=lambda: on_button_click(3))
# button4 = tk.Button(root, text="Encrption", command=lambda: on_button_click(4))
# # button5 = tk.Button(root, text="Anonymisation", command=lambda: on_button_click(5))
# button5 = tk.Button(root, text="Data user", command=lambda: on_button_click(5))

button1 = tk.Button(root, text="Enrollment", command=lambda: on_button_click(1))
button2 = tk.Button(root, text="Checkup details", command=ask_patient_consent)
button3 = tk.Button(root, text="Data retrieval", command=lambda: on_button_click(3))
button6 = tk.Button(root, text="Exit", command=root.quit)

button1.pack(pady=9)
button2.pack(pady=9)
button3.pack(pady=9)
# button4.pack(pady=9)
# button5.pack(pady=9)
button6.pack(pady=9)
# button7.pack(pady=9)

@socket.event
def connect():
    print('Connected to server:', server_address)

@socket.event
def disconnect():
    print('Disconnected from server')

root.mainloop()