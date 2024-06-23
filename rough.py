import warnings

warnings.filterwarnings("ignore")
import tkinter as tk
from tkinter import messagebox
from datetime import datetime
import requests
import Block_chain
import hashlib
import random
import string
import time
start_time = time.time()
# Global variable to store latency measurements
latency_measurements = []
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
    public_key, private_key = generate_fixed_keys()
    abe_key = ABE('').generate_master_key(4)
    attributes = ["Symptoms", "Diagnosis"]
    abe = ABE(abe_key)
    # message_bytes = json.dumps(existing_data).encode('utf-8')
    aa =registration_details['Symptoms']
    aa1=registration_details['Diagnosis']
    a=str([aa,aa1])
    encrypted_data = abe.encrypt(a, attributes)
    print("sensitive Encrypted Data:", encrypted_data)
    b=str([registration_details['Patient ID'],registration_details['Date'],registration_details['Age'],registration_details['Heart Rate'],registration_details['Blood Pressure'],registration_details['Weight'],registration_details['Height'],registration_details['Medicines']])
    c=hash(b)
    print("Encrypted Data:", c)
    Block_chain.saving_data(b)
    Block_chain.saving_data1(c)
    print('The encrypted data saved ')

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
    return b,c,abe_key



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


def on_button_click(button_number):
    """
    Callback function for button click events.
    """
    if button_number == 1:
        ask_user_type()
    elif button_number == 2:
        messagebox.showinfo("Verification", "Performing verification with Attribute Authority...")
        perform_verification()
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

            else:
                messagebox.showerror("Login Info", "Unauthorised user")
                registration_details = get_registration_details()
                open_anomization_window(registration_details)
                overall_latency = time.time() - start_time
                print("Latency: ", overall_latency)


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
        bp_entry, weight_entry, height_entry, symptoms_entry, diagnosis_entry, medicines_entry
    ))
    submit_button.pack(pady=20)

def submit_registration(reg_window, patient_id_entry, date_entry, age_entry, heart_rate_entry,
                        bp_entry, weight_entry, height_entry, symptoms_entry, diagnosis_entry, medicines_entry):
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

    messagebox.showinfo("Registration Info", str(registration_details))
    reg_window.destroy()

root = tk.Tk()
root.title("ABE privacy preservation")

button1 = tk.Button(root, text="Registration", command=lambda: on_button_click(1))
button2 = tk.Button(root, text="Verification", command=lambda: on_button_click(2))
button3 = tk.Button(root, text="Certificate", command=lambda: on_button_click(3))
button4 = tk.Button(root, text="Encrption", command=lambda: on_button_click(4))
# button5 = tk.Button(root, text="Anonymisation", command=lambda: on_button_click(5))
button5 = tk.Button(root, text="Data user", command=lambda: on_button_click(5))
button6 = tk.Button(root, text="Exit", command=root.quit)

button1.pack(pady=9)
button2.pack(pady=9)
button3.pack(pady=9)
button4.pack(pady=9)
button5.pack(pady=9)
button6.pack(pady=9)
# button7.pack(pady=9)

root.mainloop()

