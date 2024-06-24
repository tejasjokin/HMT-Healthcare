
from flask import Flask, render_template
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import time

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

# Enable CORS for all origins
CORS(app, resources={r"/*": {"origins": "*"}})

socketio = SocketIO(app, cors_allowed_origins="*")

@socketio.on('request_patient_consent')
def handle_consent_request(data):
    email = data.get('email')
    doctor_id = data.get('doctor_id')
    date = data.get('date')
    
    print(f"Received patient details - Email: {email}, Doctor ID: {doctor_id}, Date: {date}")

    # Example logic: process the consent request and send a response
    if email and doctor_id and date:
        print("requesting consent")
            # Emit patient details to Vue.js frontend
        time.sleep(1)
        socketio.emit('patient_details', {
            'email': email,
            'doctor_id': doctor_id,
            'date': date
        })
        print("Patient details emitted to frontend")
    else:
        emit('consent_received', {'message': 'Invalid request'})

Consent = None

@socketio.on('send consent')
def handle_consent(data):
    global Consent
    email = data.get('email')
    Consent = data.get('Consent')
    Signature = data.get('Signature')
    DoctorID = data.get('DoctorID')
    # Process encrypted consent here (example: print it)
    print(f"Consent received: {Consent}, Signature: {Signature}, DoctorID: {DoctorID}")
    # Example: emit an acknowledgment
    emit('consent received', {'message': 'Consent received on server'})
    socketio.emit('send_consent_tkinter', {
            'email': email,
            'Consent': Consent,
            'Signature': Signature,
            'DoctorID': DoctorID 
        })
    print("Consent emitted to tkinter", email, Consent, Signature, DoctorID)


@socketio.on('request_patient_key')
def handle_key_request(data):
    key = data.get('key')
    if key:
        print("requesting key")
            # Emit patient details to Vue.js frontend
        time.sleep(1)
        socketio.emit('key_details', {
            'key': key
        })
        print("Key request emitted to frontend")
    else:
        emit('key_received', {'message': 'Invalid request'})

@socketio.on('submit_key')
def handle_key(data):
    key = data.get('key')
    # Process encrypted consent here (example: print it)
    print(f"Key received: {key}")
    # Example: emit an acknowledgment
    emit('key received', {'message': 'Key received on server'})
    socketio.emit('send_key_tkinter', {
            'key': key
        })
    print("Key emitted to tkinter", key)

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    socketio.run(app, debug=True)
