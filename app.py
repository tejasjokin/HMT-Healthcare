
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
            'patient_email': email,
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
    Consent = data.get('Consent')
    Signature = data.get('Signature')
    DoctorID = data.get('DoctorID')
    # Process encrypted consent here (example: print it)
    print(f"Consent received: {Consent}, Signature: {Signature}, DoctorID: {DoctorID}")
    # Example: emit an acknowledgment
    emit('consent received', {'message': 'Consent received on server'})
    socketio.emit('send_consent_tkinter', {
            'Consent': Consent,
            'Signature': Signature,
            'DoctorID': DoctorID 
        })
    print("Consent emitted to tkinter", Consent, Signature, DoctorID)


@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    socketio.run(app, debug=True)
