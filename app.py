# app_server.py (Final Update)
from flask import Flask, render_template, request, jsonify, redirect, url_for, send_from_directory
from flask_socketio import SocketIO, emit, join_room, leave_room
import random
import os
import base64 # For file chunks

# RSA-like key encryption using number theory
RSA_PUBLIC_E = 17
RSA_MODULUS_N = 3233  # Product of two primes (like 61 * 53); in real use, much bigger

def encrypt_key(key):
    return pow(key, RSA_PUBLIC_E, RSA_MODULUS_N)


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_super_secret_key_change_this_for_production' # Change this!
socketio = SocketIO(app, cors_allowed_origins="*") # Be careful with cors_allowed_origins in production

# --- Server Configuration ---
SERVER_PASSWORD = "abc123" # Fixed server password
FILE_UPLOAD_FOLDER = 'uploads' # Directory to temporarily store uploaded files
if not os.path.exists(FILE_UPLOAD_FOLDER):
    os.makedirs(FILE_UPLOAD_FOLDER)

# --- Global Data Structures ---
authenticated_clients = {} # client_id (username): {'sid': socket_id, 'username': username, 'primary_key': pk, 'secondary_key': sk}
unauthenticated_sids = {} # {sid: True}

# --- Global Polynomial and Keys (Generated ONCE on server startup) ---
GLOBAL_PRIMARY_KEY = None
GLOBAL_SECONDARY_KEYS = []
GLOBAL_POLYNOMIAL_EQUATION_STR = ""

def greedy_select_roots(n=5, limit=50):
    roots = []
    current = 2
    while len(roots) < n and current < limit:
        if all(current % r != 0 and r % current != 0 for r in roots):  # Ensure diversity (no multiples)
            roots.append(current)
        current += 1
    return roots

def generate_polynomial_and_keys_on_startup():
    global GLOBAL_PRIMARY_KEY, GLOBAL_SECONDARY_KEYS, GLOBAL_POLYNOMIAL_EQUATION_STR

    roots = greedy_select_roots(5)

    #roots = random.sample(range(1, 11), 5) # Ensuring distinct roots
    
    GLOBAL_PRIMARY_KEY = roots[0]
    GLOBAL_SECONDARY_KEYS = roots[1:]
    
    coeffs = [1]
    for root in roots:
        new_coeffs = [0] * (len(coeffs) + 1)
        for i in range(len(coeffs)):
            new_coeffs[i+1] -= coeffs[i] * root
            new_coeffs[i] += coeffs[i]
        coeffs = new_coeffs
    
    poly_terms = []
    for i, coeff in enumerate(coeffs):
        power = 5 - i
        
        if coeff == 0:
            continue
        
        term_str = ""
        if abs(coeff) != 1 or power == 0:
            term_str += str(coeff)
        elif coeff == -1:
            term_str += "-"
        
        if power > 1:
            term_str += f"x^{power}"
        elif power == 1:
            term_str += "x"
        
        if i > 0 and coeff > 0:
            poly_terms.append(f"+{term_str}")
        else:
            poly_terms.append(term_str)
            
    GLOBAL_POLYNOMIAL_EQUATION_STR = "".join(poly_terms)

    print(f"Server Startup - Generated Polynomial: {GLOBAL_POLYNOMIAL_EQUATION_STR} = 0")
    print(f"Server Startup - Primary Key: {GLOBAL_PRIMARY_KEY}")
    print(f"Server Startup - Secondary Keys: {GLOBAL_SECONDARY_KEYS}")


# Generate on server startup
generate_polynomial_and_keys_on_startup()


# --- Routes ---
@app.route('/')
def index():
    return render_template('server_dashboard.html',
                           polynomial_equation=GLOBAL_POLYNOMIAL_EQUATION_STR,
                           primary_key=GLOBAL_PRIMARY_KEY,
                           secondary_keys=GLOBAL_SECONDARY_KEYS)

@app.route('/client.html')
def client_page():
    return render_template('client.html')

@app.route('/request_keys', methods=['POST'])
def request_keys_route():
    password = request.form.get('password')
    if password == SERVER_PASSWORD:
        assigned_secondary_key = random.choice(GLOBAL_SECONDARY_KEYS)
        return jsonify({
            'success': True,
            'primary_key': GLOBAL_PRIMARY_KEY,
            'secondary_key': assigned_secondary_key
        })
    return jsonify({'success': False, 'message': 'Incorrect server password'}), 401


# --- SocketIO Events ---
@socketio.on('connect')
def handle_connect():
    unauthenticated_sids[request.sid] = True
    print(f"Client connected (SID: {request.sid})")
    # Determine if this is a client page or the server dashboard itself
    # This is a crude way; better to have separate namespaces for different types of connections
    # For now, assume if it's the dashboard, it won't send authentication_client event
    if request.url_rule and request.url_rule.endpoint == 'index': # This checks if connecting from server dashboard
        # This is the server dashboard, we don't send welcome message or add to unauthenticated_sids.
        # Just update it with current client list
        emit('update_server_dashboard_client_list', list(authenticated_clients.keys()), room=request.sid)
        print("Server dashboard connected.")
    else:
        emit('server_message', {'message': f'Welcome. Please enter server password to request keys, then authenticate.'}, room=request.sid)


@socketio.on('disconnect')
def handle_disconnect():
    disconnected_client_id = None
    for client_id, data in authenticated_clients.items():
        if data['sid'] == request.sid:
            disconnected_client_id = client_id
            break

    if disconnected_client_id:
        print(f"Authenticated client disconnected: {disconnected_client_id}")
        del authenticated_clients[disconnected_client_id]
        emit('server_message', {'message': f'User {disconnected_client_id} has left the network.'}, broadcast=True, include_self=False)
        socketio.emit('update_client_list', list(authenticated_clients.keys())) # Update client list for clients
        socketio.emit('update_server_dashboard_client_list', list(authenticated_clients.keys())) # Update for server dashboard
    elif request.sid in unauthenticated_sids:
        print(f"Unauthenticated client disconnected (SID: {request.sid})")
        del unauthenticated_sids[request.sid]
    else:
        print(f"Unknown client disconnected (SID: {request.sid})")


@socketio.on('authenticate_client')
def authenticate_client(data):
    if request.sid not in unauthenticated_sids:
        emit('authentication_result', {'success': False, 'message': 'Session invalid or already authenticated.'})
        return

    primary_key_client = int(data.get('primary_key'))
    secondary_key_client = int(data.get('secondary_key'))
    username = data.get('username')

    if not username:
        emit('authentication_result', {'success': False, 'message': 'Username cannot be empty.'}, room=request.sid)
        return

    if username in authenticated_clients:
        emit('authentication_result', {'success': False, 'message': 'Username already taken. Please choose another.'}, room=request.sid)
        return
        
    if primary_key_client == GLOBAL_PRIMARY_KEY and secondary_key_client in GLOBAL_SECONDARY_KEYS:
        assigned_client_id = username 

        authenticated_clients[assigned_client_id] = {
            'sid': request.sid,
            'username': username,
            'primary_key': primary_key_client,
            'secondary_key': secondary_key_client
        }
        
        del unauthenticated_sids[request.sid]

        join_room(assigned_client_id)
        emit('authentication_result', {
            'success': True,
            'message': f'Authenticated as {username}! Your ID is {assigned_client_id}.',
            'client_id': assigned_client_id
        }, room=request.sid)
        
        emit('server_message', {'message': f'User {username} has joined the network.'}, broadcast=True, include_self=False)
        socketio.emit('update_client_list', list(authenticated_clients.keys())) # Update client list for clients
        socketio.emit('update_server_dashboard_client_list', list(authenticated_clients.keys())) # Update for server dashboard
        print(f"Client {username} ({assigned_client_id}) authenticated successfully.")

    else:
        emit('authentication_result', {'success': False, 'message': 'Invalid primary or secondary key.'}, room=request.sid)
        print(f"Authentication failed for SID: {request.sid} (PK: {primary_key_client}, SK: {secondary_key_client})")


@socketio.on('request_client_list')
def request_client_list():
    emit('update_client_list', list(authenticated_clients.keys()), room=request.sid)

@socketio.on('request_file_transfer')
def request_file_transfer(data):
    sender_id = None
    for cid, client_data in authenticated_clients.items():
        if client_data['sid'] == request.sid:
            sender_id = cid
            break

    if not sender_id:
        emit('server_message', {'message': 'Error: Sender not authenticated or identified.'}, room=request.sid)
        return

    receiver_id = data.get('receiver_id')
    
    if receiver_id not in authenticated_clients:
        emit('server_message', {'message': f'Client {receiver_id} not found or not authenticated.'}, room=request.sid)
        return

    sender_pk = authenticated_clients[sender_id].get('primary_key')
    if not sender_pk:
        emit('server_message', {'message': 'Error: Sender\'s keys not found on server (internal error).'}, room=request.sid)
        return
        
    emit('file_transfer_request', {
        'sender_id': sender_id,
        'sender_username': authenticated_clients[sender_id]['username'],
        'sender_primary_key': sender_pk
    }, room=authenticated_clients[receiver_id]['sid'])
    
    emit('server_message', {'message': f'Request sent to {receiver_id}. Waiting for acceptance...'}, room=request.sid)


@socketio.on('accept_file_transfer')
def accept_file_transfer(data):
    receiver_id = None
    for cid, client_data in authenticated_clients.items():
        if client_data['sid'] == request.sid:
            receiver_id = cid
            break

    if not receiver_id:
        emit('server_message', {'message': 'Error: Receiver not authenticated or identified.'}, room=request.sid)
        return

    sender_id = data.get('sender_id')
    sender_pk_from_client = data.get('sender_primary_key')

    if sender_id not in authenticated_clients:
        emit('server_message', {'message': f'Sender {sender_id} not found or not authenticated.'}, room=request.sid)
        return

    actual_sender_pk = authenticated_clients[sender_id].get('primary_key')

    if actual_sender_pk != sender_pk_from_client:
        emit('server_message', {'message': 'Error: Primary key mismatch during acceptance. Aborting transfer.'}, room=request.sid)
        emit('server_message', {'message': 'Error: Primary key mismatch during acceptance. Aborting transfer.'}, room=authenticated_clients[sender_id]['sid'])
        return
        
    emit('transfer_ready', {'receiver_id': receiver_id, 'sender_id': sender_id}, room=authenticated_clients[sender_id]['sid'])
    emit('transfer_ready', {'receiver_id': receiver_id, 'sender_id': sender_id}, room=authenticated_clients[receiver_id]['sid'])
    
    emit('server_message', {'message': f'File transfer path established between {sender_id} and {receiver_id}.'}, broadcast=True)

@socketio.on('file_upload_chunk')
def handle_file_upload_chunk(data):
    sender_id = None
    for cid, client_data in authenticated_clients.items():
        if client_data['sid'] == request.sid:
            sender_id = cid
            break

    if not sender_id:
        emit('server_message', {'message': 'Error: Sender not authenticated for file chunk.'}, room=request.sid)
        return

    receiver_id = data.get('receiver_id')
    filename = data.get('filename')
    chunk_base64 = data.get('chunk')
    offset = data.get('offset')
    total_chunks = data.get('total_chunks')

    if receiver_id not in authenticated_clients:
        emit('server_message', {'message': f'Receiver {receiver_id} not found or not authenticated for file transfer.'}, room=request.sid)
        return

    emit('file_download_chunk', {
        'sender_id': sender_id,
        'filename': filename,
        'chunk': chunk_base64,
        'offset': offset,
        'total_chunks': total_chunks
    }, room=authenticated_clients[receiver_id]['sid'])

    if offset + 1 == total_chunks:
        emit('server_message', {'message': f'File {filename} transfer initiated from {sender_id} to {receiver_id} through server.'}, room=sender_id)
        emit('server_message', {'message': f'File {filename} transfer complete from {sender_id} to {receiver_id} through server.'}, room=receiver_id)


if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)