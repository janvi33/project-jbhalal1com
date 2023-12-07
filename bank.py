import socket
import threading
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding

def decrypt_with_private_key_and_aes(private_key, encrypted_symmetric_key, encrypted_message):
    symmetric_key = private_key.decrypt(
        encrypted_symmetric_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    aesCipher = Cipher(algorithms.AES(symmetric_key), modes.ECB())
    decryptor = aesCipher.decryptor()
    decrypted_padded_message = decryptor.update(encrypted_message) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()

    
    return decrypted_message

def load_private_key(filename):
    with open(filename, "rb") as key_file:
        return serialization.load_pem_private_key(key_file.read(), password=None)

def load_public_key(filename):
    with open(filename, "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())


def validate_credentials(user_id, password, filename):
    try:
        with open(filename, 'r') as file:
            for line in file:
                stored_id, stored_password = line.strip().split(' ')
                if user_id == stored_id and password == stored_password:
                    return True
        return False
    except Exception as e:
        print(f"Error in validate_credentials: {e}")
        return False


def update_balances(balance_file, sender_id, recipient_id, amount, account_type):
    
    with open(balance_file, 'r') as file:
        lines = file.readlines()

    balances = {}
    for line in lines:
        user_id, savings, checking = line.strip().split(' ')
        balances[user_id] = {'savings': float(savings), 'checking': float(checking)}

   
    if recipient_id not in balances or sender_id not in balances:
        return "The recipient's ID does not exist"

    if account_type == '1': 
        account_key = 'savings'
    elif account_type == '2': 
        account_key = 'checking'
    else:
        return "Invalid account type"

    if balances[sender_id][account_key] < amount:
        return "Your account does not have enough funds"

    balances[sender_id][account_key] -= amount
    balances[recipient_id][account_key] += amount
    with open(balance_file, 'w') as file:
        for user_id, balance in balances.items():
            file.write(f"{user_id} {balance['savings']} {balance['checking']}\n")

    return "Your transaction is successful"

def fetch_account_balances(balance_file, user_id):
    try:
        with open(balance_file, 'r') as file:
            for line in file:
                parts = line.strip().split(' ')
                if parts[0] == user_id:
                    savings_balance = parts[1]
                    checking_balance = parts[2]
                    return f"Your savings account balance: {savings_balance}\nYour checking account balance: {checking_balance}"
        return "User account not found."
    except Exception as e:
        return f"Error reading balance file: {e}"



def handle_client_connection(client_socket, private_key, credentials_file, balance_file):
    try:
        encrypted_symmetric_key = client_socket.recv(256)
        authenticated = False
        user_id = None

        while True:
            if authenticated:
                
                request = client_socket.recv(1024).decode()
                if not request:
                    print("No more data from client. Closing connection.")
                    break

                if request.startswith("Transfer"):
                    _, account_choice, recipient_id, amount = request.split()
                    response_message = update_balances(balance_file, user_id, recipient_id, float(amount), account_choice)
                elif request == "2":
                    response_message = fetch_account_balances(balance_file, user_id)
                else:
                    response_message = "Invalid request format"
            else:
                encrypted_credentials = client_socket.recv(1024)
                decrypted_credentials = decrypt_with_private_key_and_aes(private_key, encrypted_symmetric_key, encrypted_credentials).decode().rstrip("\0")
                if 'ID: ' in decrypted_credentials and ' Password: ' in decrypted_credentials:
                    user_id, password = decrypted_credentials.split('ID: ')[1].split(' Password: ')
                    is_valid = validate_credentials(user_id, password, credentials_file)
                    response_message = "ID and password are correct" if is_valid else "ID or password is incorrect"
                    authenticated = is_valid
                else:
                    response_message = "Invalid login format"

            client_socket.sendall(response_message.encode())
            print(f"Sent response: {response_message}")

    except Exception as e:
        print(f"An error occurred while handling client request: {e}")
    finally:
        client_socket.close()



def start_bank_server(port, private_key_path, public_key_path, credentials_file, balance_file):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('', port))
    server_socket.listen(5)
    print(f"Bank server is listening on :{port}")

    private_key = load_private_key(private_key_path)
    public_key = load_public_key(public_key_path)

    try:
        while True:
            client_sock, address = server_socket.accept()
            print(f"Accepted connection from {address}")
            client_sock.sendall(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

            client_handler = threading.Thread(
                target=handle_client_connection,
                args=(client_sock, private_key, credentials_file, balance_file)
            )
            client_handler.start()
    finally:
        server_socket.close()

private_key_path = 'private_key.pem'
public_key_path = 'public_key.pem'
credentials_file = 'password'
balance_file = 'balance'

if len(sys.argv) < 2:
    print('Usage: python server.py <port number>')
    sys.exit(1)

port = int(sys.argv[1])
if not (1024 <= port <= 65535):
    print("The port number should be a user-defined number between 1024 and 65535")
    sys.exit(1)

start_bank_server(port, private_key_path, public_key_path, credentials_file, balance_file)






