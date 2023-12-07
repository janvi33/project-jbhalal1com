# import socket
# from cryptography.hazmat.primitives import serialization
# from cryptography.hazmat.primitives.asymmetric import padding
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# import getpass
# import sys
# import secrets

# SYMMETRIC_KEY = secrets.token_bytes(32)  # Use a 256-bit key for AES

# def load_public_key(filename):
#     return serialization.load_pem_public_key(open(filename, "rb").read(), backend=default_backend())

# def encrypt_txt(message, key):
#     cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend()).encryptor()
#     padded_message = message + b'\0' * (16 - len(message) % 16)
#     return cipher.update(padded_message) + cipher.finalize()

# def encrypt_with_public_key(public_key, data):
#     ciphertext = public_key.encrypt(
#         data,
#         padding.OAEP(
#             mgf=padding.MGF1(algorithm=hashes.SHA256()),
#             algorithm=hashes.SHA256(),
#             label=None
#         )
#     )
#     return ciphertext

# def send_encrypted_credentials(client_socket, public_key, user_id, password):
#     encrypted_key = encrypt_with_public_key(public_key, SYMMETRIC_KEY)
#     client_socket.sendall(encrypted_key)

#     cipher = Cipher(algorithms.AES(SYMMETRIC_KEY), modes.ECB(), backend=default_backend()).encryptor()
#     encrypted_credentials = encrypt_txt(f"ID: {user_id} Password: {password}".encode(), SYMMETRIC_KEY)
#     client_socket.sendall(encrypted_credentials)

#     response = client_socket.recv(1024).decode()
#     return response

# def send_request(client_socket, public_key, request):
#     cipher = Cipher(algorithms.AES(SYMMETRIC_KEY), modes.ECB(), backend=default_backend()).encryptor()
#     encrypted_request = encrypt_txt(request.encode(), SYMMETRIC_KEY)
#     client_socket.sendall(encrypted_request)

#     response = client_socket.recv(1024).decode()
#     return response

# def main_menu():
#     print("Please select one of the following actions (enter 1, 2, or 3):")
#     print("1. Transfer money")
#     print("2. Check account balance")
#     print("3. Exit")

# def transfer_money(client_socket, public_key, user_id):
#     while True:
#         print("Please select an account (enter 1 or 2):")
#         print("1. Savings")
#         print("2. Checking")
#         account_choice = input("Select account: ")
#         if account_choice not in ["1", "2"]:
#             print("Incorrect input. Please select either the savings or checking account.")
#             continue
#         recipient_id = input("Enter the recipient's ID: ")
#         if recipient_id == user_id:
#             print("Recipient ID cannot be the same as your ID. Please try again.")
#             continue
#         amount = input("Enter the amount to be transferred: ")
#         try:
#             amount = float(amount)
#         except ValueError:
#             print("Invalid amount. Please enter a numeric value.")
#             continue
#         transfer_request = f"Transfer {account_choice} {recipient_id} {amount}"
#         response = send_request(client_socket, public_key, transfer_request)
#         print(f"Server response: {response}")
#         break

# def generateKeys():
#     public_key = serialization.load_pem_public_key(open("public_key.pem", "rb").read(), backend=default_backend())
#     return public_key

# def connect_to_bank_server(host, port, public_key_path):
#     public_key = generateKeys()

#     with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
#         client_socket.connect((host, port))
#         print(f"Connected to bank server at {host}:{port}")

#         while True:  
#             user_id = input("Enter your ID: ")
#             password = getpass.getpass("Enter your password: ")
#             response = send_encrypted_credentials(client_socket, public_key, user_id, password)

#             if response == "ID and password are correct":
#                 while True:
#                     main_menu()
#                     choice = input("Your choice: ")

#                     if choice == "1":
#                         transfer_money(client_socket, public_key, user_id)
#                     elif choice == "2":
#                         balance_info = send_request(client_socket, public_key, "2")
#                         print(balance_info)
#                     elif choice == "3":
#                         print("Exiting.")
#                         break
#                     else:
#                         print("Invalid choice. Please try again.")
#                 break 
#             else:
#                 print("ID or password is incorrect. Please try again.")
#                 retry = input("Do you want to try again? (yes/no): ")
#                 if retry.lower() != 'yes':
#                     print("Exiting.")
#                     break

# public_key_path = 'public_key.pem'
# if len(sys.argv) < 3:
#     print("Usage: python client.py <host> <port number>")
# else:
#     host = sys.argv[1]
#     port = int(sys.argv[2])
#     if host == "localhost" or not host:
#         print("The host name should not be localhost or empty")
#         sys.exit(1)

#     if not (1024 <= port <= 65535):
#         print("The port number should be a user-defined number between 1024 and 65535")
#         sys.exit(1)

#     connect_to_bank_server(host, port, public_key_path)



import socket
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import getpass
from cryptography.hazmat.primitives import padding as sym_padding  # New import for symmetric padding



def load_public_key(filename):
    with open(filename, "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())

def encrypt_with_aes_and_public_key(public_key, message):
    symmetric_key = os.urandom(32)  # 256-bit key

    padder = sym_padding.PKCS7(128).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()

    # Encrypt the message with AES
    aesCipher = Cipher(algorithms.AES(symmetric_key), modes.ECB())
    encryptor = aesCipher.encryptor()
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()

    # Encrypt the symmetric key with the public key
    encrypted_symmetric_key = public_key.encrypt(
        symmetric_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    return encrypted_symmetric_key, encrypted_message


def send_encrypted_credentials(client_socket, public_key, user_id, password):
    credentials = f"ID: {user_id} Password: {password}"
    encrypted_symmetric_key, encrypted_credentials = encrypt_with_aes_and_public_key(public_key, credentials)
    client_socket.sendall(encrypted_symmetric_key)
    client_socket.sendall(encrypted_credentials)
    response = client_socket.recv(1024).decode()
    return response

def send_request(client_socket, request):
    client_socket.sendall(request.encode())
    response = client_socket.recv(1024).decode()
    return response

def main_menu():
    print("Please select one of the following actions (enter 1, 2, or 3):")
    print("1. Transfer money")
    print("2. Check account balance")
    print("3. Exit")

def transfer_money(client_socket, user_id):
    while True:
        print("Please select an account (enter 1 or 2):")
        print("1. Savings")
        print("2. Checking")
        account_choice = input("Select account: ")
        if account_choice not in ["1", "2"]:
            print("Incorrect input. Please select either the savings or checking account.")
            continue
        recipient_id = input("Enter the recipient's ID: ")
        if recipient_id == user_id:
            print("Recipient ID cannot be the same as your ID. Please try again.")
            continue
        amount = input("Enter the amount to be transferred: ")
        try:
            amount = float(amount)
        except ValueError:
            print("Invalid amount. Please enter a numeric value.")
            continue
        transfer_request = f"Transfer {account_choice} {recipient_id} {amount}"
        response = send_request(client_socket, transfer_request)
        print(f"Server response: {response}")
        break

def connect_to_bank_server(host, port, public_key_path):
    public_key = load_public_key(public_key_path)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host, port))
        print(f"Connected to bank server at {host}:{port}")

        server_public_key_data = client_socket.recv(1024)
        server_public_key = serialization.load_pem_public_key(server_public_key_data)

        while True:
            user_id = input("Enter your ID: ")
            password = getpass.getpass("Enter your password: ")
            response = send_encrypted_credentials(client_socket, server_public_key, user_id, password)

            if response == "ID and password are correct":
                while True:
                    main_menu()
                    choice = input("Your choice: ")
                    if choice == "1":
                        transfer_money(client_socket, user_id)
                    elif choice == "2":
                        balance_info = send_request(client_socket, "2")
                        print(balance_info)
                    elif choice == "3":
                        break
                    else:
                        print("Invalid choice. Please try again.")
                break
            else:
                print("ID or password is incorrect. Please try again.")
                retry = input("Do you want to try again? (yes/no): ")
                if retry.lower() != 'yes':
                    break

public_key_path = 'public_key.pem'
if len(sys.argv) < 3:
    print("Usage: python client.py <host> <port number>")
else:
    host = sys.argv[1]
    port = int(sys.argv[2])
    if host == "localhost" or not host:
        print("The host name should not be localhost or empty")
        sys.exit(1)

    if not (1024 <= port <= 65535):
        print("The port number should be a user-defined number between 1024 and 65535")
        sys.exit(1)

connect_to_bank_server(host, port, public_key_path)