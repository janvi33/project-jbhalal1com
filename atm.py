import sys
import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import getpass

def load_public_key(filename):
    with open(filename, "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())

def encrypt_with_public_key(public_key, message):
    return public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def send_encrypted_credentials(client_socket, public_key, user_id, password):
    credentials = f"ID: {user_id} Password: {password}"
    encrypted_credentials = encrypt_with_public_key(public_key, credentials)
    client_socket.sendall(encrypted_credentials)
    response = client_socket.recv(1024).decode()
    return response

def send_request(client_socket, public_key, request):
    encrypted_request = encrypt_with_public_key(public_key, request)
    client_socket.sendall(encrypted_request)
    response = client_socket.recv(1024).decode()
    return response

def main_menu():
    print("Please select one of the following actions (enter 1, 2, or 3):")
    print("1. Transfer money")
    print("2. Check account balance")
    print("3. Exit")

def transfer_money(client_socket, public_key, user_id):
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
        response = send_request(client_socket, public_key, transfer_request)
        print(f"Server response: {response}")
        break

def connect_to_bank_server(host, port, public_key_path):
    public_key = load_public_key(public_key_path)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect((host, port))
        print(f"Connected to bank server at {host}:{port}")

        server_public_key_data = client_socket.recv(1024)
        server_public_key = serialization.load_pem_public_key(server_public_key_data)

        while True:  # Keep asking for ID and password until correct or exited
            user_id = input("Enter your ID: ")
            password = getpass.getpass("Enter your password: ")
            response = send_encrypted_credentials(client_socket, server_public_key, user_id, password)

            if response == "ID and password are correct":
                while True:
                    main_menu()
                    choice = input("Your choice: ")

                    if choice == "1":
                        transfer_money(client_socket, server_public_key, user_id)
                    elif choice == "2":
                        balance_info = send_request(client_socket, server_public_key, "2")
                        print(balance_info)
                    elif choice == "3":
                        print("Exiting.")
                        break
                    else:
                        print("Invalid choice. Please try again.")
                break  # Break out of the outer loop if logged in successfully
            else:
                print("ID or password is incorrect. Please try again.")
                retry = input("Do you want to try again? (yes/no): ")
                if retry.lower() != 'yes':
                    print("Exiting.")
                    break

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python script_name.py <host> <port>")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])

    public_key_path = 'public_key.pem'  # Replace with your file path
    connect_to_bank_server(host, port, public_key_path)
