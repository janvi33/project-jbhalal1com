1)The name and email address 
Name: Janvi bhalala
email: jbhalal1@binghamton.edu

2)The programming language you use (C/C++/Java/Python)
Python

3)Code for performing encryption/decryption
Cryptography library in Python is used for the encryption and decryption in the banking application.
Asymmetric encryption (RSA) is used for encrypting the symmetric key
symmetric encryption (AES) is used for securing the actual messages.

4)Whether your code was tested on remote.cs.binghamton.edu.
Yes, it was tested on remote.cs.binghamton.edu.

5)How to execute your program.
1) run "python3 bank.py <port number>"  which will start the bank server at specified port.
2) run "python3 atm.py remote00-07.cs.binghamton.edu <same port number(as entered for bank)>" . then both bank and atm will be connected.
3) Atm will asked to enter the user ID and password. Enter the user ID and password. If it's correct it will proceed further to the menu (1 for fund transfer, 2 for balance inquiry, 3 to exit).and if it's incorrect it will display"Incorrect ID/password" and ask again to enter.
4) further you need to choose from the menu options (1 for fund transfer, 2 for balance inquiry, 3 to exit). if you select 1, it will ask you to select (1. savings 2 checkings) then provide necessary details for fund transfer.
5) if you select 2 it will display the savings and checkings balance of your account.
6) by selecting 3 , you can exit the connection.

6)Anything special about your submission that the TA/grader should take note of.
Python 3 should be installed on your system.
Install the python library Cryptography using "pip install cryptography" if not installed.