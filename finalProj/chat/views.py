import secrets

from django.contrib.auth import authenticate, login
from django.contrib.auth.forms import AuthenticationForm
from django.shortcuts import render, redirect
from .forms import MessagesForm
from .models import Messages

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from base64 import b64encode, b64decode


def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(data=request.POST)
        if form.is_valid():
            # get the user info from the form data and log in the user
            user = form.get_user()
            login(request, user)
            return redirect('home')
    else:
        form = AuthenticationForm()
        return render(request, 'login.html', {'form': form})

# Jahmaro Gordon
# def login_view(request):
#     if request.method == 'POST':
#         username = request.POST.get('Username')
#         password = request.POST.get('Password')
#
#         user = authenticate(request, username=username, password=password)
#         if user is not None:
#             # User was authenticated
#             # redirect to the index page upon successful login
#
#             # login in the user
#             login(request, user)
#             return redirect('chatLayout')
#         else:
#             # User was not authenticated
#             form = AuthenticationForm()
#             return render(request, 'home.html')
#
#     return render(request, 'login.html')


def chat(request):
    context = {}

    # create object of form
    form = MessagesForm(request.POST or None, request.FILES or None)

    # check if form data is valid
    if form.is_valid():
        # save the form data to model
        form.save()

    context['form'] = form
    context['data'] = Messages.objects.all()
    return render(request, "chatLayout.html", context)


def ssl_trigger(request):
    context = {}

    # create object of form
    form = MessagesForm(request.POST or None, request.FILES or None)

    # check if form data is valid
    if form.is_valid():
        # save the form data to model
        form.save()

    # renders form on webpage
    context['form'] = form
    context['data'] = Messages.objects.all()
    return render(request, "chatLayout.html", context)


# Jahmaro Gordon -> method to encrypt message
# want to run command : pip install pycryptodome
def encrypt_message_to_database(message):
    # Generate AES key to encrypt message
    aes_key = generate_aes_keys()

    # Message to encrypt
    ciphermessage = encrypt_message(message, aes_key)
    # for debug
    print("Encrypted message:", b64encode(ciphermessage).decode())

    # to decrypt
    decryptedmessage = decrypt_message(message, aes_key)
    # for debug
    print("Decrypted message:", b64encode(ciphermessage).decode())

    return message


def generate_aes_keys():
    # this will generate a 256 bit AES key
    return secrets.token_bytes(32)


# This function will pad the message
def pad_message(message):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    return padded_data


# This function encrypts a message with AES
def encrypt_message(message, key):
    # 128 bit IV
    iv = secrets.token_bytes(16)
    # algorithms.AES specifies that AES is used , key is going to be the AES key , MODE = CFB
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    # creates the encryptor object
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(pad_message(message)) + encryptor.finalize()
    return iv + ciphertext


# Function to decrypt a message with AES
def decrypt_message(ciphertext, key):
    # get iv fron cipher text (extracts first 16 bits)
    iv = ciphertext[:16]
    # gets cipher text
    ciphertext = ciphertext[16:]
    # Creates a Cipher object from provided key, IV, and CFB mode
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    # Performs the decryption by processing the ciphertext
    padded_message = decryptor.update(ciphertext) + decryptor.finalize()
    # creates an unpadder for the PKCS7 padding
    unpadder = padding.PKCS7(128).unpadder()
    # Remove the padding to get the original message
    message = unpadder.update(padded_message) + unpadder.finalize()
    return message
