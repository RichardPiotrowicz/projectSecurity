import secrets

from django.contrib.auth.forms import UserCreationForm
from django.shortcuts import render, redirect
from .forms import MessagesForm
from .models import Messages

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from base64 import b64encode, b64decode

from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.forms import AuthenticationForm


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


def register_view(request):
    # This function renders the registration form page and create a new user based on the form data
    if request.method == 'POST':
        # We use Django's UserCreationForm which is a model created by Django to create a new user.
        # UserCreationForm has three fields by default: username (from the user model), password1, and password2.
        form = UserCreationForm(request.POST)
        # check whether it's valid: for example it verifies that password1 and password2 match
        if form.is_valid():
            form.save()
            # redirect the user to login page so that after registration the user can enter the credentials
            return redirect('login')
    else:
        # Create an empty instance of Django's UserCreationForm to generate the necessary html on the template.
        form = UserCreationForm()
    # return render(request, 'accounts/register.html', {'form': form})
    return render(request, 'register.html', {'form': form})


def logout_view(request):
    # Log out user
    logout(request)
    # Redirect to index with user logged out
    return redirect('index')


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
