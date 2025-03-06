# Secure Encryption Website

A Django web application for secure text encryption and decryption using AES-GCM with Argon2id key derivation.

## Features

- AES-256-GCM encryption algorithm for confidentiality and authenticity
- Argon2id password hashing (with PBKDF2 fallback) for resistance to brute force attacks
- Material Design UI for a modern, responsive interface
- Simple two-menu system: Encrypt and Decrypt
- No data stored server-side - all encryption/decryption happens in memory
- Copy to clipboard functionality for easy sharing

## Installation

1. Clone the repository
2. Install the required packages:
   ```
   pip install -r requirements.txt
   ```
3. Run migrations:
   ```
   cd encryption_project
   python manage.py migrate
   ```
4. Start the development server:
   ```
   python manage.py runserver
   ```

## Usage

1. Navigate to the home page at `http://localhost:8000/`
2. Choose either Encrypt or Decrypt from the navigation menu
3. For encryption:
   - Enter your text in the text field
   - Enter a strong password
   - Click "Encrypt" to generate encrypted text
   - Copy the encrypted text using the "Copy" button
4. For decryption:
   - Paste the encrypted text in the text field
   - Enter the same password that was used for encryption
   - Click "Decrypt" to recover the original text

## Security Notes

- This application uses industry-standard encryption techniques (AES-GCM with Argon2id key derivation)
- The password is never stored - it is only used to derive a key for encryption/decryption
- For maximum security, consider running this application locally and avoiding transmitting sensitive data over networks

## Technical Details

- Built with Django
- Uses the `cryptography` Python library for encryption operations
- Material Design styling for a modern UI
- Responsive design works on desktop and mobile devices