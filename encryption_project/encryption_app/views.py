"""Views for the encryption application."""

from django.shortcuts import render
from django.contrib import messages
from .sec_edbd import SecureEDBD

def home(request):
    """Home page view."""
    return render(request, 'encryption_app/home.html')

def encrypt(request):
    """Encrypt text view."""
    result = None
    
    if request.method == 'POST':
        text = request.POST.get('text', '')
        password = request.POST.get('password', '')
        
        if not text or not password:
            messages.error(request, 'Both text and password are required')
        else:
            try:
                encryptor = SecureEDBD(password)
                result = encryptor.encrypt(text)
                messages.success(request, 'Text encrypted successfully')
            except Exception as e:
                messages.error(request, f'Encryption error: {str(e)}')
    
    return render(request, 'encryption_app/encrypt.html', {'result': result})

def decrypt(request):
    """Decrypt text view."""
    result = None
    
    if request.method == 'POST':
        encrypted_text = request.POST.get('text', '')
        password = request.POST.get('password', '')
        
        if not encrypted_text or not password:
            messages.error(request, 'Both encrypted text and password are required')
        else:
            try:
                decryptor = SecureEDBD(password)
                result = decryptor.decrypt(encrypted_text)
                
                if result is None:
                    messages.error(request, 'Decryption failed. Invalid password or tampered data.')
                else:
                    messages.success(request, 'Text decrypted successfully')
            except Exception as e:
                messages.error(request, f'Decryption error: {str(e)}')
    
    return render(request, 'encryption_app/decrypt.html', {'result': result})