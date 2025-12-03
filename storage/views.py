import logging
import hashlib
import random

from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.core.files.base import ContentFile
from django.core.mail import send_mail
from django.urls import reverse
from django.utils.html import strip_tags
from django.core.mail import EmailMultiAlternatives

from .forms import RegisterForm, ResetPasswordForm, UploadForm,SecureNoteForm, NoteUnlockForm
from .models import EncryptedFile, PasswordResetOTP,SharedFile,LoginActivity,FileDownloadActivity,SecurityAlert,SecureNote
from .encryption.aes import generate_aes_key, encrypt_bytes, decrypt_bytes
from .encryption.rsa import generate_rsa_keypair, rsa_encrypt, rsa_decrypt
from .encryption.keywrap import wrap_private_key, unwrap_private_key


logger = logging.getLogger(__name__)


def index(request):
    return render(request, "homepage.html")

def register_view(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)

        if form.is_valid():
            user = form.save()

            public_pem, private_pem = generate_rsa_keypair()

            raw_password = form.cleaned_data['password1']
            wrapped = wrap_private_key(private_pem, raw_password)

            profile = user.profile
            profile.public_key = public_pem.decode()
            profile.private_key_encrypted = wrapped
            profile.save()

            messages.success(request, "Registration successful! Please log in.", extra_tags="register")
            return redirect("login")

    else:
        form = RegisterForm()

    return render(request, "register.html", {"form": form})


from .utils import get_client_ip, get_geo_data, get_device_info
from storage.models import LoginActivity

def login_view(request):
    email_error = ""
    password_error = ""

    if request.method == "POST":
        email = request.POST.get("email", "").strip()
        password = request.POST.get("password", "").strip()

        if not email:
            email_error = "Email is required."
        if not password:
            password_error = "Password is required."

        if email_error or password_error:
            return render(request, "login.html", {
                "email_error": email_error,
                "password_error": password_error,
                "email_value": email
            })

        try:
            user_obj = User.objects.get(email=email)
        except User.DoesNotExist:
            return render(request, "login.html", {
                "password_error": "Invalid email or password.",
                "email_value": email
            })

        user = authenticate(request, username=user_obj.username, password=password)

        if user:


            if user.profile.mfa_enabled:
                request.session["mfa_user_id"] = user.id
                return redirect("mfa_verify")

            login(request, user)


            ip = get_client_ip(request)
            geo = get_geo_data(ip)
            device = get_device_info(request)

            LoginActivity.objects.create(
                user=user,
                ip=ip,
                country=geo.get("country"),
                city=geo.get("city"),
                browser=device.get("browser"),
                os=device.get("os"),
            )

            last_log = LoginActivity.objects.filter(user=user).order_by('-timestamp')[1:2].first()

            def _alert_exists(alert_type, message):
                return SecurityAlert.objects.filter(
                    user=user,
                    alert_type=alert_type,
                    message=message,
                    is_resolved=False
                ).exists()

            if last_log:

                if last_log.ip != ip:
                    msg = f"New login detected from IP {ip}. Previous IP was {last_log.ip}."
                    if not _alert_exists("New Login Location", msg):
                        SecurityAlert.objects.create(
                            user=user,
                            alert_type="New Login Location",
                            message=msg,
                            severity=SecurityAlert.SEVERITY_MEDIUM,
                        )

                last_browser = (last_log.browser or "").lower().strip()
                last_os = (last_log.os or "").lower().strip()
                cur_browser = (device.get("browser") or "").lower().strip()
                cur_os = (device.get("os") or "").lower().strip()

                if last_browser != cur_browser or last_os != cur_os:
                    msg = (
                        f"New device detected: {device.get('browser') or 'Unknown browser'} "
                        f"on {device.get('os') or 'Unknown OS'}. Previous device: "
                        f"{last_log.browser or 'Unknown'} on {last_log.os or 'Unknown'}."
                    )
                    if not _alert_exists("New Device Login", msg):
                        SecurityAlert.objects.create(
                            user=user,
                            alert_type="New Device Login",
                            message=msg,
                            severity=SecurityAlert.SEVERITY_HIGH,
                        )

            return redirect("home")

        return render(request, "login.html", {
            "password_error": "Invalid email or password.",
            "email_value": email
        })

    return render(request, "login.html")


def logout_view(request):
    logout(request)
    return redirect("login")

from .models import LoginActivity, FileDownloadActivity

@login_required
def dashboard(request):
    files = EncryptedFile.objects.filter(user=request.user).order_by('-uploaded_at')[:5]
    received_files = SharedFile.objects.filter(recipient=request.user).order_by('-created_at')[:5]

    storage_used = sum(
        f.encrypted_file.size for f in EncryptedFile.objects.filter(user=request.user)
    ) / (1024 * 1024)

    login_logs = LoginActivity.objects.filter(user=request.user).order_by('-timestamp')[:10]
    download_logs = FileDownloadActivity.objects.filter(user=request.user).order_by('-timestamp')[:10]

    alerts = SecurityAlert.objects.filter(
        user=request.user, is_resolved=False
    ).order_by('-created_at')[:10]

    return render(request, "dashboard.html", {
        "files": files,
        "received_files": received_files,
        "storage_used": "%.2f" % storage_used,
        "login_logs": login_logs,
        "download_logs": download_logs,
        "alerts": alerts,  
    })

import mimetypes

@login_required
def upload_view(request):

    MAX_FILES = 10
    MAX_SIZE_MB = 10
    MAX_SIZE = MAX_SIZE_MB * 1024 * 1024

    ALLOWED_MIME = {
        "image/jpeg": [".jpg", ".jpeg"],
        "image/png": [".png"],
        "application/pdf": [".pdf"],
        "text/plain": [".txt"],
    }

    if request.method == "POST":
        form = UploadForm(request.POST, request.FILES)

        if form.is_valid():
            f = form.cleaned_data["file"]

            if EncryptedFile.objects.filter(user=request.user).count() >= MAX_FILES:
                messages.error(request, f"Limit reached: {MAX_FILES} files allowed.", extra_tags="upload")
                return redirect("upload")

            if f.size > MAX_SIZE:
                messages.error(request, f"File too large (max {MAX_SIZE_MB}MB).", extra_tags="upload")
                return redirect("upload")

            mime_type = f.content_type
            if mime_type not in ALLOWED_MIME:
                messages.error(request, "Invalid file type.", extra_tags="upload")
                return redirect("upload")

            file_ext = f.name.lower().rsplit(".", 1)[-1]
            valid_exts = [e.replace(".", "") for e in ALLOWED_MIME[mime_type]]

            if file_ext not in valid_exts:
                messages.error(request, "File extension mismatch! Possible disguised file.", extra_tags="upload")
                return redirect("upload")

            raw = f.read()

            file_hash = hashlib.sha256(raw).hexdigest()
            if EncryptedFile.objects.filter(user=request.user, file_hash=file_hash).exists():
                messages.error(request, "Duplicate file detected.", extra_tags="upload")
                return redirect("upload")

            if EncryptedFile.objects.filter(user=request.user, file_name=f.name).exists():
                messages.error(request, "A file with this name already exists.", extra_tags="upload")
                return redirect("upload")

            # --------------------------------
            # ENCRYPTION LOGIC (same as yours)
            # --------------------------------
            aes_key = generate_aes_key()
            encrypted_blob = encrypt_bytes(raw, aes_key)
            public_pem = request.user.profile.public_key.encode()
            encrypted_aes_key = rsa_encrypt(public_pem, aes_key)

            EncryptedFile.objects.create(
                user=request.user,
                file_name=f.name,
                encrypted_file=ContentFile(encrypted_blob, f.name),
                encrypted_aes_key=encrypted_aes_key,
                file_hash=file_hash
            )

            messages.success(request, "File uploaded & encrypted securely.", extra_tags="upload")
            return redirect("upload")

    else:
        form = UploadForm()

    files = EncryptedFile.objects.filter(user=request.user).order_by("-uploaded_at")
    return render(request, "upload.html", {"form": form, "files": files})


@login_required
def files_view(request):
    files = EncryptedFile.objects.filter(user=request.user).order_by("-uploaded_at")
    return render(request, "files.html", {"files": files})


@login_required
def download_view(request, file_id):
    ef = get_object_or_404(EncryptedFile, id=file_id)

    # Permission check
    if ef.user != request.user:
        messages.error(request, "Permission denied.", extra_tags="download")
        return redirect("files")

    if request.method == "POST":
        passphrase = request.POST.get("passphrase")

        encrypted_blob = ef.encrypted_file.read()

        try:
            private_pem = unwrap_private_key(
                request.user.profile.private_key_encrypted,
                passphrase
            )
        except:
            messages.error(request, "Wrong password.", extra_tags="download")
            return render(request, "download.html", {"file": ef})

        try:
            aes_key = rsa_decrypt(private_pem, ef.encrypted_aes_key)
            decrypted_data = decrypt_bytes(encrypted_blob, aes_key)
        except:
            messages.error(request, "Decryption failed.", extra_tags="download")
            return render(request, "download.html", {"file": ef})

        # Integrity check
        if hashlib.sha256(decrypted_data).hexdigest() != ef.file_hash:
            messages.error(request, "Integrity check failed!", extra_tags="download")
            return redirect("files")

        # -------------------------------------------------
        # GEO LOGGING START (IP, CITY, COUNTRY, DEVICE)
        # -------------------------------------------------
        from .utils import get_client_ip, get_geo_data, get_device_info
        from .models import FileDownloadActivity

        ip = get_client_ip(request)
        geo = get_geo_data(ip)
        device = get_device_info(request)

        FileDownloadActivity.objects.create(
            user=request.user,
            file_name=ef.file_name,
            ip=ip,
            country=geo["country"],
            city=geo["city"],
            browser=device["browser"],
            os=device["os"]
        )
        # -------------------------------------------------
        # GEO LOGGING END
        # -------------------------------------------------

        # Return decrypted file
        response = HttpResponse(
            decrypted_data,
            content_type="application/octet-stream"
        )
        response["Content-Disposition"] = f'attachment; filename="{ef.file_name}"'
        return response

    # GET request → Show password form
    return render(request, "download.html", {"file": ef})


@login_required
def delete_view(request, file_id):
    ef = get_object_or_404(EncryptedFile, id=file_id)

    if ef.user != request.user:
        messages.error(request, "Permission denied.", extra_tags="delete")
    else:
        ef.encrypted_file.delete(save=False)
        ef.delete()
        messages.success(request, "File deleted.", extra_tags="delete")

    return redirect("files")


def forgot_password(request):
    if request.method == "POST":
        email = request.POST.get("email")

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            messages.error(request, "Email not found.", extra_tags="forgot")
            return render(request, "forgot_password.html")

        otp = str(random.randint(100000, 999999))
        PasswordResetOTP.objects.create(user=user, otp=otp)

        send_mail(
            "Password Reset OTP",
            f"Your OTP is: {otp}\nValid for 5 minutes.",
            "noreply@secureportal.com",
            [email]
        )

        request.session["reset_email"] = email
        messages.success(request, "OTP sent to your email.", extra_tags="forgot")
        return redirect("verify_otp")

    return render(request, "forgot_password.html")


def verify_otp(request):
    email = request.session.get("reset_email")

    if not email:
        messages.error(request, "Session expired.", extra_tags="forgot")
        return redirect("forgot_password")

    if request.method == "POST":
        otp_entered = request.POST.get("otp")

        try:
            user = User.objects.get(email=email)
        except:
            messages.error(request, "Invalid email.", extra_tags="forgot")
            return redirect("forgot_password")

        otp_obj = (
            PasswordResetOTP.objects.filter(user=user, otp=otp_entered, is_used=False)
            .order_by("-created_at")
            .first()
        )

        if not otp_obj:
            messages.error(request, "Invalid OTP.", extra_tags="forgot")
            return redirect("verify_otp")

        if otp_obj.is_expired():
            messages.error(request, "OTP expired.", extra_tags="forgot")
            return redirect("forgot_password")

        otp_obj.is_used = True
        otp_obj.save()
        request.session["otp_verified"] = True
        return redirect("reset_password")

    return render(request, "verify_otp.html")


def reset_password(request):

    if not request.session.get("otp_verified"):
        return redirect("login")

    email = request.session.get("reset_email")
    if not email:
        return redirect("forgot_password")

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        messages.error(request, "User not found.", extra_tags="reset")
        return redirect("forgot_password")

    if request.method == "POST":
        form = ResetPasswordForm(request.POST)

        if form.is_valid():
            new_pw = form.cleaned_data["password1"]

            user.set_password(new_pw)
            user.save()

            public_pem, private_pem = generate_rsa_keypair()
            wrapped_private = wrap_private_key(private_pem, new_pw)

            profile = user.profile
            profile.public_key = public_pem.decode()
            profile.private_key_encrypted = wrapped_private
            profile.save()

            files = EncryptedFile.objects.filter(user=user)
            for f in files:
                try:
                    f.encrypted_file.close()
                except:
                    pass
                f.encrypted_file.delete(save=False)
                f.delete()

            request.session.pop("reset_email", None)
            request.session.pop("otp_verified", None)

            messages.success(request, "Password reset successful.", extra_tags="reset")
            return redirect("login")

        messages.error(request, "Fix the errors below.", extra_tags="reset")

    else:
        form = ResetPasswordForm()

        messages.warning(
            request,
            "Resetting your password will permanently delete all your encrypted files because they cannot be decrypted without your old password.",
            extra_tags="reset",
        )

    return render(request, "reset_password.html", {"form": form})

from .models import SharedFile
@login_required
def share_view(request, file_id):
    file_obj = get_object_or_404(EncryptedFile, id=file_id, user=request.user)
    users = User.objects.exclude(id=request.user.id)

    if request.method == "POST":
        recipient_email = request.POST.get("email", "").strip()
        owner_password = request.POST.get("owner_password", "")
        message_text = request.POST.get("message", "")

        try:
            recipient = User.objects.get(email=recipient_email)
            if recipient.id == request.user.id:
                messages.error(request, "You cannot share a file with yourself.")
                return redirect("share", file_id=file_id)
        except User.DoesNotExist:
            messages.error(request, "Recipient must be a registered user.")
            return redirect("share", file_id=file_id)

        try:
            owner_wrapped = request.user.profile.private_key_encrypted
            owner_private_pem = unwrap_private_key(owner_wrapped, owner_password)
        except Exception as e:
            logger.warning(f"Share unlock failed for {request.user.email}: {e}")
            messages.error(request, "Wrong password. Cannot unlock your private key.")
            return redirect("share", file_id=file_id)

        try:
            aes_key = rsa_decrypt(owner_private_pem, file_obj.encrypted_aes_key)
        except Exception as e:
            logger.exception(f"Failed decrypting AES key: {e}")
            messages.error(request, "Internal error decrypting file key.")
            return redirect("share", file_id=file_id)


        try:
            recip_pub = recipient.profile.public_key.encode()
            encrypted_for_recipient = rsa_encrypt(recip_pub, aes_key)
        except Exception as e:
            logger.exception(f"Failed encrypting AES key for recipient: {e}")
            messages.error(request, "Internal error encrypting file key for recipient.")
            return redirect("share", file_id=file_id)

        shared_entry = SharedFile.objects.create(
            file=file_obj,
            owner=request.user,
            recipient=recipient,
            encrypted_aes_key_for_recipient=encrypted_for_recipient
        )

        link = request.build_absolute_uri(
            reverse("shared_download", args=[shared_entry.id])
        )

        subject = f"{request.user.email} shared a secure file with you"

        html_content = f"""
        <html>
          <body style="font-family: Arial; background:#f5f5f5; padding:20px;">
            <div style="max-width:600px; margin:auto; background:white; padding:25px; border-radius:10px;">

              <h2 style="text-align:center; color:#333;">Secure File Shared</h2>

              <p><strong>{request.user.email}</strong> has shared an encrypted file with you.</p>

              <p>
                <strong> File:</strong> {file_obj.file_name}<br>
                <strong> Expires:</strong> {shared_entry.expires_at.strftime("%Y-%m-%d %H:%M")}
              </p>

              <p>To access the file:</p>
              <ol>
                <li>Log in to your SecurePortal account</li>
                <li>Click the button below</li>
                <li>Enter your password to decrypt</li>
              </ol>

              <div style="text-align:center; margin-top:25px;">
                <a href="{link}"
                   style="background:#4a90e2; color:white; padding:12px 22px;
                          text-decoration:none; border-radius:6px; font-size:16px;">
                   🔓 Open Secure File
                </a>
              </div>

              <p style="margin-top:25px; color:#555;">
                <strong>Message from sender:</strong><br>
                <em>{message_text}</em>
              </p>

              <p style="font-size:13px; color:#888; margin-top:20px;">
                This link expires automatically after 24 hours.
              </p>
            </div>
          </body>
        </html>
        """

        text_content = strip_tags(html_content)
        email = EmailMultiAlternatives(
            subject=subject,
            body=text_content,
            from_email="noreply@secureportal.com",
            to=[recipient.email],
        )
        email.attach_alternative(html_content, "text/html")

        try:
            email.send()
            messages.success(
                request,
                "Secure share email sent successfully!",
                extra_tags="share"
            )
        except Exception as e:
            logger.error(f"Email sending failed: {e}")
            messages.warning(
                request,
                "File shared, but email could NOT be sent.",
                extra_tags="share"
             )

        return redirect("files")

    return render(request, "share.html", {"file": file_obj, "users": users})

@login_required
def shared_download_view(request, share_id):
    shared = get_object_or_404(SharedFile, id=share_id, recipient=request.user)
    ef = shared.file

    if shared.is_expired():
        messages.error(request, "This secure link has expired.", extra_tags="shared_download")
        return redirect("files")

    if request.method == "POST":
        passphrase = request.POST.get("passphrase", "").strip()

        try:
            recipient_private_pem = unwrap_private_key(
                request.user.profile.private_key_encrypted, passphrase
            )
        except Exception as e:
            logger.warning(f"Recipient unwrap failed: {e}")
            messages.error(request, "Wrong password. Cannot unlock your private key.",
                           extra_tags="shared_download")
            return render(request, "shared_download.html", {"file": ef})

        try:
            aes_key = rsa_decrypt(recipient_private_pem, shared.encrypted_aes_key_for_recipient)
        except Exception as e:
            logger.exception(f"Decrypt AES key failed: {e}")
            messages.error(request, "Failed to decrypt file key.",
                           extra_tags="shared_download")
            return render(request, "shared_download.html", {"file": ef})

        try:
            decrypted = decrypt_bytes(ef.encrypted_file.read(), aes_key)
        except Exception:
            messages.error(request, "File decryption failed.",
                           extra_tags="shared_download")
            return render(request, "shared_download.html", {"file": ef})

        if hashlib.sha256(decrypted).hexdigest() != ef.file_hash:
            messages.error(request, "Integrity check failed! File corrupted.",
                           extra_tags="shared_download")
            return redirect("files")

        response = HttpResponse(decrypted, content_type="application/octet-stream")
        response["Content-Disposition"] = f'attachment; filename="{ef.file_name}"'
        return response
    
    return render(request, "shared_download.html", {"file": ef})

@login_required
def secure_notes_list(request):
    """List secure notes for the current user."""
    notes = SecureNote.objects.filter(user=request.user).order_by('-updated_at')
    return render(request, "list.html", {"notes": notes})

@login_required
def secure_note_create(request):
    """Create & encrypt a new secure note."""
    if request.method == "POST":
        form = SecureNoteForm(request.POST)
        if form.is_valid():
            title = form.cleaned_data["title"]
            content_text = form.cleaned_data["content"].encode("utf-8")

            # generate per-note AES key and encrypt content
            aes_key = generate_aes_key()
            encrypted_blob = encrypt_bytes(content_text, aes_key)

            # encrypt AES key with user's public RSA key
            public_pem = request.user.profile.public_key.encode()
            encrypted_aes_key = rsa_encrypt(public_pem, aes_key)

            SecureNote.objects.create(
                user=request.user,
                title=title,
                encrypted_content=encrypted_blob,
                encrypted_aes_key=encrypted_aes_key
            )
            messages.success(request, "Secure note saved and encrypted.")
            return redirect("secure_notes_list")
        else:
            messages.error(request, "Fix the errors below.")
    else:
        form = SecureNoteForm()

    return render(request, "form.html", {"form": form, "action": "Create"})

@login_required
def secure_note_view(request, note_id):
    """Show UI to unlock and view a note. Decryption happens server-side after passphrase."""
    note = get_object_or_404(SecureNote, id=note_id, user=request.user)

    if request.method == "POST":
        form = NoteUnlockForm(request.POST)
        if form.is_valid():
            passphrase = form.cleaned_data["passphrase"]
            try:

                private_pem = unwrap_private_key(request.user.profile.private_key_encrypted, passphrase)
            except Exception:
                messages.error(request, "Wrong passphrase. Cannot unlock your private key.")
                return render(request, "view.html", {"note": note, "form": form})


            try:
                aes_key = rsa_decrypt(private_pem, note.encrypted_aes_key)
                decrypted_bytes = decrypt_bytes(note.encrypted_content, aes_key)
                decrypted_text = decrypted_bytes.decode("utf-8")
            except Exception:
                messages.error(request, "Decryption failed.")
                return render(request, "view.html", {"note": note, "form": form})

            # show decrypted note
            return render(request, "view.html", {
                "note": note,
                "form": form,
                "decrypted_text": decrypted_text
            })
    else:
        form = NoteUnlockForm()

    return render(request, "view.html", {"note": note, "form": form})

@login_required
def secure_note_delete(request, note_id):
    note = get_object_or_404(SecureNote, id=note_id, user=request.user)
    if request.method == "POST":
        note.delete()
        messages.success(request, "Note deleted.")
        return redirect("secure_notes_list")
    return render(request, "confirm_delete.html", {"note": note})


@login_required
def secure_note_edit(request, note_id):
    note = get_object_or_404(SecureNote, id=note_id, user=request.user)

    if request.method == "POST" and "passphrase" in request.POST:
        passphrase = request.POST.get("passphrase")

        try:
            private_pem = unwrap_private_key(request.user.profile.private_key_encrypted, passphrase)

            aes_key = rsa_decrypt(private_pem, note.encrypted_aes_key)

            decrypted_bytes = decrypt_bytes(note.encrypted_content, aes_key)

            request.session["note_edit_key"] = aes_key.hex()

        except Exception:
            messages.error(request, "Incorrect passphrase.")
            return render(request, "secure_note_edit.html", {
                "note": note,
                "unlocked": False
            })

        return render(request, "secure_note_edit.html", {
            "note": note,
            "note_decrypted": decrypted_bytes.decode(),
            "unlocked": True
        })
    elif request.method == "POST":
        title = request.POST.get("title")
        content = request.POST.get("content")

        aes_key_hex = request.session.get("note_edit_key")

        if not aes_key_hex:
            messages.error(request, "Session expired. Unlock the note again.")
            return redirect("secure_note_edit", note_id=note.id)

        aes_key = bytes.fromhex(aes_key_hex)

        new_encrypted = encrypt_bytes(content.encode(), aes_key)

        note.title = title
        note.encrypted_content = new_encrypted
        note.save()

        del request.session["note_edit_key"]

        messages.success(request, "Note updated successfully.")
        return redirect("secure_note_view", note_id=note.id)

    return render(request, "secure_note_edit.html", {
        "note": note,
        "unlocked": False
    })


import base64
import io
import pyotp
import qrcode

from django.conf import settings

from .forms import MFAVerifyForm, MFAEnableConfirmForm

def qrcode_data_uri(uri):
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    b64 = base64.b64encode(buffer.getvalue()).decode()
    return f"data:image/png;base64,{b64}"


@login_required
def mfa_setup(request):
    """
    Step 1: If user doesn't have a secret, create TOTP secret and show QR + manual key.
    Step 2: User scans QR with Google Authenticator and enters first code to confirm.
    """
    profile = request.user.profile

    # If user already enabled MFA, show status and option to disable
    if profile.mfa_enabled:
        return render(request, "mfa_already_enabled.html", {"profile": profile})

    # Generate secret if needed and store temporarily in session (do NOT persist enabled flag until confirmed)
    if not profile.mfa_secret:
        secret = pyotp.random_base32()  # 16-32 chars
        profile.mfa_secret = secret
        profile.save()  # we can save secret now; not enabled until verified
    else:
        secret = profile.mfa_secret

    issuer = getattr(settings, "MFA_ISSUER_NAME", "SecurePortal")
    user_email = request.user.email or request.user.username
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=user_email, issuer_name=issuer)
    qr_data = qrcode_data_uri(provisioning_uri)

    if request.method == "POST":
        form = MFAEnableConfirmForm(request.POST)
        if form.is_valid():
            token = form.cleaned_data["token"].strip()
            if pyotp.TOTP(secret).verify(token, valid_window=1):
                profile.mfa_enabled = True
                profile.save()
                messages.success(request, "MFA enabled successfully.")
                return redirect("dashboard")
            else:
                messages.error(request, "Invalid code. Please try again.")
    else:
        form = MFAEnableConfirmForm()

    return render(request, "mfa_setup.html", {
        "secret": secret,
        "qr_data": qr_data,
        "form": form,
        "issuer": issuer,
    })

@login_required
def mfa_disable(request):
    profile = request.user.profile
    if request.method == "POST":
        # optionally require current password or TOTP token to disable (safer)
        profile.mfa_enabled = False
        profile.mfa_secret = ""
        profile.save()
        messages.success(request, "MFA has been disabled.")
        return redirect("dashboard")
    return render(request, "mfa_disable.html", {"profile": profile})

def mfa_verify(request):
    from django.contrib.auth import login as auth_login
    from django.contrib.auth.models import User

    user_id = request.session.get("mfa_user_id")
    if not user_id:
        messages.error(request, "Session expired. Please login again.")
        return redirect("login")

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        messages.error(request, "User not found.")
        return redirect("login")

    profile = user.profile

    if request.method == "POST":
        token = request.POST.get("token", "").strip()

        if pyotp.TOTP(profile.mfa_secret).verify(token, valid_window=1):
            # Clear session → complete login
            auth_login(request, user)
            request.session.pop("mfa_user_id", None)

            messages.success(request, "MFA verified. Welcome!")
            return redirect("dashboard")
        else:
            messages.error(request, "Invalid code. Try again.")

    return render(request, "mfa_verify.html")
