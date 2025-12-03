from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone
from datetime import timedelta


class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    public_key = models.TextField(blank=True, null=True)
    private_key_encrypted = models.BinaryField(blank=True, null=True)
    role = models.CharField(max_length=20, default='user')

    mfa_enabled = models.BooleanField(default=False)
    mfa_secret = models.CharField(max_length=32, blank=True, null=True)

    def __str__(self):
        return f"{self.user.username} Profile"

@receiver(post_save, sender=User)
def create_or_update_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)
    else:
        instance.profile.save()


# ------------------ ENCRYPTED FILE ------------------

class EncryptedFile(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    file_name = models.CharField(max_length=512)
    encrypted_file = models.FileField(upload_to='encrypted/')
    encrypted_aes_key = models.BinaryField()
    file_hash = models.CharField(max_length=128, blank=True, null=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.file_name} ({self.user.username})"


# ------------------ PASSWORD RESET OTP ------------------

class PasswordResetOTP(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    is_used = models.BooleanField(default=False)

    def is_expired(self):
        return (timezone.now() - self.created_at).total_seconds() > 300


# ------------------ SHARE FILE ------------------

def expiry_24h():
    return timezone.now() + timedelta(hours=24)

class SharedFile(models.Model):
    file = models.ForeignKey(EncryptedFile, on_delete=models.CASCADE)
    owner = models.ForeignKey(User, related_name="shared_owner", on_delete=models.CASCADE)
    recipient = models.ForeignKey(User, related_name="shared_recipient", on_delete=models.CASCADE)
    encrypted_aes_key_for_recipient = models.BinaryField()
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(default=expiry_24h)

    def is_expired(self):
        return timezone.now() > self.expires_at


# ------------------ LOGIN GEO-LOCATION LOG ------------------

class LoginActivity(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    ip = models.CharField(max_length=50)
    country = models.CharField(max_length=100, null=True, blank=True)
    city = models.CharField(max_length=100, null=True, blank=True)
    browser = models.CharField(max_length=100, null=True)
    os = models.CharField(max_length=100, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)


# ------------------ FILE DOWNLOAD GEO-LOCATION LOG ------------------

class FileDownloadActivity(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    file_name = models.CharField(max_length=255)
    ip = models.CharField(max_length=50)
    country = models.CharField(max_length=100, null=True, blank=True)
    city = models.CharField(max_length=100, null=True, blank=True)
    browser = models.CharField(max_length=100, null=True)
    os = models.CharField(max_length=100, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)


class SecurityAlert(models.Model):
    SEVERITY_LOW = "low"
    SEVERITY_MEDIUM = "medium"
    SEVERITY_HIGH = "high"
    SEVERITY_CHOICES = [
        (SEVERITY_LOW, "Low"),
        (SEVERITY_MEDIUM, "Medium"),
        (SEVERITY_HIGH, "High"),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    alert_type = models.CharField(max_length=100)  
    message = models.TextField()
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default=SEVERITY_LOW)
    created_at = models.DateTimeField(auto_now_add=True)
    is_resolved = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.user.email} - {self.alert_type} - {self.severity} @ {self.created_at}"


class FailedDecryptAttempt(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    file = models.ForeignKey(EncryptedFile, on_delete=models.CASCADE, null=True, blank=True)
    ip = models.CharField(max_length=50, null=True, blank=True)
    user_agent = models.CharField(max_length=255, null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)



class SecureNote(models.Model):
    """
    Encrypted secure text note.
    - encrypted_content: AES-encrypted bytes stored as BinaryField
    - encrypted_aes_key: AES key encrypted with user's public RSA key
    - title: optional note title (not secret)
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    title = models.CharField(max_length=255, blank=True)
    encrypted_content = models.BinaryField()      
    encrypted_aes_key = models.BinaryField()             
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        title = self.title if self.title else "(untitled)"
        return f"{title} — {self.user.username}"
