from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import AuthenticationForm
import re
import re
from django import forms
from django.contrib.auth.models import User

class RegisterForm(forms.Form):
    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Email'
        })
    )

    password1 = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Password'
        }),
        required=True
    )

    password2 = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Confirm Password'
        }),
        required=True
    )

    def clean_email(self):
        email = self.cleaned_data.get("email")

        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("Email is already registered.")

        if " " in email:
            raise forms.ValidationError("Email cannot contain spaces.")

        disposable_domains = [
            "mailinator.com", "tempmail.com", "10minutemail.com",
            "discard.email", "guerrillamail.com", "trashmail.com"
        ]
        domain = email.split("@")[-1]
        if domain.lower() in disposable_domains:
            raise forms.ValidationError("Disposable email not allowed.")

        return email

    def clean_password1(self):
        password = self.cleaned_data.get("password1")
        errors = []

        if len(password) < 8:
            errors.append("• Minimum 8 characters required.")

        if not re.search(r"[A-Z]", password):
            errors.append("• Must contain at least 1 uppercase letter (A-Z).")
            
        if not re.search(r"\d", password):
            errors.append("• Must contain at least 1 number (0-9).")

        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            errors.append("• Must contain at least 1 special character (!@#$%^&*).")

        if errors:
            raise forms.ValidationError(errors)

        return password

    def clean(self):
        cleaned = super().clean()
        p1 = cleaned.get("password1")
        p2 = cleaned.get("password2")

        if p1 and p2 and p1 != p2:
            raise forms.ValidationError("Passwords do not match.")

        return cleaned

    def save(self):
        email = self.cleaned_data['email']
        password = self.cleaned_data['password1']

        user = User.objects.create_user(
            username=email,
            email=email,
            password=password
        )
        return user

class ResetPasswordForm(forms.Form):
    password1 = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'New Password'
        }),
        required=True
    )

    password2 = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Confirm New Password'
        }),
        required=True
    )

    def clean_password1(self):
        password = self.cleaned_data.get("password1")

        if len(password) < 8:
            raise forms.ValidationError("Password must be at least 8 characters.")

        if not re.search(r"[A-Z]", password):
            raise forms.ValidationError("Must contain one uppercase letter.")

        if not re.search(r"\d", password):
            raise forms.ValidationError("Must contain one number.")

        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            raise forms.ValidationError("Must contain one special character.")

        return password

    def clean(self):
        cleaned = super().clean()
        p1 = cleaned.get("password1")
        p2 = cleaned.get("password2")

        if p1 and p2 and p1 != p2:
            raise forms.ValidationError("Passwords do not match.")

        return cleaned

class UploadForm(forms.Form):
    file = forms.FileField()


class SecureNoteForm(forms.Form):
    title = forms.CharField(max_length=255, required=False, widget=forms.TextInput(attrs={
        "class": "form-control", "placeholder": "Title (optional)"
    }))
    content = forms.CharField(widget=forms.Textarea(attrs={
        "class": "form-control", "rows": 8, "placeholder": "Type your secure note here..."
    }), required=True)

class NoteUnlockForm(forms.Form):
    passphrase = forms.CharField(widget=forms.PasswordInput(attrs={
        "class": "form-control", "placeholder": "Enter your account password"
    }), required=True)

class MFAVerifyForm(forms.Form):
    token = forms.CharField(max_length=6, required=True, widget=forms.TextInput(attrs={
        "placeholder": "123456",
        "class": "form-control",
        "autocomplete": "one-time-code"
    }))

class MFAEnableConfirmForm(forms.Form):
    token = forms.CharField(max_length=6, required=True, widget=forms.TextInput(attrs={
        "placeholder": "Enter code from app",
        "class": "form-control",
        "autocomplete": "one-time-code"
    }))
