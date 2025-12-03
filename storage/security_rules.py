from django.utils import timezone
from datetime import timedelta
from django.core.mail import send_mail
from .models import LoginActivity, FileDownloadActivity, SecurityAlert, FailedDecryptAttempt

DOWNLOADS_THRESHOLD_COUNT = 6       
DOWNLOADS_THRESHOLD_SECONDS = 60     
FAILED_DECRYPT_THRESHOLD = 3            
FAILED_DECRYPT_WINDOW_MINUTES = 10

def _create_alert(user, alert_type, message, severity="low", notify_email=False):
    SecurityAlert.objects.create(
        user=user,
        alert_type=alert_type,
        message=message,
        severity=severity
    )
    if notify_email and user.email:
        try:
            send_mail(
                subject=f"[Security Alert] {alert_type}",
                message=message,
                from_email="security@portal.com",
                recipient_list=[user.email],
                fail_silently=True,
            )
        except Exception:
            pass


def evaluate_login(user, ip, country, city, browser, os, timestamp=None):
    """
    Call this after inserting a LoginActivity row.
    Rules:
     - New IP / country not seen recently -> medium alert
     - New device/browser -> low alert (or medium if coupled with new country)
    """
    if timestamp is None:
        timestamp = timezone.now()

    last = LoginActivity.objects.filter(user=user).order_by('-timestamp')[:5]
    if last:
        last_item = last[0]

        if country and last_item.country and country != last_item.country:
            msg = f"Login from new country detected. Previous: {last_item.country} ({last_item.ip}) at {last_item.timestamp}. Now: {country} ({ip})."
            _create_alert(user, "new_country", msg, severity="medium", notify_email=True)

        if ip and last_item.ip and ip != last_item.ip:
            msg = f"Login from new IP detected. Previous IP: {last_item.ip}. Now: {ip}."

        if browser and last_item.browser and browser != last_item.browser:
            msg = f"Device/browser changed: previous {last_item.browser}/{last_item.os} — now {browser}/{os}."
            _create_alert(user, "new_device", msg, severity="low", notify_email=False)


def evaluate_downloads(user, file_obj, ip, country, browser, os, timestamp=None):
    """
    Rules:
    - If user downloaded >= DOWNLOADS_THRESHOLD_COUNT files within DOWNLOADS_THRESHOLD_SECONDS -> medium/high alert
    """
    if timestamp is None:
        timestamp = timezone.now()

    window_start = timestamp - timedelta(seconds=DOWNLOADS_THRESHOLD_SECONDS)
    recent_count = FileDownloadActivity.objects.filter(
        user=user, timestamp__gte=window_start
    ).count()

    # including the current one will exceed threshold?
    if recent_count + 1 >= DOWNLOADS_THRESHOLD_COUNT:
        msg = (f"High download activity: {recent_count+1} downloads in the last "
               f"{DOWNLOADS_THRESHOLD_SECONDS} seconds. Possible automated exfiltration.")
        _create_alert(user, "rapid_downloads", msg, severity="high", notify_email=True)


def evaluate_failed_decrypt(user, file_obj, ip, user_agent, timestamp=None):
    """
    Rules:
    - If user has >= FAILED_DECRYPT_THRESHOLD failed decrypt attempts within window -> medium alert
    """
    if timestamp is None:
        timestamp = timezone.now()

    window_start = timestamp - timedelta(minutes=FAILED_DECRYPT_WINDOW_MINUTES)
    cnt = FailedDecryptAttempt.objects.filter(
        user=user, timestamp__gte=window_start
    ).count()

    if cnt >= FAILED_DECRYPT_THRESHOLD:
        msg = (f"{cnt} failed decryption attempts in the past {FAILED_DECRYPT_WINDOW_MINUTES} minutes. "
               f"Possible credential guessing or compromised client.")
        _create_alert(user, "failed_decrypts", msg, severity="medium", notify_email=True)
