
from django.urls import path
from . import views

urlpatterns = [
    path("", views.index, name="home"),
    path('register/', views.register_view, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path("forgot-password/", views.forgot_password, name="forgot_password"),
    path("verify-otp/", views.verify_otp, name="verify_otp"),
    path("reset-password/", views.reset_password, name="reset_password"),

    path('dashboard/', views.dashboard, name='dashboard'),
    path('upload/', views.upload_view, name='upload'),
    path('files/', views.files_view, name='files'),
    path('download/<int:file_id>/', views.download_view, name='download'),
    path('delete/<int:file_id>/', views.delete_view, name='delete'),
    path('share/<int:file_id>/', views.share_view, name='share'),
    path("shared-download/<int:share_id>/", views.shared_download_view, name="shared_download"),
    path('notes/', views.secure_notes_list, name='secure_notes_list'),
    path('notes/create/', views.secure_note_create, name='secure_note_create'),
    path('notes/<int:note_id>/', views.secure_note_view, name='secure_note_view'),
    path('notes/<int:note_id>/edit/', views.secure_note_edit, name='secure_note_edit'),
    path('notes/<int:note_id>/delete/', views.secure_note_delete, name='secure_note_delete'),
    
    path('mfa/setup/', views.mfa_setup, name='mfa_setup'),
    path('mfa/verify/', views.mfa_verify, name='mfa_verify'),
    path('mfa/disable/', views.mfa_disable, name='mfa_disable'),



]
