from django.contrib.auth import views as auth_views
from core.forms import EmailValidationOnForgotPassword
from django.urls import path
from core import views

urlpatterns = [
  # add index page
  path('', views.index),
  path('terms-privacy/', views.terms_privacy),
  # register and login path
  path('login/', auth_views.LoginView.as_view(template_name="account/login.html"), name="login"),
  path('sign-out/', auth_views.LogoutView.as_view(next_page="/")),
  path('register/', views.register),

  # Recover password path
  path('password-reset/', auth_views.PasswordResetView.as_view(form_class=EmailValidationOnForgotPassword, template_name="account/password_reset.html"), name='password_reset'),
  path('password-reset/done/', auth_views.PasswordResetDoneView.as_view(template_name="account/password_reset_done.html"), name='password_reset_done'),
  path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name="account/password_reset_confirm.html"), name='password_reset_confirm'),
  path('reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name="account/password_reset_complete.html"), name='password_reset_complete'),
]