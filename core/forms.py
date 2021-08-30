from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.contrib.auth.forms import PasswordResetForm
from django.core.exceptions import ValidationError

class SignUpForm(UserCreationForm):
  email = forms.EmailField(max_length=250, required=True)
  first_name = forms.CharField(max_length=150, required=True)
  last_name = forms.CharField(max_length=150, required=True)

  class Meta:
    model = User
    fields = ('email', 'first_name', 'last_name', 'password1', 'password2')

  def clean_email(self):
    email = self.cleaned_data['email'].lower()
    if User.objects.filter(email=email):
      raise ValidationError("Esta dirección de correo electrónico ya existe.")
    return email

# Email verification for reset password
class EmailValidationOnForgotPassword(PasswordResetForm):
  def clean_email(self):
    email = self.cleaned_data['email']
    if not User.objects.filter(email__iexact=email, is_active=True).exists():
      raise ValidationError("¡No hay ningún usuario registrado con la dirección de correo electrónico especificada!")
    return email