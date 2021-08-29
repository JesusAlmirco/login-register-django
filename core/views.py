from django.shortcuts import render, redirect
from django.views import View
import json
from django.http import JsonResponse
from django.contrib.auth.models import User
# email validator module
from validate_email import validate_email
from django.contrib import messages, auth
from django.core.mail import EmailMessage
from django.utils.encoding import force_bytes, force_text, DjangoUnicodeDecodeError
from django.core.mail import send_mail
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from .utils import account_activation_token
from django.urls import reverse

from django.contrib.auth.tokens import PasswordResetTokenGenerator
import threading

# Home
class HomeView(View):
  def get(self, request):
    return render(request, 'home.html')

# Email thread
class EmailThread(threading.Thread):

  def __init__(self, email):
    self.email = email
    threading.Thread.__init__(self)

  def run(self):
    self.email.send(fail_silently=False)

# Validate Email
class EmailValidationView(View):
  def post(self, request):
    data = json.loads(request.body)
    email = data['email']
    if not validate_email(email):
      return JsonResponse({'email_error': 'El correo electrónico es invalido.'}, status=400)
    if User.objects.filter(email=email).exists():
      return JsonResponse({'email_error': 'Correo electrónico en uso, elija otro.'}, status=409)
    return JsonResponse({'email_valid': True})

# Validate username
class UsernameValidationView(View):
  def post(self, request):
    data = json.loads(request.body)
    username = data['username']
    if not str(username).isalnum():
      return JsonResponse({'username_error': 'El nombre de usuario solo debe contener caracteres alfanuméricos.'}, status=400)
    if User.objects.filter(username=username).exists():
      return JsonResponse({'username_error': 'Nombre de usuario en uso, elija otro.'}, status=409)
    return JsonResponse({'username_valid': True})

# Registration.
class RegistrationView(View):
  def get(self, request):
    return render(request, 'accounts/register.html')
  
  def post(self, request):
    # GET USER DATA
    # VALIDATE
    # create a user account

    username = request.POST['username']
    first_name = request.POST['first_name']
    last_name = request.POST['last_name']
    email = request.POST['email']
    password = request.POST['password']

    context = {
      'fieldValues': request.POST
    }

    if not User.objects.filter(username=username).exists():
      if not User.objects.filter(email=email).exists():
        if len(password) < 6:
          messages.error(request, 'Contraseña demasiado corta')
          return render(request, 'authentication/register.html', context)

        user = User.objects.create_user(username=username, email=email)
        user.set_password(password)
        user.first_name = first_name
        user.last_name = last_name
        user.is_active = False
        user.save()
        current_site = get_current_site(request)
        email_body = {
          'user': user,
          'domain': current_site.domain,
          'uid': urlsafe_base64_encode(force_bytes(user.pk)),
          'token': account_activation_token.make_token(user),
        }

        link = reverse('activate', kwargs={'uidb64': email_body['uid'], 'token': email_body['token']})

        email_subject = 'Activa tu cuenta'

        activate_url = 'http://'+current_site.domain+link

        email = EmailMessage(
          email_subject,
          'Hola '+user.username + ', haz click en el enlace a continuación para activar su cuenta \n'+activate_url,
          'noreply@higolearn.com',
          [email],
        )
        email.send(fail_silently=False)
        messages.success(request, 'Cuenta creada con éxito')
        return render(request, 'accounts/register.html')

    return render(request, 'accounts/register.html')

# Verification
class VerificationView(View):
  def get(self, request, uidb64, token):
    try:
      id = force_text(urlsafe_base64_decode(uidb64))
      user = User.objects.get(pk=id)

      if not account_activation_token.check_token(user, token):
        return redirect('login'+'?message='+'User already activated')

      if user.is_active:
        return redirect('login')
      user.is_active = True
      user.save()

      messages.success(request, 'Cuenta activada con éxito')
      return redirect('login')

    except Exception as ex:
      pass

    return redirect('login')

# validate login with email
def authenticate_user(email, password):
  try:
    user = User.objects.get(email=email)
  except User.DoesNotExist:
    return None
  else:
    if user.check_password(password):
      return user

  return None

# Login
class LoginView(View):
  def get(self, request):
    return render(request, 'accounts/login.html')

  def post(self, request):
    email = request.POST['email']
    password = request.POST['password']

    if email and password:
      # user = auth.authenticate(username=username, password=password)
      user = authenticate_user(email, password)

      if user:
        if user.is_active:
          auth.login(request, user)
          messages.success(request, 'Bienvenido, ' + user.username+' estás conectado')
          return redirect('home')
        messages.error(
          request, 'Su cuenta no está activa, por favor revise su correo electrónico')
        return render(request, 'accounts/login.html')
      messages.error(
        request, 'Credenciales no válidas, inténtalo de nuevo')
      return render(request, 'accounts/login.html')

    messages.error(
      request, 'Por favor completa los espacios')
    return render(request, 'account/login.html')
        
# Sign out
class LogoutView(View):
  def post(self, request):
    auth.logout(request)
    messages.success(request, 'Sesión cerrada correctamente')
    return redirect('login')

# Reset password
class RequestPasswordResetEmail(View):
  def get(self, request):
    return render(request, 'accounts/reset-password.html')

  def post(self, request):
    email = request.POST['email']
    context = {
      'values' : request.POST
    }

    if not User.objects.filter(email=email).exists():
      messages.error(request, 'Correo electrónico no válido')
      return render(request, 'accounts/reset-password.html', context)
    
    current_site = get_current_site(request)

    user = User.objects.filter(email=email)

    if user.exists():
      email_contents ={
        'user': user[0],
        'domain': current_site.domain,
        'uid': urlsafe_base64_encode(force_bytes(user[0].pk)),
        'token': PasswordResetTokenGenerator().make_token(user[0])
      }

      link = reverse('reset-user-password', kwargs={'uidb64': email_contents['uid'], 'token': email_contents['token']})

      email_subject = 'Restablecer su Contraseña'

      reset_url = 'http://'+current_site.domain+link

      email = EmailMessage(
        email_subject,
        'Hola, haga clic en el enlace de abajo para restablecer su contraseña \n'+reset_url,
        'noreply@higolearn.com',
        [email],
      )
      EmailThread(email).start()

    messages.success(request, 'Le hemos enviado un correo electrónico para restablecer')
    return render(request, 'accounts/reset-password.html')

# Completed reset
class CompletePasswordReset(View):
  def get(self, request, uidb64, token):

    context={
      'uidb64':uidb64,
      'token':token
    }
    
    
    try:
      user_id = force_text(urlsafe_base64_decode(uidb64))
      user=User.objects.get(pk=user_id)
      if not PasswordResetTokenGenerator().check_token(user, token):
        messages.info(request, 'El enlace de restablecimiento no es válido, solicite uno nuevo')
        return render(request, 'accounts/reset-password.html')
    except Exception as identifier:
      pass
    
    return render(request, 'accounts/set-new-password.html', context)

  def post(self, request, uidb64, token):

    context={
      'uidb64':uidb64,
      'token':token
    }

    password = request.POST['password']
    password2 = request.POST['password2']

    if password != password2:
      messages.error(request, 'La contraseña no coincide')
      return render(request, 'accounts/set-new-password.html', context)

    if len(password) < 6:
      messages.error(request, 'Contraseña demasiado corta')
      return render(request, 'accounts/set-new-password.html', context)
  
    try:
      user_id = force_text(urlsafe_base64_decode(uidb64))
      user=User.objects.get(pk=user_id)
      user.set_password(password)
      user.save()
      messages.success(request, 'Restablecimiento de contraseña exitoso')
      return redirect('login')
    except Exception as identifier:
      messages.info(request, 'Algo salió mal, intenta de nuevo')
      return render(request, 'accounts/set-new-password.html', context)

    return render(request, 'accounts/set-new-password.html', context)