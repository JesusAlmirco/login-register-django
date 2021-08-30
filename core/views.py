from django.shortcuts import render, redirect
from django.contrib.auth import login
# root import form
from . import forms
# Create your views here.
def index(request):
  return render(request, 'index.html')

# Terms and privacy
def terms_privacy(request):
  return render(request, 'terms_privacy.html')

# Register fom
def register(request):
  form = forms.SignUpForm()
  if request.method == 'POST':
    form = forms.SignUpForm(request.POST)

    if form.is_valid():
      email = form.cleaned_data.get('email').lower()

      user = form.save(commit=False)
      user.username = email
      user.save()

      login(request, user)
      return redirect('/')
  return render(request, 'account/register.html', {
    'form': form
  })