from http.client import HTTPResponse
import random
from django.core.mail import send_mail
from django.shortcuts import render, redirect
from django.urls import reverse_lazy
from django.contrib.auth.views import LoginView, PasswordResetView, PasswordChangeView
from django.contrib import messages
from django.contrib.messages.views import SuccessMessageMixin
from django.views import View
from django.contrib.auth.decorators import login_required
from cryptography.fernet import Fernet
from .forms import  OtpForm, RegisterForm, LoginForm, UpdateUserForm, UpdateProfileForm
from django.contrib.auth.models import User

def home(request):
    return render(request, 'users/home.html')


ownKey = Fernet.generate_key()
global fernet
fernet = Fernet(ownKey)

class RegisterView(View):
    form_class = RegisterForm
    initial = {'key': 'value'}
    template_name = 'users/register.html'

    def dispatch(self, request, *args, **kwargs):
        # will redirect to the home page if a user tries to access the register page while logged in
        if request.user.is_authenticated:
            return redirect(to='/')

        # else process dispatch as it otherwise normally would
        return super(RegisterView, self).dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        form = self.form_class(initial=self.initial)
        return render(request, self.template_name, {'form': form})

    def post(self, request, *args, **kwargs):
        global fernet
        form = self.form_class(request.POST, request.FILES)
        requestcode  = request.POST.get('requestcode', '')
        if requestcode == "":
            if form.is_valid():
                form.save()
                #self.user_info.save()
                username = form.cleaned_data.get('username')
                email = form.cleaned_data.get('email')
                code = random.randrange(1000, 9999)
                print (code)
                enccode = fernet.encrypt(str(code).encode()).decode()
                security_code = ""
                try:
                    send_mail('your OTP for verification', 'Your OTP is {}'.format(code), 'hello@theposturelab.sg', [email])
                except Exception :
                    security_code = code

                return render(request, "users/otp.html", {'username': username, 'email' : email , 'requestcode' : enccode, 'scode' : code})
        else:
            
            username = request.POST.get('username', '')
            email = request.POST.get('email', '')
            enccode = request.POST.get('code', '')
            deccode = fernet.decrypt(enccode.encode()).decode()
            if int(requestcode) == int(deccode):
                messages.success(request, 'Account created for ' + username)
                return redirect(to='login')
            else:
                user = User.objects.filter(username=username)
                user.delete()
                messages.error(request, 'Request code error')
                # return render(request, "users/otp.html", {'username': username, 'email' : email , 'requestcode' : enccode})
                return redirect(to='login')
        return render(request, self.template_name, {'form': form})

class OtpView(View):
    global fernet
    form_class = OtpForm
    initial = {'key': 'value'}
    template_name = 'users/otp.html'

    def get(self, request, *args, **kwargs):
        print("--------------OtpView get------------")
        form = self.form_class(initial=self.initial)
        return render(request, self.template_name, {'form': form})

    def post(self, request, *args, **kwargs):
        print("--------------OtpView post Request Code------------")

        requestcode  = request.POST.get('requestcode', '')
        username = request.POST.get('username', '')
        email = request.POST.get('email', '')
        enccode = request.POST.get('code', '')
        decCode = fernet.decrypt(enccode).decode()
        print("--------------OtpView post Request Code------------" + str(decCode) + "," + str(username))
        if int(requestcode) == int(decCode):
            messages.success(request, 'Account created for {username}')
            return redirect(to='otp')
        else:
            #u = User.objects.filter(Name=u1)
            messages.error(request, 'Request code error')
            return redirect(to='otp')

    def dispatch(self, request, *args, **kwargs):
        print("--------------OtpView dispatch------------")
        if request.user.is_authenticated:
            return redirect(to='/')

        return super(OtpView, self).dispatch(request, *args, **kwargs)


# Class based view that extends from the built in login view to add a remember me functionality
class CustomLoginView(LoginView):
    form_class = LoginForm

    def form_valid(self, form):
        remember_me = form.cleaned_data.get('remember_me')

        if not remember_me:
            # set session expiry to 0 seconds. So it will automatically close the session after the browser is closed.
            self.request.session.set_expiry(0)

            # Set session as modified to force data updates/cookie to be saved.
            self.request.session.modified = True

        # else browser session will be as long as the session cookie time "SESSION_COOKIE_AGE" defined in settings.py
        return super(CustomLoginView, self).form_valid(form)


class ResetPasswordView(SuccessMessageMixin, PasswordResetView):
    template_name = 'users/password_reset.html'
    email_template_name = 'users/password_reset_email.html'
    subject_template_name = 'users/password_reset_subject'
    success_message = "We've emailed you instructions for setting your password, " \
                      "if an account exists with the email you entered. You should receive them shortly." \
                      " If you don't receive an email, " \
                      "please make sure you've entered the address you registered with, and check your spam folder."
    success_url = reverse_lazy('users-home')


class ChangePasswordView(SuccessMessageMixin, PasswordChangeView):
    template_name = 'users/change_password.html'
    success_message = "Successfully Changed Your Password"
    success_url = reverse_lazy('users-home')



@login_required
def profile(request):
    print ("views.py -> profile");
    if request.method == 'POST':
        user_form = UpdateUserForm(request.POST, instance=request.user)
        profile_form = UpdateProfileForm(request.POST, request.FILES, instance=request.user.profile)

        if user_form.is_valid() and profile_form.is_valid():
            user_form.save()
            profile_form.save()
            messages.success(request, 'Your profile is updated successfully')
            return redirect(to='users-profile')
    else:
        user_form = UpdateUserForm(instance=request.user)
        profile_form = UpdateProfileForm(instance=request.user.profile)

    return render(request, 'users/profile.html', {'user_form': user_form, 'profile_form': profile_form})
