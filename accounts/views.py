from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from django.views.decorators.cache import cache_page
from django.core.cache import cache
import time
import requests


from django.shortcuts import render,redirect
from django.contrib.auth import authenticate, login , logout
from django.contrib.auth.forms import AuthenticationForm,UserCreationForm
from django.contrib.auth.decorators import login_required
from django.urls import reverse


#from .tasks import sendEmail
# def send_email(request):
#     sendEmail.delay()
#     return HttpResponse("<h1>Done Sending</h1>")


# @cache_page(60)
# def test(request):
#     response = requests.get(
#         "https://b0334311-3948-4555-af18-17d55a318926.mock.pstmn.io/test/delay/5"
#     )
#     return JsonResponse(response.json())



# login & logout & signup with coci & session ->
"""
def login_view(request):
    if not request.user.is_authenticated:
        if request.method == 'POST':
            form = AuthenticationForm(request=request,data=request.POST)
            if form.is_valid():
                username = form.cleaned_data.get('username')
                password = form.cleaned_data.get('password')
                user = authenticate(request, username=username, password=password)
                # from django.shortcuts import get_object_or_404
                # from django.contrib.auth import get_user_model
                # User = get_user_model()
                # user = get_object_or_404(User, email=username, password=password)
            
                if user is not None:
                    login(request,user)
                    return redirect('/')

        form = AuthenticationForm()
        context = {'form':form}
        return render(request,'accounts/login.html',context)
    else:
        return redirect('/')


@login_required
def logout_view(request):
    logout(request)
    return redirect('/')


def signup_view(request):
    if not request.user.is_authenticated:
        if request.method == 'POST':
            form = UserCreationForm(request.POST)
            if form.is_valid():
                form.save()
                return redirect('/')
        form = UserCreationForm()
        context = {'form':form}
        return render(request,'accounts/signup.html',context)
    else:
        return redirect('/')

"""
# <-
