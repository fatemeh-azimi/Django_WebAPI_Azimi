from django.urls import path, include
from . import views

app_name = 'accounts'

urlpatterns = [
    path('', include('django.contrib.auth.urls')),
    
    path('api/v1/',include('accounts.api.v1.urls')),

    # path('send-email/', views.send_email, name='send-email'),
    # path('test/', views.test, name='test'),
    
    # path('api/v2/', include('djoser.urls')),
    # path('api/v2/', include('djoser.urls.jwt')),



    # login & logout & signup with coci & session ->
    # login ->
    # path('login/', views.login_view,name='login'),
    # logout ->
    # path('logout/', views.logout_view,name='logout'),
    # registration / signup ->
    # path('signup/', views.signup_view,name='signup'),   
]

