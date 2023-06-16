from django.urls import path, include
from . import views
from rest_framework_simplejwt.views import (TokenObtainPairView, TokenRefreshView, TokenVerifyView)
#from rest_framework.authtoken.views import ObtainAuthToken


app_name = 'api-v1'

#example for DefaultRouter ->
#router = DefaultRouter()
#router.register("post", views.PostViewSet, basename="post")
#router.register("category", views.CategoryModelViewSet, basename="category")
#urlpatterns = router.urls


urlpatterns = [
    # ACCOUNTS   -> 
    # registration
    path('registration/', views.RegistrationApiView.as_view(), name='registration'),
    path('register/', views.RegisterApiView.as_view(), name='register'),
    path('register/email-verify/', views.VerifyEmailApiView.as_view(), name='email_verify'),
    path('register/email-verify/resend/', views.ResendVerifyEmailApiView.as_view(), name='email_verify'),

    path('test-email', views.TestEmailSend.as_view(), name='test-email'),
    
    # activation
    path('activation/confirm/<str:token>', views.ActivationApiView.as_view(), name='activation'),

    # resend activation
    path('activation/resend/', views.ActivationResendApiView.as_view(), name='activation-resend'),

    # login token
    path('token/login/', views.CustomObtainAuthToken.as_view(), name='token-login'),
    path('token/logout/', views.CustomDiscardAuthToken.as_view(), name='token-logout'),
    path('token/obtain/login/', views.ObtainTokenApiView.as_view(),name='token_obtain'),
    
    # change password
    path('change-password/', views.ChangePasswordApiView.as_view(), name='change-password'),
    # path('change-password/', views.ChangePasswordView.as_view(), name='change-password'),
    # reset password
    path('reset-password/', views.PasswordResetRequestEmailApiView.as_view(),name='reset-password-request'),
    path('reset-password/validate-token/', views.PasswordResetTokenValidateApiView.as_view(),name='reset-password-validate'),
    path('reset-password/set-password/', views.PasswordResetSetNewApiView.as_view(),name='reset-password-confirm'),

    # login jwt
    # path('jwt/create/', views.CustomTokenObtainPairView.as_view(), name='jwt-create'),
    # path('jwt/create/', TokenObtainPairView.as_view(), name='jwt-create'),
    path('jwt/create/', views.JWTObtainPairTokenApiView.as_view()),
    path('jwt/refresh/', TokenRefreshView.as_view(), name='jwt-refresh'),
    path('jwt/verify/', TokenVerifyView.as_view(), name='jwt-verify'),
    

    # PROFILE ->
    # profile
    path('profile/', views.ProfileApiView.as_view(), name='profile'),
    
]

