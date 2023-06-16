from rest_framework import generics, status, views, mixins
from rest_framework.response import Response
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.views import TokenObtainPairView
from django.shortcuts import get_object_or_404
from mail_templated import send_mail, EmailMessage
from rest_framework_simplejwt.tokens import RefreshToken
import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidSignatureError
from django.conf import settings
from .serializers import (RegisterSerializer, RegistrationSerializer, EmailVerificationSerializer, 
                          ResendVerifyTokenSerializer, CustomAuthTokenSerializer, ObtainTokenSerializer,
                          CustomTokenObtainPairSerializer, ChangePasswordSerialier,  ChangePasswordSerializer2,
                          PasswordResetRequestEmailSerializer, PasswordResetTokenVerificationSerializer, 
                          SetNewPasswordSerializer, JWTObtainPairTokenSerializer,
                            ProfileSerializer, ActivationResendSerializer)
#from .serializers import *
from ...models import Profile
from ..utils import EmailThread, Util
from rest_framework.serializers import Serializer
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from blog.models import Post, Category


from django.contrib.auth import get_user_model
User = get_user_model()

'''
class RegisterApiView(generics.GenericAPIView):
    """Creates new user with the given info and credentials"""
    serializer_class = RegisterSerializer
    
    def post(self, request, *args, **kwargs):
        """
        Register class
        """
        serializer = RegisterSerializer(data=request.data, many=False)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
'''

class RegisterApiView(generics.GenericAPIView):

    serializer_class = RegisterSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            serializer.save()
            user = User.objects.get(email=serializer.validated_data['email'])
            token = RefreshToken.for_user(user).access_token
            current_site = get_current_site(request).domain
            relativeLink = reverse('accounts:email_verify')
            absurl = 'http://'+current_site+relativeLink+"?token="+str(token)
            # email_body = 'Hi '+user.email + \
            #     ' Use the link below to verify your email \n' + absurl
            # data = {'email_body': email_body, 'to_email': user.email,
            #         'email_subject': 'Verify your email'}
            #  Util.send_email(data)
            data = {'email':user.email,"link":absurl,"site":current_site}
            Util.send_templated_email('emails/verification_template.html',data)
            return Response(serializer.data, status=status.HTTP_201_CREATED)


class RegistrationApiView(generics.GenericAPIView):
    serializer_class = RegistrationSerializer
    
    def post(self, request, *args, **kwargs):
        serializer = RegistrationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            email = serializer.validated_data['email']
            data = {'email': email}
            user_obj = get_object_or_404(User, email=email)
            token = self.get_tokens_for_user(user_obj)
            email_obj = EmailMessage('email/activation_email.tpl',{'token': token},'f.s.a.2001.a.s.f@gmail.com',to=[email],)
            EmailThread(email_obj).start()
            return Response(data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def get_tokens_for_user(self, user):
        refresh = RefreshToken.for_user(user)
        return str(refresh.access_token)
        


class VerifyEmailApiView(generics.GenericAPIView):
    serializer_class = EmailVerificationSerializer
    
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]
        if not user.is_verified:
            user.is_verified = True
            user.save()
        return Response({"detail":"user verified successfully"},status=status.HTTP_200_OK)


class ResendVerifyEmailApiView(generics.GenericAPIView):
    serializer_class = ResendVerifyTokenSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data["instance"]
            token = RefreshToken.for_user(user).access_token
            current_site = get_current_site(request).domain
            relativeLink = reverse('accounts:email_verify')
            absurl = 'http://'+current_site+relativeLink+"?token="+str(token)
            # email_body = 'Hi '+user.email + \
            #     ' Use the link below to verify your email \n' + absurl
            # data = {'email_body': email_body, 'to_email': user.email,
            #         'email_subject': 'Verify your email'}
            # data = {'email':user.email,"link":absurl,"site":current_site}
            #  Util.send_email(data)
            data = {'email':user.email,"link":absurl,"site":current_site}
            Util.send_templated_email('emails/verification_template.html',data)
           
            return Response({"details":"verification mail has been sent"}, status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CustomObtainAuthToken(ObtainAuthToken):
    serializer_class = CustomAuthTokenSerializer
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        return Response({'token': token.key, 'user_id': user.pk, 'email': user.email})


class ObtainTokenApiView(generics.CreateAPIView):
    serializer_class = ObtainTokenSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data,
                                           context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        token, created = Token.objects.get_or_create(user=user)
        return Response({
            'token': token.key,
            'user_id': user.pk,
            'email': user.email
        })


class CustomDiscardAuthToken(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request, format=None):
        request.user.auth_token.delete()
        return Response({"details": "token successfully removed"}, status=status.HTTP_204_NO_CONTENT)


class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

class JWTObtainPairTokenApiView(generics.CreateAPIView):
    serializer_class = JWTObtainPairTokenSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        refresh = RefreshToken.for_user(user)
        return Response({'access': str(refresh.access_token), 'refresh': str(refresh), 'user_id': user.pk, 'email': user.email})


class ChangePasswordApiView(generics.GenericAPIView):
    model = User
    permission_classes = [IsAuthenticated]
    serializer_class = ChangePasswordSerialier
    
    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def put(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            # Check old password
            if not self.object.check_password(serializer.data.get("old_password")):
                return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST,)
            # set_password also hashes the password that the user will get
            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()
            return Response({"details": "password changed successfully"}, status=status.HTTP_200_OK,)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
'''
class ChangePasswordView(mixins.UpdateModelMixin, generics.GenericAPIView):
    """
    An endpoint for changing password.
    """
    serializer_class = ChangePasswordSerializer2
    permission_classes = (IsAuthenticated,)

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def put(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            # Check old password
            if not self.object.check_password(serializer.data.get("old_password")):
                return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
            # set_password also hashes the password that the user will get
            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()
            response = {'details': 'Password updated successfully',}
            return Response(response)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
'''


class PasswordResetRequestEmailApiView(generics.GenericAPIView):
    serializer_class = PasswordResetRequestEmailSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]
        token = RefreshToken.for_user(user).access_token
        relativeLink = "/accounts/reset-password" #reverse('accounts:password-reset-confirm')
        current_site = get_current_site(
            request=request).domain
        absurl = 'http://'+current_site+relativeLink+"?token="+str(token)
        # email_body = 'Hi '+user.email + \
        #         'Use the link below to reset your password \n' + absurl
        # data = {'email_body': email_body, 'to_email': user.email,
        #             'email_subject': 'Verify your email'}

        # Util.send_email(data)
        data = {'email':user.email,"link":absurl,"site":current_site}
        Util.send_templated_email('emails/reset_password_template.html',data)
        return Response({'success': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)


class PasswordResetTokenValidateApiView(mixins.RetrieveModelMixin, generics.GenericAPIView):
    serializer_class = PasswordResetTokenVerificationSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response({"detail":"Token is valid"},status=status.HTTP_200_OK)


class PasswordResetSetNewApiView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'detail': 'Password reset successfully'}, status=status.HTTP_200_OK)


class ProfileApiView(generics.RetrieveUpdateAPIView):
    serializer_class = ProfileSerializer
    queryset = Profile.objects.all()
    permission_classes = [IsAuthenticated]

    def get_object(self):
        queryset = self.get_queryset()
        obj = get_object_or_404(queryset, user=self.request.user)
        return obj
    
    def my_posts(self):
        my_posts = Post.objects.filter(author = self.request.user)
        return my_posts

    

class TestEmailSend(generics.GenericAPIView):
    def get(self, request, *args, **kwargs):
        self.email = 'test1@test.com'
        user_obj = get_object_or_404(User, email=self.email)
        token = self.get_tokens_for_user(user_obj)
        email_obj = EmailMessage('email/hello.tpl', {'token': token}, 'azimi@test.com', to=[self.email],)
        EmailThread(email_obj).start()
        return Response('email sent')

    def get_tokens_for_user(self, user):
        refresh = RefreshToken.for_user(user)
        return str(refresh.access_token)


class ActivationApiView(APIView):
    def get(self, request, token, *args, **kwargs):
        try:
            token = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = token.get('user_id')
        except ExpiredSignatureError:
            return Response({'details': 'token has been expired'}, status=status.HTTP_400_BAD_REQUEST)
        except InvalidSignatureError:
            return Response({'details': 'token is not valid'}, status=status.HTTP_400_BAD_REQUEST)
        user_obj = User.objects.get(pk=user_id)
        if user_obj.is_verified:
            return Response({'details': 'your account has already been verified'})
        user_obj.is_verified = True
        user_obj.save()
        return Response({'details': 'your account have been verified and activated successfully'})


class ActivationResendApiView(generics.GenericAPIView):
    serializer_class = ActivationResendSerializer

    def post(self, request, *args, **kwargs):
        serializer = ActivationResendSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user_obj = serializer.validated_data['user']
        token = self.get_tokens_for_user(user_obj)
        email_obj = EmailMessage('email/activation_email.tpl', {'token': token}, 
                                 'admin@admin.com', to=[user_obj.email])
        EmailThread(email_obj).start()
        return Response({'details': 'user activation resend successfully'}, status=status.HTTP_200_OK)

    def get_tokens_for_user(self, user):
        refresh = RefreshToken.for_user(user)
        return str(refresh.access_token)


