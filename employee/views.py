from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User
from .serializers import RegisterSerializer, LoginSerializer, ForgotPasswordSerializer
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_decode
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth import get_user_model

User = get_user_model()

class RegisterView(APIView):
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            user.is_active = False  
            user.save()

            # Generate email verification token
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))

            # Send email verification link
            current_site = get_current_site(request)
            verification_link = f"http://{current_site.domain}/api/verify-email/{uid}/{token}/"

            mail_subject = 'Activate your account'
            message = f"Hello {user.name},\n\n" \
                      f"Thank you for registering. Please click the link below to verify your email address and activate your account:\n" \
                      f"{verification_link}\n\n" \
                      f"If you did not make this request, please ignore this email.\n\n" \
                      f"Best regards,\n" \
                      f"Your Company Name"

            send_mail(
                mail_subject,
                message,
                'mamlapaani@gmail.com',   
                [user.email],
                fail_silently=False,
            )

            return Response({"detail": "A verification email has been sent to your email address."}, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            
            # Use custom authentication
            user = authenticate(request, email=email, password=password)
            if user:
                refresh = RefreshToken.for_user(user)
                return Response({
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                }, status=status.HTTP_200_OK)
            else:
                user_exists = User.objects.filter(email=email).exists()
                if user_exists:
                    return Response({'detail': 'Password is incorrect'}, status=status.HTTP_401_UNAUTHORIZED)
                else:
                    return Response({'detail': 'User does not exist'}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LogoutView(APIView):
    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response(status=status.HTTP_400_BAD_REQUEST)

class ForgotPasswordView(APIView):
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                return Response({"detail": "User with this email does not exist."}, status=status.HTTP_404_NOT_FOUND)

            # Generate password reset token
            token_generator = PasswordResetTokenGenerator()
            token = token_generator.make_token(user)
            uid = urlsafe_base64_encode(force_bytes(user.pk))

            # Create password reset link
            current_site = get_current_site(request)
            reset_link = f"http://{current_site.domain}/api/reset-password/{uid}/{token}/"

            # Send password reset email
            mail_subject = 'Reset your password'
            message = f"Hello {user.name},\n\n" \
                      f"We received a request to reset your password. Click the link below to reset your password:\n" \
                      f"{reset_link}\n\n" \
                      f"If you did not make this request, please ignore this email.\n\n" \
                      f"Best regards,\n" \
                      f"Your Iron Man"

            send_mail(
                mail_subject,
                message,
                'mamlapaani@gmail.com',   
                [email],
                fail_silently=False,
            )

            return Response({"detail": "Password reset link sent to your email."}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class VerifyEmailView(APIView):
    def get(self, request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if user is not None and default_token_generator.check_token(user, token):
            user.is_active = True
            user.save()
            return Response({"detail": "Email verified successfully. You can now log in."}, status=status.HTTP_200_OK)
        else:
            return Response({"detail": "Invalid verification link."}, status=status.HTTP_400_BAD_REQUEST)


class ResetPasswordView(APIView):
    def post(self, request, uidb64, token):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({"detail": "Invalid or expired password reset link."}, status=status.HTTP_400_BAD_REQUEST)

        # Check if the token is valid
        token_generator = PasswordResetTokenGenerator()
        if not token_generator.check_token(user, token):
            return Response({"detail": "Invalid or expired password reset link."}, status=status.HTTP_400_BAD_REQUEST)

        
        new_password = request.data.get("new_password")
        if not new_password:
            return Response({"detail": "New password is required."}, status=status.HTTP_400_BAD_REQUEST)

        # Set new password
        user.set_password(new_password)
        user.save()

        return Response({"detail": "Password has been reset successfully."}, status=status.HTTP_200_OK)
