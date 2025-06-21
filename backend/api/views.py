from django.http import JsonResponse, HttpResponse, HttpResponseForbidden
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.generics import CreateAPIView
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import CustomTokenObtainPairSerializer, ProjectSerializer
from api.models import Project, User, UserProject, ProjectRole
from api.serializers import UserSerializer
from rest_framework import status
from django.core.mail import send_mail
from django.conf import settings
from django.db import connection
from rest_framework.decorators import api_view
from rest_framework.response import Response

import os
from django.shortcuts import redirect, HttpResponse
from google_auth_oauthlib.flow import Flow
from django.contrib.auth.decorators import login_required
from datetime import datetime, timezone
from google.oauth2.credentials import Credentials
import json
from googleapiclient.discovery import build

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLIENT_SECRETS_FILE = os.path.join(BASE_DIR, 'api', 'client_secret.json')

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # permite HTTP inseguro para dev local


def google_calendar_init_view(request):
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=['https://www.googleapis.com/auth/calendar'],
        redirect_uri='http://localhost:8000/api/google-calendar/redirect/'
    )
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'
    )
    request.session['state'] = state
    return redirect(authorization_url)

def google_calendar_redirect_view(request):
    state = request.session.get('state')

    if not state:
        return HttpResponseForbidden('Missing OAuth state in session.')

    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=['https://www.googleapis.com/auth/calendar'],
        state=state,
        redirect_uri='http://localhost:8000/api/google-calendar/redirect/'
    )

    authorization_response = request.build_absolute_uri()
    flow.fetch_token(authorization_response=authorization_response)

    credentials = flow.credentials

    request.session['google_token'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri, #type:ignore
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

    return redirect('http://localhost:5173/home/calendario')


def google_calendar_is_connected(request):
    # Aqui você deve verificar se o token está salvo para o usuário (na sessão, banco ou cache)
    token = request.session.get('google_token')
    connected = token is not None
    return JsonResponse({'connected': connected})



def google_calendar_events(request):
    token_json = request.session.get('google_token')
    if not token_json:
        return HttpResponseForbidden('Usuário não conectado ao Google Calendar')

    # Aqui sim, faz o loads pois token_json é string
    token_info = json.loads(token_json)

    creds = Credentials.from_authorized_user_info(token_info)

    service = build('calendar', 'v3', credentials=creds)

    now = datetime.now(timezone.utc).isoformat()
    events_result = service.events().list(
        calendarId='primary', timeMin=now,
        maxResults=10, singleEvents=True,
        orderBy='startTime'
    ).execute()
    events = events_result.get('items', [])

    return JsonResponse({'items': events})

# Na view a gente faz o tratamento do que a url pede. Depende se for get, post, update.
# Sempre retorne em JSON pro front conseguir tratar bem
class RegisterView(CreateAPIView):
    queryset = User.objects.all()  # Pega todos os usuários do banco de dados
    serializer_class = UserSerializer  # Serializa os dados do usuário
    permission_classes = [AllowAny]  # Permite acesso a qualquer usuário, mesmo não autenticado


class LoginView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

class HomeView(APIView):
    permission_classes = [IsAuthenticated]
    print('chega no home view')

    def get(self, request):
        print("Usuário autenticado:", request.user)
        print("Email do usuário:", request.user.email)
        print("Username:", request.user.username)
        print("Dados completos do usuário:", UserSerializer(request.user).data)

        serializer = UserSerializer(request.user)
        return Response(serializer.data)
    
class ProjectView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        projetos = Project.objects.filter(userproject__user=request.user)
        serializer = ProjectSerializer(projetos, many=True)
        return Response(serializer.data)

    def post(self, request):
        print("Dados recebidos no POST:", request.data)
        serializer = ProjectSerializer(data=request.data)
        if serializer.is_valid():
            project = serializer.save()
            UserProject.objects.create(
                user=request.user,
                project=project,
                role=ProjectRole.LEADER  # ou ProjectRole.MEMBER se quiser padrão
            )

            collaborator_emails = request.data.get('collaborators', [])
            for email in collaborator_emails:
                try:
                    found_user = User.objects.get(email=email)
                    UserProject.objects.create(user=found_user, project=project, role=ProjectRole.MEMBER)
                except User.DoesNotExist:
                    print(f"Usuário com email: {email} não encontrado. Enviando convite")
                    subject = "Você foi convidado para colaborar em um projeto!"
                    message = f"Olá!\n\nVocê foi convidado para colaborar no projeto '{project.name}' na nossa plataforma. " \
                              f"Se você ainda não tem uma conta, por favor, registre-se usando este e-mail para ter acesso ao projeto." \
                              f"\n\nLink do projeto: http://localhost:5173/register"
                    from_email = settings.DEFAULT_FROM_EMAIL
                    recipient_list = [email]
                    
                    try:
                        send_mail(subject, message, from_email, recipient_list, fail_silently=False)
                        print(f"Convite enviado para: {email}")
                    except Exception as e:
                        print(f"Falha ao enviar convite para: {email}: {e}")
            
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class ProjectCollaboratorsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, project_id):
        try:
            project = Project.objects.get(pk=project_id)
        except Project.DoesNotExist:
            return Response({"error": "Project not found"}, status=status.HTTP_404_NOT_FOUND)

        user_projects = UserProject.objects.filter(project=project).select_related('user')
        users = [up.user for up in user_projects]
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

