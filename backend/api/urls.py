from django.urls import path
from .views import RegisterView, LoginView, HomeView, ProjectView, ProjectCollaboratorsView

from . import views

urlpatterns = [
    path('google-calendar/init/', views.google_calendar_init_view, name='google_calendar_init'),
    path('google-calendar/redirect/', views.google_calendar_redirect_view, name='google_calendar_redirect'),

    path("register/", RegisterView.as_view(), name="register"),
    path("login/", LoginView.as_view(), name="login"),
    path("home/", HomeView.as_view(), name='home'),
    path('projetos/', ProjectView.as_view(), name='projetos'),
    path('projetos/<int:project_id>/collaborators/', ProjectCollaboratorsView.as_view(), name='project-collaborators'),
]


