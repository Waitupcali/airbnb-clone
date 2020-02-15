from django.urls import path
from . import views

app_name = "lists"

urlpatterns = [
    path("toggle/<int:room_pk>", views.toggle_room, name="toggle_room"),
    path("favs/", views.SeeFavView.as_view(), name="see_favs"),
]
