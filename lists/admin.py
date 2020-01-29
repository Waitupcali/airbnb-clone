from django.contrib import admin
from . import models


@admin.register(models.List)
class ListAdmin(admin.ModelAdmin):

    list_display = (
        "name",
        "user",
        "count_room",
    )

    filter_horizontal = (
        "rooms",
    )

    search_fields = ("name",)
    