# Generated by Django 2.2.5 on 2019-12-29 07:57

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('reservations', '0002_auto_20191228_2217'),
    ]

    operations = [
        migrations.RenameField(
            model_name='reservation',
            old_name='geust',
            new_name='guest',
        ),
    ]