# Generated by Django 2.2.5 on 2019-12-28 09:35

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('reviews', '0001_initial'),
    ]

    operations = [
        migrations.RenameField(
            model_name='review',
            old_name='alue',
            new_name='value',
        ),
    ]
