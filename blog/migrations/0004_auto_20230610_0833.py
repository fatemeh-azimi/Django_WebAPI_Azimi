# Generated by Django 3.2.16 on 2023-06-10 15:33

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('blog', '0003_auto_20230609_0016'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='post',
            name='login_require',
        ),
        migrations.RemoveField(
            model_name='post',
            name='tags',
        ),
    ]