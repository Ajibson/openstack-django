# Generated by Django 5.1.3 on 2024-12-04 19:29

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='account',
            name='token_created_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='account',
            name='token_expires_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
