from rest_framework import serializers
from .models import Account
import re
# from rest_framework.exceptions import 

class RegistrationSerializer(serializers.ModelSerializer):

    class Meta:
        model = Account
        fields = ["email", "password"]

    def validate_password(self, value):
        if len(value) < 8:
            raise serializers.ValidationError("This password is too short. It must contain at least 8 characters.", 400)

        if value.isalpha() or value.isnumeric():
            raise serializers.ValidationError("password must be alphanumeric", 400)

        if not re.search(r"[^a-zA-Z0-9]", value):
            raise serializers.ValidationError("Password must contain at least one special character.", 400)
            

    def validate_emailadd(self, value):
        if Account.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email is already in use.", 400)
        return value
    
    def create(self, validated_data):
        # Create the user instance
        user = Account(
            email=validated_data['email'],
            username=validated_data['email']
        )

        # Set the password using Django's make_password
        user.set_password(validated_data['password'])


        # Save the user instance
        user.save()

        return user