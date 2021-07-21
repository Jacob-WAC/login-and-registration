
from flask_app.config.mysqlconnection import connectToMySQL
from flask import flash
from flask_bcrypt import Bcrypt
from flask_app import app
import re
# model the class after the friend table from our database
email_regex = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
zip_regex = re.compile(r'^\d{5}(?:[-\s]\d{4})?$')

bcrypt = Bcrypt(app)


class User:
    def __init__(self, data):
        # place holder data
        self.id = data['id']
        self.first_name = data['first_name']
        self.last_name = data['last_name']
        self.email = data['email']
        self.password = data['password']
        self.address = data['address']
        self.city = data['city']
        self.state = data['state']
        self.zip = data['zip']
        self.subscription = data['subscription']
        self.created_at = data['created_at']
        self.updated_at = data['updated_at']
    # Now we use class methods to query our database

    @classmethod
    def get_all(cls):
        query = "SELECT * FROM users;"
        # make sure to call the connectToMySQL function with the schema you are targeting.
        results = connectToMySQL("users").query_db(query)
        # Create an empty list to append our instances of friends
        users = []
        # Iterate over the db results and create instances of friends with cls.
        for user in results:
            users.append(cls(user))
            print(users[0])
        return users

    @classmethod
    def get_user_by_id(cls, data):

        query = "SELECT * FROM users WHERE id = %(id)s ;"

        results = connectToMySQL('users').query_db(query, data)

        users = []

        for user in results:
            users.append(cls(user))
            print(users[0])
        return users[0]

    @classmethod
    def get_user_by_email(cls, data):

        query = "SELECT * FROM users WHERE email = %(email)s ;"

        results = connectToMySQL('users').query_db(query, data)

        users = []

        for user in results:
            users.append(cls(user))

        return users

    @classmethod
    def save(cls, data):
        query = "INSERT INTO users ( first_name , last_name , email,password,address,city,state,zip,subscription) VALUES ( %(first_name)s , %(last_name)s , %(email)s, %(password)s, %(address)s, %(city)s, %(state)s, %(zip)s, %(subscription)s);"
        return connectToMySQL('users').query_db(query, data)

    @classmethod
    def update(cls, data):
        query = "UPDATE users SET first_name = %(fname)s, last_name = %(lname)s, email = %(email)s WHERE id = %(id)s;"

        connectToMySQL('users').query_db(query, data)

    @classmethod
    def delete(cls, data):
        query = "DELETE FROM users WHERE id = %(id)s;"

        connectToMySQL('users').query_db(query, data)

    # @staticmethod
    # def in_db(check_email):
    #     print(check_email['email'])
    #     is_unique = True
    #     results = Email.get_all()
    #     for email in results:
    #         print(email.email)
    #         if email.email == check_email['email']:
    #             flash('email already in database, please try another.', 'email')
    #             is_unique = False
    #     return is_unique

    @staticmethod
    def validate_registration(data):
        is_valid = True

        if len(data['first_name']) < 2:
            flash('first name must be at least 2 character!', 'first_name')
            is_valid = False

        if len(data['last_name']) < 2:
            flash('last name must be at least 2 character!', 'last_name')
            is_valid = False

        if (not email_regex.match(data['email'])) or (len(data['email']) < 1):
            flash("Please enter a valid email address", 'email')
            is_valid = False

        if len(User.get_user_by_email({'email': data['email']})) != 0:
            flash('email is already in database, enter new email', 'email')
            is_valid = False

        if len(data['password']) < 8:
            flash(
                "Must enter a password that is equal or greater then 8 characters", "password")
            is_valid = False

        if (data['confirm_password'] != data['password']) or (len(data['confirm_password']) < 1):
            flash('confirm password does not match', 'confirm_password')
            is_valid = False

        if len(data['address']) < 1:
            flash('please enter your address', 'address')
            is_valid = False

        if len(data['city']) < 1:
            flash('please enter the name of your city', 'city')
            is_valid = False

        if data["state"] == 'Choose...':
            flash('Must choose a state!', 'state')
            is_valid = False

        if (not zip_regex.match(data['zip'])) or (len(data["zip"]) < 1):
            flash('Please enter valid US zip code', 'zip')
            is_valid = False

        return is_valid
