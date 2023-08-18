import streamlit as st
import json
import os
import hashlib

def signup_():
    st.write("Create a new account\n")
    username = st.text_input("New_Username")
    password = st.text_input("New_Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")
    if st.button("Signup"):
        if password == confirm_password:
            with open("users.json", "r") as f:
                users = json.load(f)

            if username in users:
                st.error("Username already exists")
            else:
                password_hash = hashlib.sha256(password.encode()).hexdigest()
                users[username] = password_hash
                with open("users.json", "w") as f:
                    json.dump(users, f)
                os.makedirs(f"user_data2/{username}")
                st.success("Account created!")
                st.button('Login',login_())
                st.button('Sign up',signup_())
        else:
            st.error("Passwords do not match")  
                   
                     
def login_():
    st.write("Login to your account\n")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        with open("users.json", "r") as f:
            users = json.load(f)

        if username in users:
            # Hash the user-provided password using SHA-256
            password_hash = hashlib.sha256(password.encode()).hexdigest()

            if users[username] == password_hash:
                st.success("Logged in!")
                st.write(f"Welcome, {username}!")
                st.experimental_set_query_params(Login=True, username=username, original_url=st.experimental_get_query_params().get("original_url", [""])[0])  
                st_button('Login',login_())
                st_button('Sign up',signup_())
            else:
                st.error("Invalid password")
        else:
            st.error("Invalid username")
     
    return None

#menu=["Login","Signup"]

if "Login" not in st.experimental_get_query_params():
    choice= st.sidebar.selectbox('login/Signup',['Login', 'Sign up'])

    if choice == "Login":
        login_()
    else:
        signup_()
# with s.expander:
#     if(s.button(text='Login')):
        
