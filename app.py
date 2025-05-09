import math
from flask import Flask, abort,render_template,redirect, flash,request, url_for, session,get_flashed_messages,flash 
from dotenv import load_dotenv 
from sqlalchemy import func , and_, or_, not_, select
from flask_login import LoginManager, login_user, login_required, current_user, logout_user 
from werkzeug.security import generate_password_hash, check_password_hash 
import logging
from sqlalchemy.exc import IntegrityError 
from werkzeug.utils import secure_filename

from functools import wraps
import os

from models import db,User,ParkingLot,ParkingSpot,ReserveParkingSpot
from forms import LoginForm,RegisterForm
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'secret_key'

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

with app.app_context():
    db.create_all()
    User.create_admin()  

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
   return render_template('index.html')

@app.route('/register',methods=['GET','POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        NewUser = User(name = form.name.data,email= form.email.data,password=form.password.data)
        db.session.add(NewUser)
        db.session.commit()
        flash("Registration Successful","success")
        return redirect(url_for('login'))
    return render_template('registration.html',form=form)    

@app.route('/login',methods=['GET','POST'])
def login():
        form  = LoginForm()
        if form.validate_on_submit():
            email = request.form['email']
            password = request.form['password']
            user = User.query.filter_by(email=form.email.data).first()
            if user and user.check_password(password):
                session['name']=user.name
                session['email']=user.email
                session['password']=user.password
                login_user(user)
                return redirect(url_for('admin_dashboard' if user.is_admin else 'user_dashboard'))
            flash("Invalid User credentials","danger")    
        return render_template('login.html',form=form)                 


@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return redirect(url_for('user_dashboard'))
    return render_template('admin_dashboard.html')    

@app.route('/user/dashboard')
@login_required
def user_dashboard():
    return render_template('user_dashboard.html')    

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))    
    
if __name__ == '__main__':
    app.run(debug=True)
