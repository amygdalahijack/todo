from flask import Flask, Blueprint, g, render_template, flash, redirect, url_for, session, logging, request, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms_alchemy import model_form_factory
from wtforms import StringField, TextAreaField, PasswordField, validators, BooleanField
from passlib.hash import sha256_crypt
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user


app = Flask(__name__)
app.secret_key = "welcometotheclinbrows"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////Users/ferhatguzel/Desktop/todo/todo.db'
db = SQLAlchemy(app)
bootstrap = Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
Base = declarative_base()

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column('user_id', db.Integer, primary_key=True)
    name = db.Column(db.String(20))
    username = db.Column (db.String(20), unique=True)
    email = db.Column (db.String(20), unique=True)
    password = db.Column (db.String(12))
    todos = db.relationship('Todo', backref='user',lazy='dynamic')  
    
class Todo(db.Model):
    __tablename__ = 'todos'
    id = db.Column("todo_id", db.Integer, primary_key=True)   
    title = db.Column(db.String(80))
    complete = db.Column (db.Boolean)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id')) 


def __init__(self , username ,password , email):
        self.username = username
        self.password = password
        self.email = email
        self.registered_on = datetime.utcnow()
 
def is_authenticated(self):
    return True

def is_active(self):
    return True

def is_anonymous(self):
    return False

def get_id(self):
    return unicode(self.id)

def __repr__(self):
    return '<User %r>' % (self.username)
    
@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

@app.before_request
def before_request():
    g.user = current_user

class SignupForm (FlaskForm):   
    name = StringField("Adınız", validators=[validators.input_required(message="İsminizi giriniz.."), validators.length(min=4, max=20)])
    username = StringField ("Kullanıcı Adı", validators=[validators.input_required(message="Lütfen geçerli bir kullanıcı adı giriniz.."), validators.length(min=4, max=20)])
    email = StringField ("E-posta Adresi", validators=[validators.Email(message="Uygun formatta bir e-posta adresi giriniz..")])
    password = PasswordField ("Şifre", validators=[
        validators.input_required(),
        validators.equal_to(fieldname="confirm", message = "Şifre uyuşmuyor.."),
        validators.length(min=4, max=20)
    ])
    confirm = PasswordField("Şifreyi Doğrula")


class LoginForm(FlaskForm):
    username = StringField("Kullanıcı Adı")
    password = PasswordField ("Şifre")
    remember = BooleanField('Beni Hatırla')

@app.route('/dashboard')
@login_required
def dashboard():
    if session["logged_in"]==True:
        todos=Todo.query.filter_by(user_id = g.user.id).all()
    else:
        flash("Please sign in", "danger")
    return render_template('dashboard.html', todos=todos)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(name=form.username.data, username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash("You have successfully signed up..", "success")
        return redirect(url_for("login"))

    return render_template('signup.html', form=form)
    
@app.route("/login", methods = ["GET", "POST"])    
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                flash("You have successfully signed in..", "success")
                session["logged_in"] = True
                
                return redirect(url_for('dashboard'))

        flash("Invalid username or password", "danger")
        return redirect(url_for('login'))

    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


@app.route("/")
def index ():
    return render_template("index.html")


@app.route("/add", methods=["POST"])
@login_required
def addTodo():
    if request.method == 'POST' and session["logged_in"] == True:
        title = request.form.get("title")
        newTodo = Todo(title=title, user_id=g.user, complete=False)
        newTodo.user=g.user
        db.session.add(newTodo)
        db.session.commit()
    else: 
        flash("Invalid username or password", "danger")
        return redirect(url_for('login'))
    session["logged_in"] = True
    return redirect (url_for("dashboard"))

@app.route("/complete/<string:id>")
@login_required
def completeTodo(id):
    todo = Todo.query.filter_by(id=id).first()
    todo.complete = not todo.complete
    db.session.commit()
    session["logged_in"] = True
    return redirect(url_for("dashboard"))

@app.route("/delete/<string:id>")
@login_required
def deleteTodo(id):
    todo = Todo.query.filter_by(id=id).first()
    db.session.delete(todo)
    db.session.commit()
    session["logged_in"] = True
    return redirect(url_for("dashboard"))


    
if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)
