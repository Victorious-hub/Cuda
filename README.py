from flask import Flask,render_template,url_for,request,flash,redirect,abort,Blueprint, send_from_directory,jsonify
from jinja2 import Template,Environment,FileSystemLoader
from markupsafe import escape
import sqlite3 as sq
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager,UserMixin,current_user,login_user,login_required,logout_user
from flask_wtf import FlaskForm,Recaptcha,RecaptchaField
from wtforms import StringField, SubmitField, TextAreaField,FileField,PasswordField
from flask_wtf.file import FileField,FileAllowed
from wtforms.validators import ValidationError,DataRequired, Email,Length,EqualTo
from werkzeug.utils import secure_filename
from werkzeug.datastructures import  FileStorage
from flask_bcrypt import Bcrypt
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_mail import Mail,Message
from flask_recaptcha import ReCaptcha
from elasticsearch import Elasticsearch
from flask_uploads import IMAGES,configure_uploads,UploadSet
from cloudipsp import Api, Checkout
from flask_restful import Api,Resource,fields,marshal_with
from flask_marshmallow import Marshmallow
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
from flask_bootstrap import Bootstrap
from datetime import datetime
app = Flask(__name__)
db = SQLAlchemy(app)
login = LoginManager()
login.init_app(app)
recaptcha = ReCaptcha(app)
app.config['SECRET_KEY']  ='qewwfjqkwopr3i91u8ygi3124t53rgerhy'
app.config['RECAPTCHA_PUBLIC_KEY'] = '6LexA5IhAAAAALVxNUEulSI6w5_2o3RX-OopC0TP'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LexA5IhAAAAABRWx_a4eppLOurnL4jS0LBYPNLm'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///info.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
Bootstrap(app)
class User(UserMixin,db.Model):
    id = db.Column(db.Integer,primary_key = True)
    nick = db.Column(db.Text,nullable = False)
    email = db.Column(db.Text,nullable = False)
    password = db.Column(db.Integer,nullable = False)
    confirm_p = db.Column(db.Integer,nullable = False)
    note = db.relationship('Post_data',backref='author',lazy = True)
    def __repr__(self):
       return '<Article %r>' % self.id
class Post_data(UserMixin,db.Model):
    id = db.Column(db.Integer,primary_key = True)
    title = db.Column(db.Text,nullable = False)
    content = db.Column(db.Text,nullable = False)
    date_posted = db.Column(db.DateTime,nullable = False, default = datetime.utcnow)
    user_id = db.Column(db.Integer,db.ForeignKey('user.id'),nullable = False)
    def __repr__(self):
       return '<Article %r>' % self.id
class Registrate(FlaskForm):
    nick = StringField('Username',validators=[DataRequired(),Length(min=2,max=15)])
    def validate_username(self,nick ):
        excluded_chars = " *?!'^+%&amp;/()=}][{$#"
        for char in self.nick .data:
            if char in excluded_chars:
                raise ValidationError(
                    f"Character {char} is not allowed in username.")
    email = StringField('Email',validators=[DataRequired(),Email()])
    password = PasswordField('Password',validators=[DataRequired()])
    confirm_p = PasswordField('Confrim password',validators=[DataRequired(),EqualTo('password')])
    submit = SubmitField('Submit')

class Note_form(FlaskForm):
    title = StringField("Title",validators=[DataRequired(),Length(min = 2, max = 15)])
    content = TextAreaField("Title",validators=[DataRequired(),Length(min = 2, max = 300)])
    submit = SubmitField('Submit')

class Authentication(FlaskForm):
    nick = StringField("Username",validators=[DataRequired(),Length(min = 2, max = 15)])
    email = StringField('Email',validators=[DataRequired(),Email()])
    password = PasswordField('Password',validators=[DataRequired()])
    submit = SubmitField('Submit')

@app.route('/website')
def website():
    return render_template('Cuda.html')
@login.user_loader
def load_user(id):
    return User.query.get(int(id))
@app.route('/registration',methods=['GET','POST'])
def rege():
    form = Registrate()
    if form.validate_on_submit():
        hash = generate_password_hash(form.password.data)
        hash1 = generate_password_hash(form.confirm_p.data)
        user = User(nick = form.nick.data,email = form.email.data,password = hash,confirm_p=hash1)
        try:
            if User.query.filter_by(email=form.email.data).first():
                flash('This email already exists')
            elif User.query.filter_by(nick=form.nick.data).first():
                   flash('This username already exists')
            else:
             db.session.add(user)
             db.session.commit()  
             return redirect(url_for('website'))
        except:
            return flash('Check your password confirm or email, or urename')
    return render_template('registrate.html',title='SEARCHER.',form=form)
@app.errorhandler(401)
def unauthorized(error):
    return "<h1>Man, what the fuck are you doing here?</h1>"

@app.route('/authentication',methods=['GET','POST'])
def authorization():
    if current_user.is_authenticated:
      return redirect(url_for('authorized'))
    form = Authentication()
    if form.validate_on_submit():
       email_validation =User.query.filter_by(email = form.email.data).first()
       nickname_validation = User.query.filter_by(nick = form.nick.data).first()
       if not  nickname_validation:
           flash(f"Your nickname is invalid")
       elif not email_validation:
           flash(f"Your email is invalid")
       elif not  check_password_hash(email_validation.password,form.password.data):
           flash(f"Your password is invalid")
       else:
           login_user(email_validation,nickname_validation)
           return redirect(url_for('authorized'))
    return render_template('authentication.html',form=form)

@app.route("/authorized_website")
@login_required
def authorized():
    return render_template("authorized_page.html",title = "Cuda")
@app.route('/home_note')
def home_note():
    note = Post_data.query.all()
    return render_template('notes.html',note = note)
@app.route("/create_post/new",methods=["GET","POST"])
@login_required
def create_post():
    form = Note_form()
    if form.validate_on_submit():
        notes = Post_data(title = form.title.data,content = form.content.data,author = current_user)
        try:
           db.session.add(notes)
           db.session.commit()  
           return redirect(url_for("home_note"))
        except:
           flash("You are baklan")
    return render_template("create_post.html",title='Cuda',form=form)
@app.route('/donate')
def donate():
    api = Api(merchant_id=1396424,
          secret_key='test')
    checkout = Checkout(api=api)
    data = {
    "currency": "USD",
    "amount": 1000
    }
    url = checkout.url(data).get('checkout_url')
    return  redirect(url)
if __name__ == '__main__':
  app.run(debug = True)
