from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, current_user, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, validators, PasswordField, SubmitField, ValidationError, BooleanField

# SETUP AND CONFIG FLASK APP
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.db'
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'My secret key'

# CONFIG SQLALCHEMY
db = SQLAlchemy(app)

#SET UP FLASK-LOGIN
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "users.login"

# DEFINING MODELS
class Blog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    body = db.Column(db.String, nullable=False)
    author = db.Column(db.String(30), nullable=False)
    created = db.Column(db.DateTime, server_default=db.func.now())
    updated = db.Column(db.DateTime, server_default=db.func.now(), server_onupdate=db.func.now())

db.create_all()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), nullable=False, unique=True)
    password = db.Column(db.String(20), nullable=False)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

db.create_all()

## FORM WTF
class RegistrationForm(FlaskForm):
    email = StringField('Email Address', [validators.Length(min=6, max=35)])
    password = PasswordField('New Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Repeat Password')
    # accept_tos = BooleanField('I accept the TOS', [validators.DataRequired()])
    submit = SubmitField("Send")

    def validate_email(form, field):
        user = User.query.filter_by(email=field.data).first()
        if user:
            raise ValidationError('Email taken')            

db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

# @app.route
# @login_required
# def logout():
#     logout_user()
#     return urlfor(login)

#LOGIN
@app.route('/', methods=['GET', 'POST'])
def log_in():
    if request.method == 'POST':

        # import code; code.interact(local=dict(globals(), **locals()))
        user = User.query.filter_by(email = request.form['email']).first()

        # if current_user.is_authenticated:
        #    return redirect(url_for('profile'))

        if user != request.form['email']:
            flash("The password you've entered is incorrect !", 'danger')

        if not user:
            flash("Your account does not exist, please sign up")
            return redirect(url_for('register'))

        if user.check_password(request.form['password']):
            flash("Welcome Back! {0}" .format(user.email), 'success')
            return redirect(url_for('profile'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm(request.form)
    if request.method == 'POST' :
        print("POST", form.email.data, form.password.data, form.confirm.data)
        if form.validate_on_submit():
            user = User.query.filter_by(email = form.email.data).first()
            if user: 
                flash("Your account have already existed, log in now")
                return redirect(url_for('log_in'))

            if not user:
                user = User(email = form.email.data)
                user.set_password(form.password.data)
                db.session.add(user)
                db.session.commit()
                flash('Thanks for registering !!')
                return redirect(url_for('log_in'))
        else:
            for field,errors in form.errors.items():
                print(field,errors)
    return render_template('register.html', form = form)

@app.route('/profile',  methods=['GET', 'POST'])
def profile():
    return render_template('profile.html')

# ADD New Entry
@app.route('/newpost', methods=['GET', 'POST'])
def new_post():
    if request.method == "POST":
        new_blog = Blog(title=request.form['title'], body=request.form['body'],
                        author=request.form['author'])
        db.session.add(new_blog)
        db.session.commit()
        return redirect(url_for('new_post'))
    posts = Blog.query.all()
    return render_template('home.html', posts = posts)

#DELETE New Entry
# @app.route('/blogs/<id>', methods=['GET','POST']) ## specify route with methods
# def delete_entry(id):  ## grabing id from route to function
#     if request.method == "POST" :  ## check if the request method is POST, we execute the following logic
#         post = Blog.query.filter_by(id=id).first() ## select a post from database base on the ID we got from URL
#         if not post:  ## if there is no such post, we stop everything 
#             return "THERE IS NO SUCH POST"
#         db.session.delete(post)  ## else: there's an entry with that ID, we delete it
#         db.session.commit()
#         return redirect(url_for('new_post')) ## then redirect to our root route or function new_post
#     return "NOT ALLOWED"  ## guarding against incorrect request method (being nice!)



if __name__ == "__main__":
    app.run(debug=True)
