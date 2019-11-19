from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, current_user, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, validators, PasswordField, SubmitField, ValidationError, BooleanField
import fontawesome as fa
from flask_migrate import Migrate

# SETUP AND CONFIG FLASK APP
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'My secret key'

# CONFIG SQLALCHEMY
db = SQLAlchemy(app)

#SET UP FLASK-LOGIN
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Please Sign In to access your blog"
migrate = Migrate(app, db)


class Comment(db.Model):
    # __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String, nullable=False)
    user_id = db.Column(db.Integer, nullable=False)
    post_id = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now()) 
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), server_onupdate=db.func.now())


class Post(db.Model):
    # __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, server_default=db.func.now()) 
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), server_onupdate=db.func.now())
    view_count = db.Column(db.Integer, default=0)

likes = db.Table('likes',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('post_id', db.Integer, db.ForeignKey('post.id'), primary_key=True)
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), nullable=False, unique=True)
    email = db.Column(db.String(200), nullable=False, unique=True)
    password = db.Column(db.String(20), nullable=False)
    avatar_url = db.Column(db.Text, nullable=False)
    post = db.relationship('Post', backref='user', lazy=True)
    likes_post = db.relationship('Post', secondary='likes', backref='who_likes_post', lazy=True)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

## FORM WTF
class RegistrationForm(FlaskForm):
    name = StringField('Username', [validators.Length(min=6, max=35)])
    email = StringField('Email Address', [validators.Length(min=6, max=35)])
    password = PasswordField('New Password', [
        validators.DataRequired(), validators.Length(min=8),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Repeat Password')
    avatar_url = StringField('Your Avatar', [validators.DataRequired()])
    submit = SubmitField("Send")

    def validate_email(form, field):
        user = User.query.filter_by(email=field.data).first()
        if user:
            raise ValidationError('Email taken !')            
db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You've Signed out !", 'success')
    return redirect(url_for('landingpage'))

#LOGIN
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # import code; code.interact(local=dict(globals(), **locals()))
        user = User.query.filter_by(email = request.form['email']).first()

        if not user:
            flash("Your account does not exist, please Sign up !", 'warning')
            return redirect(url_for('login'))

        if user.check_password(request.form['password']):
            login_user(user)
            flash("Welcome Back! {0}" .format(user.name), 'success')
            return redirect(url_for('home'))
        flash("The password or email you've entered is incorrect !", 'danger')

    if current_user.is_authenticated:
        return redirect(url_for('home'))

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm(request.form)
    if request.method == 'POST' :
        if form.validate_on_submit():
            user = User.query.filter_by(email = form.email.data).first()
            if user: 
                flash("Your account have already existed, log in now")
                return redirect(url_for('register'))
            if not user:
                user = User(email = form.email.data, name = form.name.data, avatar_url = form.avatar_url.data)
                user.set_password(form.password.data)
                db.session.add(user)
                db.session.commit()
                flash('Thanks for registering !!', 'success')
                return redirect(url_for('login'))
        else:
            for field,errors in form.errors.items():
                print(field,errors)
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    return render_template('register.html', form = form)

@app.route('/')
def landingpage():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    return render_template('landingpage.html')

@app.route('/home')
@login_required
def home():
    posts = Post.query.all()
    posts = Post.query.order_by(Post.created_at.desc()).all()
    if request.args.get('filter') == 'most-oldest':
        posts = Post.query.order_by(Post.created_at.asc()).all()
    for post in posts:
        post.author = User.query.filter_by(id=post.user_id).first()
    return render_template('home.html', posts = posts)

# ADD New Entry
@app.route('/newpost', methods=['POST'])
def new_post():
    if request.method == "POST":
        new_blog = Post(body=request.form['body'], user_id=current_user.id)
    db.session.add(new_blog)
    db.session.commit()
    return redirect(url_for('home'))

@app.route('/posts/<id>', methods=['POST', 'GET'])
def single_post(id):
    action = request.args.get('action')
    print(action)
    post = Post.query.get(id)
    post.view_count += 1
    db.session.commit()
    comments = Comment.query.filter_by(post_id = post.id).all()
    if not post:
        flash('Post not found', 'warning')
        return redirect(url_for('home'))
    post.author = User.query.get(post.user_id)
    if request.method=="POST":
        if post.user_id != current_user.id:
            flash('not allow to do this', 'danger')
            return redirect(url_for('home'))
        if action == 'delete':
            db.session.delete(post)
            db.session.commit()
            return redirect(url_for('home'))
        elif action == 'update':
            post.body = request.form['body']
            db.session.commit()
            return redirect(url_for('home'))
            return redirect(url_for('single_post',id=id))
        elif action == 'edit':
            for comment in comments:
                comment.user_name = User.query.get(comment.user_id).name
            return render_template('single_post.html', post = post, action=action)
    if not action:
        action = 'view'  
    return render_template('single_post.html', post = post, action=action, comments=comments)

@app.route('/posts/<id>/comments', methods=['GET','POST'])
def create_comment(id):
    comment = Comment(user_id = current_user.id, post_id = id, body = request.form['body'])
    db.session.add(comment)
    db.session.commit()
    return redirect(url_for('single_post', id = id, action = 'view'))

@app.route('/posts/<id>/like', methods=['POST'])
def like(id):
    post = Post.query.get(id)
    if post in current_user.likes_post:
        current_user.likes_post.remove(post)
    else:
        current_user.likes_post.append(post)
    db.session.commit()
    return redirect(url_for('home')
    )

if __name__ == "__main__":
    app.run(debug=True)
