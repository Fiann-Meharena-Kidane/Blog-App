from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor, CKEditorField
from datetime import datetime

from sqlalchemy import Integer, String, Text, Table, ForeignKey, Column
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, declarative_base
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from wtforms import Form, StringField, validators, SubmitField, PasswordField, EmailField
from flask_wtf import FlaskForm
from forms import CreatePostForm
from flask_gravatar import Gravatar
from functools import wraps
import os
from dotenv import load_dotenv

load_dotenv()  # this will load variables from .env.


year=datetime.now().year
# updates year in each page,

app = Flask(__name__)
app.config['SECRET_KEY'] =os.environ.get('SECRET_KEY')
ckeditor = CKEditor(app)
Bootstrap(app)

gravatar=Gravatar(app,
                  size=100,
                  rating='g',
                  default='retro',
                  force_default=False,
                  force_lower=False,
                  use_ssl=False,
                  base_url=None)

# gravatar object to generate random profile image,

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# CONFIGURE TABLES

Base = declarative_base()


# ***************** TABLES ******************** #


class User(UserMixin, db.Model, Base):
    __tablename__ = "users"
    id = db.Column(Integer, primary_key=True)
    email = db.Column(String(100), unique=True)
    password = db.Column(String(100))
    name = db.Column(String(1000))

    posts = relationship("BlogPost", backref="author")
    # posts is list of posts a use has,
    # user author to get user who posts a post. Eg. post1.author gives author/user object associated
    # with post1 object,

    comments = relationship("Comments", backref='commentator')
    # comment_author refers to the comment_author property in the Comment class,


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(Integer, primary_key=True)
    title = db.Column(String(250), unique=True, nullable=False)
    subtitle = db.Column(String(250), nullable=False)
    date = db.Column(String(250), nullable=False)
    body = db.Column(Text, nullable=False)
    img_url = db.Column(String(250), nullable=False)

    author_id = db.Column(Integer, ForeignKey('users.id'))
    # blog post is linked to its Author/user through its author_id which is equal to User id ,

    comments=relationship("Comments", backref="post")
    # comments is list of comments under a blog,
    # user comment.post to find the post a comment is written under


class Comments(db.Model):
    __tablename__ = 'comments'
    id = db.Column(Integer, primary_key=True)
    text = db.Column(Text, nullable=False)
    post_id=db.Column(Integer, ForeignKey('blog_posts.id'))
    # comment object is liked to post through a new 'post_id' column which holds id of respective blog post

    commentator_id=db.Column(Integer,ForeignKey('users.id'))
    # each comment has a column which holds respective user's id as foreign,


# db.create_all()
# db.drop_all()

# ************** FORMS ***************** #


class RegistrationForm(FlaskForm):
    """ Class to represent Registration Form """
    user_email = EmailField('Email', validators=[validators.data_required(), validators.Email()])
    user_password = PasswordField('Password', validators=[validators.data_required()])
    user_name = StringField('Name', validators=[validators.data_required()])
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    """ Class to represent Login Form """
    user_email = EmailField('Email', validators=[validators.data_required(), validators.Email()])
    user_password = PasswordField('Password', validators=[validators.data_required()])
    submit = SubmitField('Login')


class CommentForm(FlaskForm):
    """ Class to represent Comment section """
    comment = CKEditorField("Comment", validators=[validators.data_required()])
    submit = SubmitField("Submit")


login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# this function prevents a user from accessing a route if he/she isnt admin,
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # if id is not 1, return abort 403 message,
        if not current_user.id == 1:
            return abort(403)
        return f(*args, **kwargs)
        # otherwise continue with normal route function,

    return decorated_function


@app.route('/', methods=['POST', 'GET'])
# @login_required
def get_all_posts():
    posts = BlogPost.query.all()
    if request.method=='GET':
        if not current_user.is_authenticated:
            # if user is not authenticated is asking for homepage,
            return render_template('index.html',all_posts=posts , current_user=current_user, year=year)
    return render_template("index.html", all_posts=posts, current_user=current_user, year=year)


@app.route('/register', methods=['POST', 'GET'])
def register():
    error = None
    form = RegistrationForm()

    if request.method == 'GET':
        return render_template("register.html", form=form, year=year)
    else:
        # else if user is registering,
        if form.validate_on_submit:
            my_email = request.form.get('user_email')
            email_found = User.query.filter_by(email=my_email).first()

            if email_found:
                form = LoginForm()
                error = "You have registered with that email already, Login in instead!"
                flash(error)
                return redirect(url_for('login', form=form, current_user=current_user, year=year))
                # if email is on DB redirect to login,
            else:
                hashed_password = generate_password_hash(request.form.get('user_password'), method='pbkdf2:sha256',
                                                         salt_length=8)
                new_user = User(
                    email=request.form.get('user_email'),
                    password=hashed_password,
                    name=request.form.get('user_name')
                )

                db.session.add(new_user)
                db.session.commit()
                # else if user is new, add user to users table, then login user,

                login_user(new_user)
                if new_user.id == 1:
                    # if admin, set admin to True, so that he/she gets access to create and edit post services,
                    return redirect(url_for('get_all_posts', current_user=current_user, admin=True, year=year))
                return redirect(url_for('get_all_posts', current_user=current_user, admin=False, year=year))

        else:
            return render_template('register.html', form=form, year=year)
            # if form is not validate, display again,


@app.route('/login', methods=['POST', 'GET'])
def login():
    form = LoginForm()
    if request.method == 'GET':
        return render_template("login.html", form=form, year=year)
    else:
        if form.validate_on_submit():
            user = User.query.filter_by(email=request.form.get('user_email')).first()
            if user:
                # if user is found,
                if check_password_hash(user.password, request.form.get('user_password')):
                    login_user(user)
                    if user.id == 1:
                        # if password is correct, and user is found to be admin,
                        return redirect(url_for('get_all_posts', current_user=current_user, admin=True, year=year))
                    # else if user is not admin,
                    return redirect(url_for('get_all_posts', current_user=current_user, admin=False, year=year))

                flash("Incorrect Password")
                return render_template('login.html', form=form, year=year)
            else:
                # if email not found in DB
                flash("There is no such Email")
                return redirect(url_for('login'))
        return render_template('login.html', form=form, year=year)


@app.route('/post/<int:post_id>', methods=['POST', 'GET'])
def show_post(post_id):
    comment_form = CommentForm()
    requested_post = BlogPost.query.get(post_id)

    if request.method == 'POST':
        if comment_form.validate_on_submit():
            if not current_user.is_authenticated:
                # if user not logged in,
                flash("Please Login to Comment")
                return redirect(url_for('login', year=year))

            # else if user is logged in,
            new_comment=Comments(
                text=comment_form.comment.data,
                post_id=post_id,
                commentator_id=current_user.id,
            )
            db.session.add(new_comment)
            db.session.commit()
            return render_template("post.html", post=requested_post, comment_form=comment_form, year=year)

        else:
            flash("Comment can not be empty")
            return render_template("post.html", post=requested_post, comment_form=comment_form, year=year)
    return render_template("post.html", post=requested_post, comment_form=comment_form, year=year)


@app.route('/logout')
def logout():
    logout_user()
    return render_template('index.html', current_user=current_user, year=year)


@app.route("/contact")
def contact():
    return render_template("contact.html", year=year)


@app.route("/about")
def about():
    return render_template("about.html", year=year)


@app.route("/new-post", methods=['POST', 'GET'])
@login_required
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        # create new post object, and add it to DB,
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=datetime.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts", year=year))
    return render_template("make-post.html", form=form, year=year)


@app.route("/edit-post/<int:post_id>", methods=['POST', 'GET'])
@login_required
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    # instead of blank form, we use the old post to be edited,
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    ) # date is left unchanged,

    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        # if editing goes well, display the updated one,
        return redirect(url_for("show_post", post_id=post.id, year=year))

    return render_template("make-post.html", form=edit_form, year=year)


@app.route("/delete/<int:post_id>", methods=['POST', 'GET'])
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts', year=year))


if __name__ == "__main__":
    app.run(debug=True)
