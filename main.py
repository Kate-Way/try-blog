import os

from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date

from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from sqlalchemy import Column, Integer, String, Text, ForeignKey
# to create decorator
from functools import wraps


app = Flask(__name__)
#app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
# To deploy online
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
ckeditor = CKEditor(app)
Bootstrap(app)

# CONNECT TO DB
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
# To deploy online
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# allows our app and login manager to work together
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


# reload user objects that are stored in the session
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def admin_only(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if current_user.id == 1:
            return func(*args, **kwargs)
        else:
            return abort(403)
    return decorated_function

# CONFIGURE TABLES


class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(20), nullable=False, unique=True)
    email = Column(String(80), nullable=False)
    password = Column(String(80), nullable=False)
    # One to many relationship (List of BlogPost objects attached to each User):
    # Name it after the child and make it plural, first arg = name of the class in a string + back reference
    # (new column or an existing - reference of user in blog posts)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comments", back_populates="comment_author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = Column(Integer, primary_key=True)
    # name it in relationship to the parent class, foreign key - parent table name .id
    author_id = Column(Integer, ForeignKey('users.id'))
    # author = Column(String(250))
    # author now became a property of user class, first arg = name of the class in a string + back reference to
    # a name of relationship in the parent class
    author = relationship("User", back_populates="posts")
    title = Column(String(250), unique=True, nullable=False)
    subtitle = Column(String(250), nullable=False)
    date = Column(String(250), nullable=False)
    body = Column(Text, nullable=False)
    img_url = Column(String(250), nullable=False)
    comments = relationship("Comments", back_populates="current_post")


class Comments(db.Model):
    __tablename__ = "comments"
    id = Column(Integer, primary_key=True)
    comment_author_id = Column(Integer, ForeignKey('users.id'))
    post_id = Column(Integer, ForeignKey('blog_posts.id'))
    comment_author = relationship("User", back_populates="comments")
    comment = Column(Text, nullable=False)
    current_post = relationship("BlogPost", back_populates='comments')


db.create_all()


@app.route('/', methods=['GET', 'POST'])
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)
        new_user = User(
            username=form.username.data,
            email=form.email.data,
            password=hashed_password
        )
        if User.query.filter_by(email=form.email.data).first():
            flash('You already registered. Please login.', 'warning')
            return redirect(url_for('login'))
        else:
            db.session.add(new_user)
            db.session.commit()
            # auto login user after registration
            login_user(new_user)
            return redirect(url_for('get_all_posts'), code=307)
    return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('get_all_posts'))
            else:
                flash('The password you entered does not match our records. Please try again.', 'warning')
        else:
            flash('The email you entered does not exist. Please try again.', 'warning')
    return render_template('login.html', form=form)


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    # check if user is logged in
    if current_user.is_authenticated:
        if form.validate_on_submit():
            comment = Comments(
                comment=form.comment.data,
                comment_author=current_user,
                current_post=requested_post
            )
            db.session.add(comment)
            db.session.commit()
    else:
        flash('Login required to write comments. Please login.', 'warning')
        return redirect(url_for('login'))
    return render_template("post.html", post=requested_post, form=form, current_user=current_user)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET', 'POST'])
@login_required
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            author=current_user,
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@login_required
@admin_only
def edit_post(post_id):
    # if User.query.filter_by(id=1).first(): - replaced with @admin_only
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=current_user,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)

