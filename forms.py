from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL, Length, ValidationError
from flask_ckeditor import CKEditorField


class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class RegisterForm(FlaskForm):
    username = StringField(validators=[DataRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    email = StringField(validators=[DataRequired()], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[DataRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Register')


class LoginForm(FlaskForm):
    email = StringField(validators=[DataRequired()], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[DataRequired()], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')


class CommentForm(FlaskForm):
    comment = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField('Submit')
