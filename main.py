import datetime

import flask
import flask_login
from flask import Flask, render_template, request, url_for
from flask_login import LoginManager, login_user, UserMixin, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import redirect
from wtforms import StringField, PasswordField, SubmitField
from flask_bootstrap import Bootstrap
from wtforms.validators import DataRequired, email
from smtplib import SMTP

app = Flask("__name__")
to_do_list = []
selected_list = -1
SECRET_KEY = "this is the key"
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
Bootstrap(app)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, unique=True, primary_key=True)
    username = db.Column(db.String(200))
    email = db.Column(db.String(200), unique=True)
    password = db.Column(db.String(100))
    list = db.relationship('List', backref='user', lazy=True)


class List(db.Model):
    id = db.Column(db.Integer, unique=True, primary_key=True)
    name = db.Column(db.String(200))
    tasks = db.Column(db.String(1000))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

db.create_all()


class LoginForm(FlaskForm):
    email = StringField("email", validators=[DataRequired(), email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Log In")

@login_manager.user_loader
def user_loader(user_id):
    return User.query.get(user_id)

@app.route("/", methods=["POST", "GET"])
def home():
    return render_template("index.html")


@app.route("/list", methods=["POST", "GET"])
def create_list():
    global selected_list
    date = datetime.datetime.now()
    list_name = f"To-Do List ({date.strftime('%d-%m-%Y')})"
    all_lists = []
    print("Create list", to_do_list)
    if current_user.is_authenticated:
        all_lists = show_lists(current_user.id)
        print("Cre", all_lists)
    if request.method == "POST":
        #list_name = request.form
        to_do_list.append(request.form["task"])

        return redirect(url_for("create_list", to_do_list=to_do_list, list_name=list_name, all_lists=all_lists))

    return render_template("main.html", to_do_list=to_do_list, list_name=list_name, all_lists=all_lists)


@app.route("/login", methods=["POST", "GET"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        print(user)
        if user is None:
            flask.flash("Email is not registered")
        elif not check_password_hash(user.password, form.password.data):
            flask.flash("Check your password again")
        else:
            login_user(user)
            return redirect(url_for('home'))
    return render_template("login.html", form=form)


@app.route("/register", methods=["POST", "GET"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(email=email).first()
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        if not email or not username or not password:
            flask.flash("Fill in all the fields.")
        elif user is not None:
            flask.flash("The email is already registered. Use a different email.")
        else:
            u = User(email=email, password=hashed_password, username=username)
            db.session.add(u)
            db.session.commit()
            login_user(u)
            return redirect(url_for('home'))
    return render_template("register.html")


@app.route("/share_list", methods=["POST", "GET"])
def share_list():
    print(request.method)
    if request.method == "POST":
        with SMTP("smtp.gmail.com") as connection:
            connection.starttls()
            connection.login(user="simplifytodolist@gmail.com", password="simplifyto-do347")
            sender = request.form["sender_email"]
            nl = '\n'
            connection.sendmail(from_addr=sender,
                                to_addrs=request.form["receiver_email"],
                                msg=f"subject: To-do list sent by {sender} \n\n"
                                    f"Here is the to-do-list sent by {sender}\n"
                                    f"{nl.join(to_do_list)}")
        print("success")
    return redirect(url_for('create_list'))


@app.route("/save_list/<list_name>/<user_id>")
def save_list(list_name, user_id):
    print(list_name)
    print(user_id)
    to_do_list_str = " ".join(str(x) for x in to_do_list)
    list = List(name=list_name,
                tasks= to_do_list_str, user_id=user_id)
    if selected_list == -1:
        db.session.add(list)
    else:
        l = List.query.get(selected_list)
        l.tasks = to_do_list_str
    db.session.commit()
    return redirect(url_for('create_list'))


def show_lists(user_id):
    lists = List.query.filter_by(user_id=user_id).all()
    print(user_id)
    print("lists", lists)
    for l in lists:
        print("name", l.name)
        print("lists", l.tasks)
    return lists


@app.route("/set_list/<list_id>")
def set_list(list_id):
    global to_do_list
    global selected_list
    selected_list = list_id
    task_id = List.query.get(list_id)
    tasks = task_id.tasks
    to_do_list = list(tasks.split(" "))
    return redirect(url_for('create_list'))


@app.route("/reset")
def reset():
    global to_do_list
    global selected_list
    to_do_list = []
    selected_list = -1
    return redirect(url_for('create_list'))


@app.route("/remove-task/<task>")
def remove_task(task):
    global to_do_list
    to_do_list.remove(task)
    return redirect(url_for('create_list'))


@app.route("/logout")
def logout():
    flask_login.logout_user()
    return redirect(url_for('home'))


if __name__ == "__main__":
    app.run(debug=True)