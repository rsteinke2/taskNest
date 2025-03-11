from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from forms import RegisterForm, LoginForm
from sqlalchemy.exc import IntegrityError
import os

app = Flask(__name__)
SECRET_KEY = os.urandom(32)
app.config['SECRET_KEY'] = SECRET_KEY
ckeditor = CKEditor(app)
Bootstrap5(app)
login_manager = LoginManager()
login_manager.init_app(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:  # Check if the user is not admin
            return abort(403)  # Forbidden

        return f(*args, **kwargs)

    return decorated_function

class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tasks.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = db.Column(db.Integer, primary_key=True)
    email: Mapped[str] = db.Column(db.String(100), unique=True, nullable=False)
    password: Mapped[str] = db.Column(db.String(100), nullable=False)
    name: Mapped[str] = db.Column(db.String(100), nullable=False)

    # Define relationship to Tasklist
    tasklist = db.relationship("Tasklist", back_populates="author")

class Tasklist(db.Model):
    __tablename__ = "tasklist"
    id: Mapped[int] = db.Column(db.Integer, primary_key=True)
    description: Mapped[str] = db.Column(db.String(250), nullable=False)  # Removed unique=True
    checked: Mapped[bool] = db.Column(db.Boolean, nullable=False, default=False)
    starred: Mapped[bool] = db.Column(db.Boolean, nullable=False, default=False)

    # Foreign key linking task to a user
    author_id: Mapped[int] = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    author = db.relationship("User", back_populates="tasklist")

with app.app_context():
    db.create_all()

todo_list = []

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST" and current_user.is_authenticated:
        task_description = request.form.get("task")
        if task_description:
            # Check if the task already exists for the current user
            existing_task = Tasklist.query.filter_by(
                description=task_description,
                author_id=current_user.id
            ).first()

            if existing_task:
                flash("Task already exists.")
            else:
                new_task = Tasklist(
                    description=task_description,
                    checked=False,
                    starred=False,
                    author_id=current_user.id
                )
                try:
                    db.session.add(new_task)
                    db.session.commit()
                except IntegrityError:
                    db.session.rollback()
                    flash("An error occurred while adding the task.")

        return redirect(url_for("index"))

    # Fetch tasks if user is authenticated
    unchecked_tasks, completed_tasks = [], []
    if current_user.is_authenticated:
        unchecked_tasks = Tasklist.query.filter_by(checked=False, author_id=current_user.id).all()
        completed_tasks = Tasklist.query.filter_by(checked=True, author_id=current_user.id).all()

    return render_template("start.html", unchecked_tasks=unchecked_tasks,
                           completed_tasks=completed_tasks)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        password = form.password.data
        result = db.session.execute(db.select(User).where(User.email == form.email.data))
        user = result.scalar()

        if not user:
            flash("That email does not exist, please try again.")
        elif not check_password_hash(user.password, password):
            flash("Password incorrect, please try again.")
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('index'))
    # Passing True or False if the user is authenticated.
    return render_template("login.html", form=form, current_user=current_user)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        result = db.session.execute(db.select(User).where(User.email == form.email.data))
        user = result.scalar()
        if user:
            # User already exists
            flash("You've already registered with that email, log in instead!")
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=form.email.data,
            name=form.name.data,
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("index"))
    return render_template("register.html", form=form, current_user=current_user)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/new_list')
@login_required
def new_list():
    # Delete all tasks associated with the current user
    user_tasks = Tasklist.query.filter_by(author_id=current_user.id).all()
    for task in user_tasks:
        db.session.delete(task)
    db.session.commit()
    flash("Started a new list.")
    return redirect(url_for('index'))

from flask import Response

@app.route('/save')
@login_required
def save():
    # Retrieve unchecked tasks for the current user
    unchecked_tasks = Tasklist.query.filter_by(author_id=current_user.id, checked=False).all()
    task_descriptions = "\n".join([task.description for task in unchecked_tasks])

    # Create a text response for download
    return Response(
        task_descriptions,
        mimetype="text/plain",
        headers={"Content-Disposition": "attachment;filename=task_list.txt"}
    )

@app.route("/add_task", methods=["GET", "POST"])
@login_required
def add_task():
    task_description = request.form.get("description")
    if task_description:
        new_task = Tasklist(
            description=task_description,
            checked=False,
            starred=False,
            author_id=current_user.id
        )
        db.session.add(new_task)
        db.session.commit()
    return redirect(url_for("index"))

@app.route("/complete/<int:task_id>", methods=["GET", "POST"])
@login_required
def complete_task(task_id):
    task = Tasklist.query.get_or_404(task_id)
    task.checked = not task.checked
    db.session.commit()
    return redirect(url_for("index"))

@app.route("/remove/<int:task_id>", methods=["GET", "POST"])
@login_required
def remove_task(task_id):
    task = Tasklist.query.get_or_404(task_id)
    # Ensure only the task owner can remove it
    if task.author_id == current_user.id:
        db.session.delete(task)
        db.session.commit()
        flash("Task removed successfully.")
    else:
        flash("You don't have permission to remove this task.")
    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)