from flask import Flask, render_template, request, url_for, redirect, flash, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

    def set_password(self, secret):
        self.password = generate_password_hash(secret)

    def check_password(self, secret):
        return check_password_hash(self.password, secret)


#Line below only required once, when creating DB. 
# db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=["POST", "GET"])
def register():
    if request.method == "POST":
        password = generate_password_hash("123456", method="pbkdf2:sha256", salt_length=8)
        new_user = User(
            name=request.form["name"],
            email=request.form["email"],
            password=password
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return render_template("/secrets.html", name=current_user.name)
    return render_template("register.html")


@app.route('/login', methods=["POST", "GET"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(email=request.form["email"]).first()
        password = request.form["password"]
        if user.check_password(password):
            login_user(user, remember=True)
            return redirect(url_for('secrets'))
    return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():
    name = current_user.name
    return render_template("secrets.html", name=name)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect("/")


@app.route('/download')
@login_required
def download():
    return send_file("static/files/cheat_sheet.pdf")


if __name__ == "__main__":
    app.run(debug=True)
