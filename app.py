from flask import Flask, render_template, flash, redirect, url_for, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, date
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user, login_required, logout_user


# CONFIGURATIONS
app = Flask(__name__)
app.config['SECRET_KEY'] = '7jf0477adf76233#@!!@#-' 

ENV = 'production' #to determine does the app is running in production mode or in development mode.
if ENV == 'dev':
    app.debug = True
    app.config["SQLALCHEMY_DATABASE_URI"] = ""  #enter your local postgres url.
    # This means when we are in development mode in our local machine we will be using our own postgres database.
else:
    app.debug = False
    app.config["SQLALCHEMY_DATABASE_URI"] = "postgres://vghauclecqdbha:d9c29e0cca0f04cba142355de3d8714b6bfb1cb5f26b30ba9c217c269fb5bfa0@ec2-52-71-85-210.compute-1.amazonaws.com:5432/ddfmt0g62mdtuu"
    # when app is to be depoyed we wil use their database like heroku's postgres add-on.

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  #the view for routes with @login_required.
login_manager.login_message_category = 'danger'

# LOGIN LOADER
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# FORMS
class LoginForm(FlaskForm):
    login_username = StringField('Username', validators= [DataRequired(), Length(min= 2, max= 20)], render_kw={'autofocus': True})
    login_pass = PasswordField('Password', validators= [DataRequired(), Length(min=2, max= 20)])
    login_remember = BooleanField('remember me')
    login_btn = SubmitField('Login')

class RegisterForm(FlaskForm):
    register_username = StringField('Username', validators= [DataRequired(), Length(min= 2, max= 20)], render_kw={'autofocus': True}) 
    register_pass = PasswordField('Password', validators= [DataRequired(), Length(min=2, max=20)])
    register_confirm_pass = PasswordField('Confirm Password', validators= [DataRequired(), EqualTo('register_pass', message= 'Passwords must match!')])
    register_btn = SubmitField('Register')

    # custom validation to check if the username already exits.
    def validate_register_username(self, register_username):
        user = User.query.filter_by(username= register_username.data).first()
        if user:
            raise ValidationError("Username already exits, please choose another.")

class ShowcaseForm(FlaskForm):
    title = StringField('Title', validators= [DataRequired(), Length(min= 2, max= 100)], render_kw={'autofocus': True})
    content = TextAreaField('Content', validators= [DataRequired()])
    save_btn = SubmitField('Save')

class SearchBar(FlaskForm):
    search = StringField("search", validators= [DataRequired()], render_kw={'autofocus': True})
    search_btn = SubmitField('Search')


# DATABASE
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(20), unique= True, nullable= False)
    password = db.Column(db.String(60), nullable= False)
    diarys = db.relationship('Diary', backref= 'author', lazy= True)

class Diary(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(100), nullable= False)
    date_posted = db.Column(db.DateTime, nullable= False, default= datetime.utcnow)
    content = db.Column(db.Text, nullable= False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable= False)

    def __repr__(self):
        return f"Diary('{self.title}', '{self.date_posted}')"


# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        flash("You are already logged in!", 'success')
        return redirect(url_for('diary_collection'))
    return render_template('index.html')

@app.route('/about')
@login_required
def about():
    return render_template('about.html')


#A route accessible even user is not logged in with some links to get to me. 
@app.route('/contact_me')
def contact_me():
    return render_template('contact_me.html')

@app.route('/showcase', methods= ['GET', 'POST'])
@login_required
def showcase():
    form = ShowcaseForm()
    if form.validate_on_submit():
        if Diary.query.filter_by(title= form.title.data, author= current_user).first():
            flash("You already have a diary note with same title, please modify your title!", 'danger')
        else:
            new_entry = Diary(title= form.title.data, content= form.content.data, author= current_user)
            db.session.add(new_entry)
            db.session.commit()
            flash("Great! You just created a new diary", 'success')
            return redirect(url_for('diary_collection'))

    return render_template('showcase.html', form= form)

@app.route('/diary_collection', methods= ["GET", "POST"])
@login_required
def diary_collection():
    form = SearchBar()
    # to get current user's stuff.
    user_id = current_user.get_id()
    user = User.query.filter_by(id= user_id).first()

    # when user searches for term, those diarys will be displayed.
    if form.validate_on_submit():
        search_term = form.search.data
        if User.query.filter_by(id= user_id).all():  #to get search result of that user only.
            # if title, content, date_posted contains searched term.
            if Diary.query.filter(Diary.title.contains(search_term)).all(): #if found title with searched term.
                diarys = [] #empty list to append our resultant diarys.
                for d in Diary.query.filter(Diary.title.contains(search_term)).all():
                    if d.author == user:  #if diary belongs to current user.
                        diarys.append(d)
                flash(f"Search results for '{search_term}'...", 'success')
            else:
                return render_template('diary_collection.html', diarys= None, form= form)
    else:    
        # to display all diarys.
        diarys = user.diarys
        diarys = diarys[::-1]  #to arrange list of diarys in descending ways.
    return render_template('diary_collection.html', diarys= diarys, form= form)


@app.route('/login', methods= ['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('diary_collection'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username= form.login_username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.login_pass.data):
            login_user(user, remember= form.login_remember.data)
            next_page = request.args.get('next')
            # to login user to page that they wanted before they were authenticated.
            if next_page:
                flash('You have been successfully logged in!', 'success')
                return redirect(next_page)
            else:
                flash('You have been successfully logged in!', 'success')
                return redirect(url_for('diary_collection'))
        else:
            flash('Log in failed, please check your username and password!', 'danger')
    return render_template('login.html', form= form)

@app.route('/register', methods= ['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('showcase')) 
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_pass = bcrypt.generate_password_hash(form.register_pass.data).decode('utf-8')
        user = User(username= form.register_username.data, password= hashed_pass)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created, please login to get started!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form= form)

# Edit Diary route
@app.route("/edit_diary/<int:diary_id>", methods= ["GET", "POST"])
@login_required
def edit_diary(diary_id):
    diary = Diary.query.get_or_404(diary_id)
    if request.method == "POST":
        try:
            diary.title = request.form["title"]
            diary.content = request.form["content"]
            db.session.commit()
            flash("Diary has been updated!", 'success')
            return redirect(url_for('diary_collection'))
        except:
            flash("Something went wrong while editing, please try again later.", 'danger')
            return redirect(url_for('diary_collection'))
    else:
        return render_template('edit_diary.html', diary= diary)

@app.route('/delete/<int:id>')
@login_required  #login is required to access this page.
def delete(id):
    diary = Diary.query.get_or_404(id)
    try:
        db.session.delete(diary)
        db.session.commit()
        flash("You deleted the diary '{}'.".format(diary.title), 'warning')  
        return redirect(url_for('diary_collection'))
    except:
        flash('Something went wrong in deleting the diary.', 'danger')

@app.route('/logout')
def logout():
   logout_user()
   return redirect(url_for('index'))

   
if __name__ == '__main__':
    app.run()
    