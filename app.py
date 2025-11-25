from flask import Flask, render_template, request, redirect, url_for, flash,Response,jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime, timezone
import traceback
from Url_short import genearate_short_url
import qrcode
import io
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address




app= Flask(__name__)
# database making
app.config['SQLALCHEMY_DATABASE_URI']= 'sqlite:///king.db'
app.config['SECRET_KEY']= 'thisisasecretkey'
# notifaction fasle
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

limite_call_app=Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day","50 per hour"]
)

db= SQLAlchemy(app)
jwt= JWTManager(app)

class User(db.Model):

    # columns
    id= db.Column(db.Integer, primary_key=True)
    email= db.Column(db.String(150), unique=True, nullable=False)
    username= db.Column(db.String(150), unique=True, nullable=False)
    password_hash= db.Column(db.String(150), nullable=False)
    is_admin= db.Column(db.Boolean, default=False)
    links = db.relationship('Link', backref='user', lazy=True)

    def Hash_password(self,password):

        self.password_hash= generate_password_hash(password=password,method='sha256')
    def check_password(self,password):

        return check_password_hash(self.password_hash,password)

# new link database
class Link(db.Model):

    id= db.Column(db.Integer, primary_key=True)
    original_url= db.Column(db.String(500), nullable=False)
    short_url= db.Column(db.String(100), unique=True, nullable=False)
    created_at= db.Column(db.DateTime, default=datetime.now(timezone.utc))
    clicks= db.Column(db.Integer, default=0)
    user_id= db.Column(db.Integer, db.ForeignKey('User.id'), nullable=False)

# Registration route    
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    if ("<script" in username.lower() or "javascript:" in username.lower()) or\
        ("<script" in password.lower() or "javascript:" in password.lower()) or\
        ("<script" in email.lower() or "javascript:" in email.lower()):
        return "JS Detected", 400
    if User.query.filter_by(username=username).first():
        return jsonify({"message": "User already exists"}), 400

    new_user = User(username=username,email=email)
    new_user.Hash_password(password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201

# Login route
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if ("<script" in username.lower() or "javascript:" in username.lower()) or\
        ("<script" in password.lower() or "javascript:" in password.lower()):
        return "JS Detected", 400
    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return jsonify({"message": "Invalid credentials"}), 401

    access_token = create_access_token(identity={'username': user.username, 'is_admin': user.is_admin})
    return jsonify({"access_token": access_token}), 200

# Create Link route
@app.route('/create_link', methods=['POST'])
@jwt_required()
@limite_call_app.limit('10 per minute')
def create_link():
    try:
        current_user= get_jwt_identity()
        check_user= User.query.filter_by(username=current_user['username']).first()
        print(f'Current User: {check_user.username}')

        # Get original URL from request
        data= request.get_json()
        original_url= data.get('original_url')
        if not original_url:
            return jsonify({"message": "Original URL is required"}), 400
        
        # Generate unique short URL
        short_url= genearate_short_url()

        # Create new Link entry
        new_link= Link(original_url=original_url, short_url=short_url, user_id=check_user.id)
        db.session.add(new_link)
        db.session.commit()
        return jsonify({
            "message": "Short URL created successfully",
            "short_url": url_for('redirect_short_url', short_url=short_url, _external=True)
        }), 201
    
    except Exception as e:
        print(f'Error creating link: {e}')
        traceback.print_exc()
        return jsonify({"message": "Internal server error"}), 500
    
# short url click route
@app.route('/<short_url>')
@limite_call_app.limit("10 per minute")
def redirect_short_url(short_url):
    try:
        links= Link.query.filter_by(short_url=short_url).first()
        if links:
            links.clicks += 1
            db.session.commit()
            print(f'Redirecting to: {links.original_url}')
            return redirect(links.original_url)
        else:
            print('Short URL not found')
            return jsonify({"message": "URL not found"}), 404
    except Exception as e:
        print(f'Error redirecting short URL: {e}')
        traceback.print_exc()
        return jsonify({"message": "Internal server error"}), 500
    
@app.route('/links', methods=['GET'])
@jwt_required()
@limite_call_app.limit("10 per minute")
def get_links():

    print('Fetching links for user')
    try:
        current_user= get_jwt_identity()
        check_user= User.query.filter_by(username=current_user['username']).first()
        links=check_user.links
        links_data=[]
        for link in links:
            links_data.append({
                "original_url": link.original_url,
                "short_url": url_for('redirect_short_url', short_url=link.short_url, _external=True),
                "created_at": link.created_at,
                "clicks": link.clicks
            })
        
        return jsonify({"links": links_data}), 200
    except Exception as e:
        print(f'Error fetching links: {e}')
        traceback.print_exc()
        return jsonify({"message": "Internal server error"}), 500
    

@app.route('/qr/<short_url>',methods=['GET'])
@jwt_required()
@limite_call_app.limit("10 per minute")
def generate_qr(short_url):

    try:
        links=Link.query.filter_by(short_url=short_url).first()

        if not links:
            return jsonify({"message": "URL not found"}),404
        url_for_= url_for('redirect_short_url', short_url=short_url, _external=True)
        print(f'Generating QR for: {links.short_url}')
        # Generate QR code
        qr= qrcode.make(url_for_)
        print('QR code generated successfully')
        image_io= io.BytesIO()
        qr.save(image_io)
        image_io.seek(0)
        print('Returning QR code image')
        return Response(image_io, mimetype='image/png')
    except Exception as e:
        print(f'Error generating QR code: {e}')
        traceback.print_exc()
        return jsonify({"message": "Internal server error"}), 500


def admin_required():
    def wrapper(fn):
        @wraps(fn)
        # Pehle yeh zaroor check karein ke token valid hai
        @jwt_required()
        def decorator(*args, **kwargs):
            # Token se identity nikalein
            current_user_identity = get_jwt_identity()
            
            # Check karein ke is_admin flag True hai ya nahi
            if current_user_identity.get('is_admin'):
                # Agar admin hai, to asal function ko chalne dein
                return fn(*args, **kwargs)
            else:
                # Agar admin nahi, to error dein
                return jsonify({"message": "Admins only!"}), 403 # 403 means Forbidden
        return decorator
    return wrapper
@app.route('/admin/users', methods=['GET'])
@admin_required()
def get_all_users():
    users = User.query.all()
    users_data = []

    for user in users:
        users_data.append({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'is_admin': user.is_admin
            # Password hash kabhi bhi API mein na bhejein! (Question 2 ka Jawab)
        })

    return jsonify(users_data), 200
@app.route('/admin/links', methods=['GET'])
@admin_required()
def get_all_links():
    links = Link.query.all()
    links_data = []

    for link in links:
        links_data.append({
            'id': link.id,
            'original_url': link.original_url,
            'short_url': url_for('redirect_short_url', short_url=link.short_url, _external=True),
            'clicks': link.clicks,
            'owner_username': link.User.username # Dekhein relationship ka faida!
        })

    return jsonify(links_data), 200