from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
import enum
import bcrypt
from sqlalchemy import Enum
from werkzeug.security import generate_password_hash, check_password_hash 
db = SQLAlchemy()

class User(UserMixin,db.Model):
    id = db.Column(db.Integer,primary_key=True)
    email = db.Column(db.String(100),unique=True)
    name = db.Column(db.String(100))
    password = db.Column(db.String(100))
    is_admin = db.Column(db.Boolean,default=False)
    @classmethod
    def create_admin(cls):
       admin = cls.query.filter_by(email="admin1234@gmail.com").first()
       if not admin:
          admin = User(name="Admin",email="admin1234@gmail.com",is_admin=True)
          admin.set_password("password")
          db.session.add(admin)
          db.session.commit()

     def set_password(self, plain_text_password):
        self.password = bcrypt.hashpw(plain_text_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def __init__(self,email,name,password):
        self.name=name
        self.email=email
        self.password=bcrypt.hashpw(password.encode('utf-8'),bcrypt.getsalt()).decode('utf-8')

    def check_password(self,password):
        return bcrypt.checkpw(password.encode('utf-8'),self.password.encode('utf-8'))

class ParkingLot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    prime_location_name = db.Column(db.String(100),nullable=False)
    address = db.Column(db.String(100),nullable=False)
    pin_code = db.Column(db.String(10),nullable=False)
    price = db.Column(db.Float,nullable=False)
    maximum_number_of_spots = db.Column(db.Integer,nullable=False) 
    spots = db.relationship('ParkingSpot', backref='lot', lazy=True, cascade="all, delete")   

class ParkingSpot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    lot_id = db.Column(db.Integer, db.ForeignKey('parking_lot.id'),nullable=False)
    status = db.Column(db.String(1), default='A')  
    reservations = db.relationship('ReserveParkingSpot', backref='spot', lazy=True)

class ReserveParkingSpot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    spot_id = db.Column(db.Integer, db.ForeignKey('parking_spot.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    parking_timestamp = db.Column(db.DateTime, nullable=False)
    leaving_timestamp = db.Column(db.DateTime,nullable=False)      
    parking_cost = db.Column(db.Integer,nullable=False)