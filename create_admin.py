from app import app, db
from models import User
import sys

def create_admin(username, email, phone_number, password):
    with app.app_context():
        # Check if user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            print(f"User {username} already exists! Updating password...")
            existing_user.set_password(password)
            existing_user.email = email
            existing_user.phone_number = phone_number
            existing_user.is_admin = True
            db.session.commit()
            print(f"Admin user {username} password updated successfully!")
            return

        # Create new admin user
        admin = User(username=username, email=email, phone_number=phone_number, is_admin=True)
        admin.set_password(password)
        db.session.add(admin)
        db.session.commit()
        print(f"Admin user {username} created successfully!")

if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python create_admin.py <username> <email> <phone_number> <password>")
        sys.exit(1)
    
    username = sys.argv[1]
    email = sys.argv[2]
    phone_number = sys.argv[3]
    password = sys.argv[4]
    
    create_admin(username, email, phone_number, password) 