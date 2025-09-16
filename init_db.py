import os
from app import app, db
from models import User, CrimeReport

def init_db():
    with app.app_context():
        # Delete existing database
        db_path = os.path.join(app.instance_path, 'crimemap.db')
        if os.path.exists(db_path):
            try:
                os.remove(db_path)
            except PermissionError:
                print("Please close any applications that might be using the database file.")
                return

        # Create new database
        db.create_all()
        
        # Create admin user
        admin = User(
            username='admin',
            email='admin@example.com',
            security_answer='admin',  # Default memorable answer
            is_admin=True
        )
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()
        
        print("Admin user created successfully!")
        print("Admin credentials:")
        print("Username: admin")
        print("Password: admin123")
        print("Database initialized successfully!")

if __name__ == '__main__':
    init_db() 