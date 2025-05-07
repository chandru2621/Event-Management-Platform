import mysql.connector
from mysql.connector import Error

def create_database():
    try:
        # Connect to MySQL server
        connection = mysql.connector.connect(
            host='localhost',
            user='root',
            password='root'  # Updated to match app.py
        )
        
        if connection.is_connected():
            cursor = connection.cursor()
            
            # Create database
            cursor.execute("CREATE DATABASE IF NOT EXISTS event_management")
            print("Database created successfully")
            
            # Use the database
            cursor.execute("USE event_management")
            
            # Create tables
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    username VARCHAR(80) UNIQUE NOT NULL,
                    email VARCHAR(120) UNIQUE NOT NULL,
                    password VARCHAR(255) NOT NULL,
                    is_admin BOOLEAN DEFAULT FALSE
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS event (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    title VARCHAR(100) NOT NULL,
                    description TEXT NOT NULL,
                    start_time DATETIME NOT NULL,
                    end_time DATETIME NOT NULL,
                    venue VARCHAR(200) NOT NULL,
                    timezone VARCHAR(50) NOT NULL,
                    is_recurring BOOLEAN DEFAULT FALSE,
                    recurrence_pattern VARCHAR(50),
                    user_id INT NOT NULL,
                    max_attendees INT,
                    FOREIGN KEY (user_id) REFERENCES user(id)
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ticket_type (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    price DECIMAL(10,2) NOT NULL,
                    quantity INT NOT NULL,
                    available INT NOT NULL,
                    event_id INT NOT NULL,
                    FOREIGN KEY (event_id) REFERENCES event(id)
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS promo_code (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    code VARCHAR(20) UNIQUE NOT NULL,
                    discount_percent DECIMAL(5,2) NOT NULL,
                    max_uses INT,
                    current_uses INT DEFAULT 0,
                    valid_from DATETIME NOT NULL,
                    valid_until DATETIME NOT NULL,
                    event_id INT NOT NULL,
                    FOREIGN KEY (event_id) REFERENCES event(id)
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS attendee (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    email VARCHAR(120) NOT NULL,
                    phone VARCHAR(20),
                    company VARCHAR(100),
                    ticket_type_id INT NOT NULL,
                    event_id INT NOT NULL,
                    registration_date DATETIME DEFAULT CURRENT_TIMESTAMP,
                    status VARCHAR(20) DEFAULT 'registered',
                    promo_code_id INT,
                    referred_by_id INT,
                    checked_in BOOLEAN DEFAULT FALSE,
                    check_in_time DATETIME,
                    FOREIGN KEY (ticket_type_id) REFERENCES ticket_type(id),
                    FOREIGN KEY (event_id) REFERENCES event(id),
                    FOREIGN KEY (promo_code_id) REFERENCES promo_code(id),
                    FOREIGN KEY (referred_by_id) REFERENCES attendee(id)
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS payment (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    attendee_id INT NOT NULL,
                    amount DECIMAL(10,2) NOT NULL,
                    currency VARCHAR(3) DEFAULT 'USD',
                    status VARCHAR(20) NOT NULL,
                    stripe_payment_intent_id VARCHAR(100) NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (attendee_id) REFERENCES attendee(id)
                )
            """)
            
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS referral (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    referrer_id INT NOT NULL,
                    referred_id INT NOT NULL,
                    event_id INT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (referrer_id) REFERENCES attendee(id),
                    FOREIGN KEY (referred_id) REFERENCES attendee(id),
                    FOREIGN KEY (event_id) REFERENCES event(id)
                )
            """)
            
            print("Tables created successfully")
            
    except Error as e:
        print(f"Error: {e}")
    finally:
        if 'connection' in locals() and connection.is_connected():
            cursor.close()
            connection.close()
            print("MySQL connection closed")

if __name__ == "__main__":
    create_database() 