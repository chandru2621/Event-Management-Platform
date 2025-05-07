from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_file, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime, timedelta
import pytz
from werkzeug.security import generate_password_hash, check_password_hash
from decimal import Decimal
from flask_mail import Mail, Message
import stripe
import os
from sqlalchemy import func
import secrets
import csv
from io import StringIO
from dotenv import load_dotenv
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo
import logging
from flask_caching import Cache
from flask_compress import Compress
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import redis

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')

# Performance configurations
app.config['SQLALCHEMY_POOL_SIZE'] = 10
app.config['SQLALCHEMY_MAX_OVERFLOW'] = 20
app.config['SQLALCHEMY_POOL_TIMEOUT'] = 30
app.config['SQLALCHEMY_POOL_RECYCLE'] = 1800

# Cache configuration
cache = Cache(app, config={
    'CACHE_TYPE': 'SimpleCache',
    'CACHE_DEFAULT_TIMEOUT': 300
})

# Compression configuration
Compress(app)

# Rate limiting configuration
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Database Configuration
try:
    # Get database URI from environment or use default
    db_uri = os.getenv('SQLALCHEMY_DATABASE_URI')
    if not db_uri:
        logger.warning("SQLALCHEMY_DATABASE_URI not found in environment variables, using default")
        db_uri = 'mysql+pymysql://root:root@localhost/event_management'
    
    logger.info(f"Using database URI: {db_uri}")
    
    app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_size': 5,
        'pool_recycle': 3600,
        'pool_pre_ping': True,
        'pool_timeout': 30,
        'max_overflow': 10,
        'echo': True,  # Enable SQL query logging
        'connect_args': {
            'connect_timeout': 10
        }
    }

    # Initialize SQLAlchemy
    db = SQLAlchemy(app)

    # Test database connection
    with app.app_context():
        db.engine.connect()
        logger.info("Database connection successful")
except Exception as e:
    logger.error(f"Database configuration error: {str(e)}")
    raise

# Email Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = ('EventHub', os.getenv('MAIL_USERNAME'))

# Stripe configuration
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
if not stripe.api_key:
    logger.warning("STRIPE_SECRET_KEY not found in environment variables. Payment features will be disabled.")
    stripe.api_key = 'sk_test_dummy_key'  # Dummy key for development

app.config['STRIPE_PUBLIC_KEY'] = os.getenv('STRIPE_PUBLIC_KEY')
if not app.config['STRIPE_PUBLIC_KEY']:
    logger.warning("STRIPE_PUBLIC_KEY not found in environment variables. Payment features will be disabled.")
    app.config['STRIPE_PUBLIC_KEY'] = 'pk_test_dummy_key'  # Dummy key for development

app.config['STRIPE_WEBHOOK_SECRET'] = os.getenv('STRIPE_WEBHOOK_SECRET')

# Log Stripe configuration (without exposing the secret key)
logger.info("Stripe configuration loaded")
logger.info(f"Stripe public key: {app.config['STRIPE_PUBLIC_KEY'][:8]}...")
logger.info(f"Stripe webhook secret: {'Configured' if app.config['STRIPE_WEBHOOK_SECRET'] else 'Not configured'}")

# Initialize extensions
login_manager = LoginManager(app)
login_manager.login_view = 'login'
mail = Mail(app)

# Initialize database tables and event listeners
with app.app_context():
    try:
        # Add SQLAlchemy event listeners for better debugging
        @db.event.listens_for(db.engine, 'connect')
        def connect(dbapi_connection, connection_record):
            logger.debug('Database connection established')

        @db.event.listens_for(db.engine, 'checkout')
        def checkout(dbapi_connection, connection_record, connection_proxy):
            logger.debug('Database connection checked out from pool')

        @db.event.listens_for(db.engine, 'checkin')
        def checkin(dbapi_connection, connection_record):
            logger.debug('Database connection returned to pool')

        # Test database connection
        with db.engine.connect() as conn:
            conn.execute(db.text('SELECT 1'))
        logger.info("Database connection successful")
        
        # Create tables
        db.create_all()
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Database initialization error: {str(e)}")
        raise

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    events = db.relationship('Event', backref='organizer', lazy=True)

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    venue = db.Column(db.String(200), nullable=False)
    timezone = db.Column(db.String(50), nullable=False)
    is_recurring = db.Column(db.Boolean, default=False)
    recurrence_pattern = db.Column(db.String(50))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    max_attendees = db.Column(db.Integer, nullable=True)

class TicketType(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    available = db.Column(db.Integer, nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    event = db.relationship('Event', backref=db.backref('ticket_types', lazy=True))

class PromoCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(20), unique=True, nullable=False)
    discount_percent = db.Column(db.Numeric(5, 2), nullable=False)
    max_uses = db.Column(db.Integer, nullable=True)
    current_uses = db.Column(db.Integer, default=0)
    valid_from = db.Column(db.DateTime, nullable=False)
    valid_until = db.Column(db.DateTime, nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    event = db.relationship('Event', backref=db.backref('promo_codes', lazy=True))

class Referral(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    referrer_id = db.Column(db.Integer, db.ForeignKey('attendee.id'), nullable=False)
    referred_id = db.Column(db.Integer, db.ForeignKey('attendee.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    referrer = db.relationship('Attendee', foreign_keys=[referrer_id], backref='referrals_made')
    referred = db.relationship('Attendee', foreign_keys=[referred_id], backref='referrals_received')
    event = db.relationship('Event', backref='referrals')

class Attendee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    company = db.Column(db.String(100), nullable=True)
    ticket_type_id = db.Column(db.Integer, db.ForeignKey('ticket_type.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    registration_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='registered')  # registered, waitlisted, cancelled
    ticket_type = db.relationship('TicketType', backref='attendees')
    event = db.relationship('Event', backref='attendees')
    promo_code_id = db.Column(db.Integer, db.ForeignKey('promo_code.id'), nullable=True)
    promo_code = db.relationship('PromoCode', backref='attendees')
    referred_by_id = db.Column(db.Integer, db.ForeignKey('attendee.id'), nullable=True)
    referred_by = db.relationship('Attendee', remote_side=[id], backref='referred_attendees')
    checked_in = db.Column(db.Boolean, default=False)
    check_in_time = db.Column(db.DateTime, nullable=True)

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    attendee_id = db.Column(db.Integer, db.ForeignKey('attendee.id'), nullable=False)
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    currency = db.Column(db.String(3), default='USD')
    status = db.Column(db.String(20), nullable=False)  # succeeded, failed, pending
    stripe_payment_intent_id = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    attendee = db.relationship('Attendee', backref='payments')

class OnSpotRegistration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    attendee_id = db.Column(db.Integer, db.ForeignKey('attendee.id'), nullable=False)
    registration_date = db.Column(db.DateTime, default=datetime.utcnow)
    payment_status = db.Column(db.String(20), default='pending')  # pending, completed, cancelled
    payment_confirmation_date = db.Column(db.DateTime, nullable=True)
    payment_confirmed_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    notes = db.Column(db.Text, nullable=True)
    attendee = db.relationship('Attendee', backref='onspot_registration')
    confirmed_by = db.relationship('User', backref='confirmed_payments')

# Forms
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@cache.memoize(timeout=300)
def get_upcoming_events():
    try:
        return Event.query.filter(
            Event.start_time >= datetime.utcnow()
        ).order_by(Event.start_time).all()
    except Exception as e:
        logger.error(f"Error fetching upcoming events: {str(e)}")
        return []

@app.route('/')
@limiter.limit("30 per minute")
def index():
    try:
        # Check if user is logged in
        is_logged_in = current_user.is_authenticated
        
        if not is_logged_in:
            flash('Please log in to view and register for events.', 'info')
            return render_template('index.html', events=[], is_logged_in=False)
            
        # Get all upcoming events
        events = Event.query.filter(
            Event.start_time >= datetime.utcnow()
        ).order_by(Event.start_time).all()
        
        if not events:
            logger.info("No upcoming events found")
            flash('No upcoming events found.', 'info')
        
        # Get ticket types for each event
        for event in events:
            event.ticket_types = TicketType.query.filter_by(event_id=event.id).all()
        
        return render_template('index.html', events=events, is_logged_in=is_logged_in)
    except Exception as e:
        logger.error(f"Error in index route: {str(e)}")
        flash('An error occurred while loading the page. Please try again later.', 'error')
        return render_template('index.html', events=[], is_logged_in=False)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        try:
            user = User.query.filter_by(email=form.email.data).first()
            if user and check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('index'))
            else:
                flash('Invalid email or password', 'error')
        except Exception as e:
            logger.error(f"Error in login route: {str(e)}")
            flash('An error occurred during login', 'error')
    
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            if User.query.filter_by(email=form.email.data).first():
                flash('Email already registered', 'error')
                return redirect(url_for('register'))
            
            if User.query.filter_by(username=form.username.data).first():
                flash('Username already taken', 'error')
                return redirect(url_for('register'))
            
            hashed_password = generate_password_hash(form.password.data)
            user = User(username=form.username.data, email=form.email.data, password=hashed_password)
            db.session.add(user)
            db.session.commit()
            flash('Your account has been created! You can now log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error in register route: {str(e)}")
            flash('An error occurred during registration', 'error')
    
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    try:
        # Clear all session data
        session.clear()
        # Logout the user
        logout_user()
        # Clear any flash messages
        flash('You have been successfully logged out.', 'success')
        return redirect(url_for('index'))
    except Exception as e:
        logger.error(f"Error during logout: {str(e)}")
        flash('An error occurred during logout. Please try again.', 'error')
        return redirect(url_for('index'))

@app.route('/create_event', methods=['GET', 'POST'])
@login_required
def create_event():
    if request.method == 'POST':
        try:
            title = request.form['title']
            description = request.form['description']
            start_time = datetime.strptime(request.form['start_time'], '%Y-%m-%dT%H:%M')
            end_time = datetime.strptime(request.form['end_time'], '%Y-%m-%dT%H:%M')
            venue = request.form['venue']
            timezone = request.form['timezone']
            is_recurring = 'is_recurring' in request.form
            recurrence_pattern = request.form.get('recurrence_pattern')
            max_attendees = request.form.get('max_attendees', type=int)

            event = Event(
                title=title,
                description=description,
                start_time=start_time,
                end_time=end_time,
                venue=venue,
                timezone=timezone,
                is_recurring=is_recurring,
                recurrence_pattern=recurrence_pattern,
                user_id=current_user.id,
                max_attendees=max_attendees
            )
            
            db.session.add(event)
            db.session.commit()

            # Add ticket types
            ticket_types = request.form.getlist('ticket_name[]')
            ticket_prices = request.form.getlist('ticket_price[]')
            ticket_quantities = request.form.getlist('ticket_quantity[]')

            for name, price, quantity in zip(ticket_types, ticket_prices, ticket_quantities):
                if name and price and quantity:
                    ticket_type = TicketType(
                        name=name,
                        price=Decimal(price),
                        quantity=int(quantity),
                        available=int(quantity),
                        event_id=event.id
                    )
                    db.session.add(ticket_type)

            db.session.commit()
            flash('Event created successfully!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error in create_event route: {str(e)}")
            flash('An error occurred while creating the event', 'error')
    
    return render_template('create_event.html', timezones=pytz.common_timezones)

@app.route('/event/<int:event_id>')
def view_event(event_id):
    try:
        event = Event.query.get_or_404(event_id)
        # Get ticket types for the event
        ticket_types = TicketType.query.filter_by(event_id=event_id).all()
        # Get organizer info
        organizer = User.query.get(event.user_id)
        return render_template('event_details.html', event=event, ticket_types=ticket_types, organizer=organizer)
    except Exception as e:
        logger.error(f"Error in view_event route: {str(e)}")
        flash('An error occurred while loading the event details', 'error')
        return redirect(url_for('index'))

@app.route('/event/<int:event_id>/promo_codes', methods=['GET', 'POST'])
@login_required
def manage_promo_codes(event_id):
    event = Event.query.get_or_404(event_id)
    if event.user_id != current_user.id:
        flash('You do not have permission to manage this event.')
        return redirect(url_for('view_event', event_id=event_id))

    if request.method == 'POST':
        discount = float(request.form['discount'])
        max_uses = int(request.form['max_uses']) if request.form['max_uses'] else None
        valid_from = datetime.strptime(request.form['valid_from'], '%Y-%m-%dT%H:%M')
        valid_until = datetime.strptime(request.form['valid_until'], '%Y-%m-%dT%H:%M')
        
        # Generate a unique promo code
        code = secrets.token_urlsafe(8).upper()[:8]
        while PromoCode.query.filter_by(code=code).first():
            code = secrets.token_urlsafe(8).upper()[:8]

        promo_code = PromoCode(
            code=code,
            discount_percent=discount,
            max_uses=max_uses,
            valid_from=valid_from,
            valid_until=valid_until,
            event_id=event_id
        )
        
        db.session.add(promo_code)
        db.session.commit()
        flash('Promo code created successfully!')
        return redirect(url_for('manage_promo_codes', event_id=event_id))

    return render_template('manage_promo_codes.html', event=event)

@app.route('/event/<int:event_id>/referral_stats')
@login_required
def referral_stats(event_id):
    event = Event.query.get_or_404(event_id)
    if event.user_id != current_user.id:
        flash('You do not have permission to view these statistics.')
        return redirect(url_for('view_event', event_id=event_id))

    # Get referral statistics
    total_referrals = len(event.referrals)
    top_referrers = db.session.query(
        Attendee.name,
        func.count(Referral.id).label('referral_count')
    ).join(Referral, Referral.referrer_id == Attendee.id)\
     .filter(Referral.event_id == event_id)\
     .group_by(Attendee.id)\
     .order_by(func.count(Referral.id).desc())\
     .limit(5).all()

    return render_template('referral_stats.html', 
                         event=event,
                         total_referrals=total_referrals,
                         top_referrers=top_referrers)

@app.route('/event/<int:event_id>/register', methods=['GET', 'POST'])
def register_attendee(event_id):
    try:
        event = Event.query.get_or_404(event_id)
        ticket_types = TicketType.query.filter_by(event_id=event_id).all()
        
        if not ticket_types:
            flash('No tickets available for this event.', 'error')
            return redirect(url_for('view_event', event_id=event_id))
        
        # Initialize the form
        form = FlaskForm()
        
        if request.method == 'POST':
            try:
                # Get form data
                name = request.form.get('name')
                email = request.form.get('email')
                phone = request.form.get('phone')
                company = request.form.get('company')
                ticket_type_id = request.form.get('ticket_type')
                quantity = int(request.form.get('quantity', 1))
                payment_method = request.form.get('payment_method')
                
                # Validate required fields
                if not all([name, email, ticket_type_id, payment_method]):
                    flash('Please fill in all required fields.', 'error')
                    return redirect(url_for('register_attendee', event_id=event_id))
                
                # Validate email format
                if '@' not in email or '.' not in email:
                    flash('Please enter a valid email address.', 'error')
                    return redirect(url_for('register_attendee', event_id=event_id))
                
                ticket_type = TicketType.query.get_or_404(ticket_type_id)
                
                # Check if ticket is available
                if ticket_type.available < quantity:
                    flash(f'Sorry, only {ticket_type.available} tickets remaining.', 'error')
                    return redirect(url_for('register_attendee', event_id=event_id))
                
                # Check if event is full
                if event.max_attendees and len(event.attendees) + quantity > event.max_attendees:
                    status = 'waitlisted'
                else:
                    status = 'registered'
                
                # Calculate final price
                final_price = float(ticket_type.price) * quantity
                
                # Create attendee record
                attendee = Attendee(
                    name=name,
                    email=email,
                    phone=phone,
                    company=company,
                    ticket_type_id=ticket_type_id,
                    event_id=event_id,
                    status=status
                )
                db.session.add(attendee)
                db.session.flush()  # Get attendee ID without committing
                
                # Create payment record
                payment = Payment(
                    attendee_id=attendee.id,
                    amount=final_price,
                    currency='USD',
                    status='pending',
                    stripe_payment_intent_id='pending'
                )
                db.session.add(payment)
                
                # Update ticket availability
                ticket_type.available -= quantity
                
                try:
                    db.session.commit()
                    flash('Registration successful!', 'success')
                    
                    # Store attendee data in session for payment processing
                    session['attendee_data'] = {
                        'name': name,
                        'email': email,
                        'phone': phone,
                        'company': company,
                        'ticket_type_id': ticket_type_id,
                        'event_id': event_id,
                        'status': status,
                        'final_price': final_price,
                        'quantity': quantity,
                        'promo_code_id': None
                    }
                    
                    if payment_method == 'onspot':
                        return redirect(url_for('process_onspot_payment'))
                    else:
                        # Create Stripe payment intent
                        payment_intent = stripe.PaymentIntent.create(
                            amount=int(final_price * 100),  # Convert to cents
                            currency='usd',
                            metadata={
                                'event_id': event_id,
                                'ticket_type_id': ticket_type_id,
                                'attendee_name': name,
                                'attendee_email': email,
                                'quantity': quantity
                            },
                            payment_method_types=['card'],
                            description=f"Event Registration - {name}",
                            receipt_email=email
                        )
                        
                        session['payment_intent_id'] = payment_intent.id
                        return redirect(url_for('process_payment'))
                        
                except Exception as e:
                    db.session.rollback()
                    logger.error(f"Database error in register_attendee: {str(e)}")
                    flash('An error occurred while saving your registration.', 'error')
                    return redirect(url_for('register_attendee', event_id=event_id))
                    
            except Exception as e:
                logger.error(f"Error processing registration: {str(e)}")
                flash('An error occurred while processing your registration.', 'error')
                return redirect(url_for('register_attendee', event_id=event_id))
        
        # GET request - show registration form
        return render_template('register_attendee.html', 
                            event=event, 
                            ticket_types=ticket_types,
                            form=form,
                            stripe_public_key=app.config['STRIPE_PUBLIC_KEY'])
                            
    except Exception as e:
        logger.error(f"Error in register_attendee route: {str(e)}")
        flash('An error occurred during registration.', 'error')
        return redirect(url_for('view_event', event_id=event_id))

@app.route('/process_payment', methods=['GET', 'POST'])
def process_payment():
    try:
        # Get attendee data from session
        attendee_data = session.get('attendee_data')
        if not attendee_data:
            flash('Session expired. Please try registering again.', 'error')
            return redirect(url_for('index'))

        # Get event data
        event = Event.query.get(attendee_data['event_id'])
        if not event:
            flash('Event not found.', 'error')
            return redirect(url_for('index'))

        if request.method == 'POST':
            try:
                # Get payment intent from session
                payment_intent_id = session.get('payment_intent_id')
                if not payment_intent_id:
                    raise Exception('Payment session expired')

                # Retrieve payment intent
                payment_intent = stripe.PaymentIntent.retrieve(payment_intent_id)
                
                if payment_intent.status == 'succeeded':
                    # Create attendee record
                    attendee = Attendee(
                        name=attendee_data['name'],
                        email=attendee_data['email'],
                        phone=attendee_data['phone'],
                        company=attendee_data['company'],
                        ticket_type_id=attendee_data['ticket_type_id'],
                        event_id=attendee_data['event_id'],
                        status='registered'
                    )
                    db.session.add(attendee)
                    db.session.flush()  # Get attendee ID

                    # Update ticket availability
                    ticket_type = TicketType.query.get(attendee_data['ticket_type_id'])
                    if ticket_type:
                        ticket_type.available -= attendee_data['quantity']
                        if ticket_type.available < 0:
                            ticket_type.available = 0

                    # Create payment record
                    payment = Payment(
                        attendee_id=attendee.id,
                        amount=attendee_data['final_price'],
                        currency='USD',
                        status='succeeded',
                        stripe_payment_intent_id=payment_intent_id
                    )
                    db.session.add(payment)

                    try:
                        db.session.commit()
                        # Send confirmation email
                        send_confirmation_email(attendee)
                        
                        # Clear session data
                        session.pop('attendee_data', None)
                        session.pop('payment_intent_id', None)
                        
                        flash('Registration successful! A confirmation email has been sent.', 'success')
                        return redirect(url_for('view_event', event_id=event.id))
                    except Exception as e:
                        db.session.rollback()
                        logger.error(f"Database error in process_payment: {str(e)}")
                        raise Exception('Error saving registration details')
                else:
                    raise Exception('Payment not completed')

            except Exception as e:
                logger.error(f"Error processing payment: {str(e)}")
                flash(str(e), 'error')
                return redirect(url_for('register_attendee', event_id=event.id))

        # GET request - show payment form
        return render_template('process_payment.html',
                            event=event,
                            attendee_data=attendee_data,
                            stripe_public_key=app.config['STRIPE_PUBLIC_KEY'])

    except Exception as e:
        logger.error(f"Error in process_payment route: {str(e)}")
        flash('An error occurred during payment processing.', 'error')
        return redirect(url_for('index'))

@app.route('/payment_success/<int:event_id>')
def payment_success(event_id):
    try:
        # Retrieve the payment intent
        payment_intent = stripe.PaymentIntent.retrieve(session.get('payment_intent_id'))
        
        if payment_intent.status == 'succeeded':
            attendee_data = session.get('attendee_data')
            if not attendee_data:
                raise Exception('Attendee data not found in session')
            
            # Create attendee record
            attendee = Attendee(
                name=attendee_data['name'],
                email=attendee_data['email'],
                phone=attendee_data['phone'],
                company=attendee_data['company'],
                ticket_type_id=attendee_data['ticket_type_id'],
                event_id=attendee_data['event_id'],
                status=attendee_data['status'],
                promo_code_id=attendee_data['promo_code_id']
            )
            
            # Update ticket availability
            ticket_type = TicketType.query.get(attendee.ticket_type_id)
            if attendee.status == 'registered':
                ticket_type.available -= 1
            
            # Update promo code usage
            if attendee.promo_code_id:
                promo_code = PromoCode.query.get(attendee.promo_code_id)
                promo_code.current_uses += 1
            
            # Create payment record
            payment = Payment(
                attendee=attendee,
                amount=attendee_data['final_price'],
                currency='USD',
                status='succeeded',
                stripe_payment_intent_id=payment_intent.id
            )
            
            db.session.add(attendee)
            db.session.add(payment)
            db.session.commit()
            
            # Send confirmation email
            send_confirmation_email(attendee)
            
            # Clear session data
            session.pop('payment_intent_id', None)
            session.pop('attendee_data', None)
            
            flash('Payment successful! A confirmation email has been sent.')
            return redirect(url_for('view_event', event_id=event_id))
        else:
            flash('Payment was not successful. Please try again.')
            return redirect(url_for('view_event', event_id=event_id))
            
    except Exception as e:
        flash(f'Error confirming payment: {str(e)}')
        return redirect(url_for('view_event', event_id=event_id))

@app.route('/webhook', methods=['POST'])
def stripe_webhook():
    payload = request.get_data()
    sig_header = request.headers.get('Stripe-Signature')
    
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, app.config['STRIPE_WEBHOOK_SECRET']
        )
    except ValueError as e:
        # Invalid payload
        return jsonify({'error': str(e)}), 400
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        return jsonify({'error': str(e)}), 400
    
    # Handle the event
    if event.type == 'payment_intent.succeeded':
        payment_intent = event.data.object
        # Update payment status in database
        payment = Payment.query.filter_by(stripe_payment_intent_id=payment_intent.id).first()
        if payment:
            payment.status = 'succeeded'
            db.session.commit()
    
    return jsonify({'status': 'success'})

@app.route('/dashboard')
@login_required
def dashboard():
    # Get organizer's events
    events = Event.query.filter_by(user_id=current_user.id).all()
    
    # Calculate statistics
    total_events = len(events)
    total_registrations = sum(len(event.attendees) for event in events)
    total_revenue = sum(
        sum(ticket.price * (ticket.quantity - ticket.available) for ticket in event.ticket_types)
        for event in events
    )
    
    # Get recent registrations (last 7 days)
    recent_registrations = Attendee.query.join(Event).filter(
        Event.user_id == current_user.id,
        Attendee.registration_date >= datetime.utcnow() - timedelta(days=7)
    ).order_by(Attendee.registration_date.desc()).all()
    
    # Get upcoming events
    upcoming_events = Event.query.filter(
        Event.user_id == current_user.id,
        Event.start_time > datetime.utcnow()
    ).order_by(Event.start_time).all()
    
    # Get ticket sales by type
    ticket_sales = {}
    for event in events:
        for ticket_type in event.ticket_types:
            sales = ticket_type.quantity - ticket_type.available
            if ticket_type.name in ticket_sales:
                ticket_sales[ticket_type.name] += sales
            else:
                ticket_sales[ticket_type.name] = sales
    
    # Get registration status counts
    status_counts = {
        'registered': Attendee.query.join(Event).filter(
            Event.user_id == current_user.id,
            Attendee.status == 'registered'
        ).count(),
        'waitlisted': Attendee.query.join(Event).filter(
            Event.user_id == current_user.id,
            Attendee.status == 'waitlisted'
        ).count()
    }
    
    return render_template('dashboard.html',
                         total_events=total_events,
                         total_registrations=total_registrations,
                         total_revenue=total_revenue,
                         recent_registrations=recent_registrations,
                         upcoming_events=upcoming_events,
                         ticket_sales=ticket_sales,
                         status_counts=status_counts)

@app.route('/event/<int:event_id>/attendees')
@login_required
def manage_attendees(event_id):
    event = Event.query.get_or_404(event_id)
    if event.user_id != current_user.id:
        flash('You do not have permission to manage this event.')
        return redirect(url_for('view_event', event_id=event_id))

    attendees = Attendee.query.filter_by(event_id=event_id).order_by(Attendee.registration_date.desc()).all()
    return render_template('manage_attendees.html', event=event, attendees=attendees)

@app.route('/event/<int:event_id>/attendee/<int:attendee_id>/check-in', methods=['POST'])
@login_required
def check_in_attendee(event_id, attendee_id):
    event = Event.query.get_or_404(event_id)
    if event.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403

    attendee = Attendee.query.get_or_404(attendee_id)
    if attendee.event_id != event_id:
        return jsonify({'error': 'Attendee not found'}), 404

    attendee.checked_in = True
    attendee.check_in_time = datetime.utcnow()
    db.session.commit()

    return jsonify({
        'success': True,
        'attendee': {
            'name': attendee.name,
            'check_in_time': attendee.check_in_time.strftime('%Y-%m-%d %H:%M:%S')
        }
    })

@app.route('/event/<int:event_id>/attendees/export')
@login_required
def export_attendees(event_id):
    event = Event.query.get_or_404(event_id)
    if event.user_id != current_user.id:
        flash('You do not have permission to export attendee data.')
        return redirect(url_for('view_event', event_id=event_id))

    attendees = Attendee.query.filter_by(event_id=event_id).all()
    
    # Create CSV in memory
    output = StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['Name', 'Email', 'Phone', 'Company', 'Ticket Type', 
                    'Registration Date', 'Status', 'Checked In', 'Check-in Time'])
    
    # Write data
    for attendee in attendees:
        writer.writerow([
            attendee.name,
            attendee.email,
            attendee.phone or '',
            attendee.company or '',
            attendee.ticket_type.name,
            attendee.registration_date.strftime('%Y-%m-%d %H:%M:%S'),
            attendee.status,
            'Yes' if attendee.checked_in else 'No',
            attendee.check_in_time.strftime('%Y-%m-%d %H:%M:%S') if attendee.check_in_time else ''
        ])
    
    output.seek(0)
    return send_file(
        output,
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'{event.title.replace(" ", "_")}_attendees.csv'
    )

@app.route('/event/<int:event_id>/attendees/email', methods=['GET', 'POST'])
@login_required
def email_attendees(event_id):
    event = Event.query.get_or_404(event_id)
    if event.user_id != current_user.id:
        flash('You do not have permission to email attendees.')
        return redirect(url_for('view_event', event_id=event_id))

    if request.method == 'POST':
        subject = request.form['subject']
        message = request.form['message']
        recipient_type = request.form.get('recipient_type', 'all')
        
        # Get recipients based on selection
        if recipient_type == 'all':
            recipients = [attendee.email for attendee in event.attendees]
        elif recipient_type == 'registered':
            recipients = [attendee.email for attendee in event.attendees if attendee.status == 'registered']
        elif recipient_type == 'waitlisted':
            recipients = [attendee.email for attendee in event.attendees if attendee.status == 'waitlisted']
        elif recipient_type == 'checked_in':
            recipients = [attendee.email for attendee in event.attendees if attendee.checked_in]
        else:
            recipients = []

        # Send emails
        for recipient in recipients:
            msg = Message(
                subject,
                recipients=[recipient]
            )
            msg.body = message
            mail.send(msg)

        flash(f'Emails sent successfully to {len(recipients)} attendees!')
        return redirect(url_for('manage_attendees', event_id=event_id))

    return render_template('email_attendees.html', event=event)

# Admin routes
@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('index'))
    
    total_users = User.query.count()
    total_events = Event.query.count()
    total_attendees = Attendee.query.count()
    total_revenue = db.session.query(func.sum(Payment.amount)).filter(Payment.status == 'succeeded').scalar() or 0
    
    recent_events = Event.query.order_by(Event.start_time.desc()).limit(5).all()
    recent_users = User.query.order_by(User.id.desc()).limit(5).all()
    
    return render_template('admin/dashboard.html',
                         total_users=total_users,
                         total_events=total_events,
                         total_attendees=total_attendees,
                         total_revenue=total_revenue,
                         recent_events=recent_events,
                         recent_users=recent_users)

# Temporary route to delete all users (remove in production)
@app.route('/delete_all_users')
def delete_all_users():
    try:
        # Delete all users
        User.query.delete()
        db.session.commit()
        return 'All users have been deleted successfully.'
    except Exception as e:
        db.session.rollback()
        return f'Error deleting users: {str(e)}'

@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('index'))
    
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/events')
@login_required
def admin_events():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('index'))
    
    events = Event.query.all()
    return render_template('admin/events.html', events=events)

@app.route('/admin/payments')
@login_required
def admin_payments():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('index'))
    
    payments = Payment.query.order_by(Payment.created_at.desc()).all()
    return render_template('admin/payments.html', payments=payments)

@app.route('/admin/user/<int:user_id>/toggle_admin', methods=['POST'])
@login_required
def toggle_admin_status(user_id):
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('index'))
    
    user = User.query.get_or_404(user_id)
    user.is_admin = not user.is_admin
    db.session.commit()
    flash(f'Admin status {"granted" if user.is_admin else "revoked"} for {user.username}')
    return redirect(url_for('admin_users'))

@app.route('/admin/event/<int:event_id>/delete', methods=['POST'])
@login_required
def admin_delete_event(event_id):
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.')
        return redirect(url_for('index'))
    
    event = Event.query.get_or_404(event_id)
    db.session.delete(event)
    db.session.commit()
    flash('Event deleted successfully')
    return redirect(url_for('admin_events'))

@app.route('/create_admin', methods=['GET', 'POST'])
def create_admin():
    # Check if any admin exists
    if User.query.filter_by(is_admin=True).first():
        flash('Admin user already exists')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('create_admin'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists')
            return redirect(url_for('create_admin'))
        
        user = User(
            username=username,
            email=email,
            password=generate_password_hash(password),
            is_admin=True
        )
        
        db.session.add(user)
        db.session.commit()
        flash('Admin account created successfully! Please login.')
        return redirect(url_for('login'))
    
    return render_template('create_admin.html')

def send_confirmation_email(attendee):
    try:
        msg = Message(
            'Registration Confirmation - EventHub',
            recipients=[attendee.email]
        )
        msg.body = f"""
        Dear {attendee.name},

        Thank you for registering for the event. Your registration has been confirmed.

        Event Details:
        - Event: {attendee.event.title}
        - Date: {attendee.event.start_time.strftime('%B %d, %Y')}
        - Time: {attendee.event.start_time.strftime('%I:%M %p')} - {attendee.event.end_time.strftime('%I:%M %p')}
        - Venue: {attendee.event.venue}

        Ticket Type: {attendee.ticket_type.name}

        We look forward to seeing you at the event!

        Best regards,
        EventHub Team
        """
        mail.send(msg)
        return True
    except Exception as e:
        logger.error(f"Error sending confirmation email: {str(e)}")
        return False

@app.route('/process_onspot_payment', methods=['GET', 'POST'])
def process_onspot_payment():
    try:
        # Get attendee data from session
        attendee_data = session.get('attendee_data')
        if not attendee_data:
            flash('Session expired. Please try registering again.', 'error')
            return redirect(url_for('index'))

        # Get event data
        event = Event.query.get(attendee_data['event_id'])
        if not event:
            flash('Event not found.', 'error')
            return redirect(url_for('index'))

        if request.method == 'POST':
            try:
                # Create attendee record with on-spot payment status
                attendee = Attendee(
                    name=attendee_data['name'],
                    email=attendee_data['email'],
                    phone=attendee_data['phone'],
                    company=attendee_data['company'],
                    ticket_type_id=attendee_data['ticket_type_id'],
                    event_id=attendee_data['event_id'],
                    status='pending_payment',
                    promo_code_id=attendee_data['promo_code_id']
                )
                db.session.add(attendee)
                db.session.flush()  # Get attendee ID

                # Create on-spot registration record
                onspot_registration = OnSpotRegistration(
                    attendee_id=attendee.id,
                    payment_status='pending'
                )
                db.session.add(onspot_registration)

                # Create payment record
                payment = Payment(
                    attendee_id=attendee.id,
                    amount=attendee_data['final_price'],
                    currency='USD',
                    status='pending',
                    stripe_payment_intent_id='onspot_payment'
                )
                db.session.add(payment)

                db.session.commit()

                # Send confirmation email with on-spot payment instructions
                try:
                    msg = Message(
                        'Registration Confirmation - On-Spot Payment Required',
                        recipients=[attendee.email]
                    )
                    msg.body = f"""
                    Dear {attendee.name},

                    Thank you for registering for the event. Your registration is pending payment.

                    Event Details:
                    - Event: {attendee.event.title}
                    - Date: {attendee.event.start_time.strftime('%B %d, %Y')}
                    - Time: {attendee.event.start_time.strftime('%I:%M %p')} - {attendee.event.end_time.strftime('%I:%M %p')}
                    - Venue: {attendee.event.venue}

                    Payment Instructions:
                    - Please arrive 30 minutes before the event
                    - Bring a valid government-issued ID
                    - Show this confirmation email
                    - Pay the amount of USD {attendee_data['final_price']} at the registration desk

                    Ticket Type: {attendee.ticket_type.name}

                    We look forward to seeing you at the event!

                    Best regards,
                    EventHub Team
                    """
                    mail.send(msg)
                except Exception as e:
                    logger.error(f"Error sending confirmation email: {str(e)}")

                # Clear session data
                session.pop('payment_intent_id', None)
                session.pop('attendee_data', None)

                flash('Registration successful! Please check your email for payment instructions.', 'success')
                return redirect(url_for('view_event', event_id=event.id))

            except Exception as e:
                db.session.rollback()
                logger.error(f"Error processing on-spot payment: {str(e)}")
                flash('An error occurred while processing your registration.', 'error')
                return redirect(url_for('register_attendee', event_id=event.id))

        # GET request - show payment instructions
        return render_template('process_onspot_payment.html',
                            event=event,
                            attendee_data=attendee_data)

    except Exception as e:
        logger.error(f"Error in process_onspot_payment route: {str(e)}")
        flash('An error occurred during payment processing.', 'error')
        return redirect(url_for('index'))

@app.route('/event/<int:event_id>/check-in/<int:attendee_id>/confirm-payment', methods=['POST'])
@login_required
def confirm_onspot_payment(event_id, attendee_id):
    try:
        event = Event.query.get_or_404(event_id)
        if event.user_id != current_user.id:
            return jsonify({'error': 'Unauthorized'}), 403

        attendee = Attendee.query.get_or_404(attendee_id)
        if attendee.event_id != event_id:
            return jsonify({'error': 'Attendee not found'}), 404

        # Update on-spot registration
        onspot_registration = OnSpotRegistration.query.filter_by(attendee_id=attendee_id).first()
        if onspot_registration:
            onspot_registration.payment_status = 'completed'
            onspot_registration.payment_confirmation_date = datetime.utcnow()
            onspot_registration.payment_confirmed_by = current_user.id

        # Update payment status
        payment = Payment.query.filter_by(attendee_id=attendee_id).first()
        if payment:
            payment.status = 'succeeded'
            payment.stripe_payment_intent_id = f'onspot_payment_{datetime.utcnow().strftime("%Y%m%d%H%M%S")}'

        # Update attendee status
        attendee.status = 'registered'
        
        # Update ticket availability
        ticket_type = TicketType.query.get(attendee.ticket_type_id)
        ticket_type.available -= 1

        # Update promo code usage if applicable
        if attendee.promo_code_id:
            promo_code = PromoCode.query.get(attendee.promo_code_id)
            promo_code.current_uses += 1

        db.session.commit()

        return jsonify({
            'success': True,
            'message': 'Payment confirmed successfully'
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/create-payment-intent', methods=['POST'])
@limiter.limit("20 per minute")
def create_payment_intent():
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['event_id', 'quantity', 'amount', 'name', 'email']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400

        # Create payment intent with additional metadata
        intent = stripe.PaymentIntent.create(
            amount=int(float(data['amount']) * 100),  # Convert to cents
            currency='usd',
            metadata={
                'event_id': data['event_id'],
                'quantity': data['quantity'],
                'name': data['name'],
                'email': data['email'],
                'phone': data.get('phone', ''),
                'company': data.get('company', '')
            },
            payment_method_types=['card'],  # Explicitly specify payment method
            description=f"Event Registration - {data['name']}",  # Add description
            receipt_email=data['email']  # Send receipt to customer
        )

        return jsonify({
            'clientSecret': intent.client_secret,
            'publishableKey': app.config['STRIPE_PUBLIC_KEY']
        })
    except stripe.error.StripeError as e:
        logger.error(f"Stripe error creating payment intent: {str(e)}")
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Error creating payment intent: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/admin/clear_database', methods=['POST'])
@login_required
def clear_database():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    try:
        # Delete all records from tables in correct order
        Payment.query.delete()
        Attendee.query.delete()
        Referral.query.delete()
        PromoCode.query.delete()
        TicketType.query.delete()
        Event.query.delete()
        # Don't delete admin users
        User.query.filter(User.is_admin == False).delete()
        
        db.session.commit()
        flash('Database cleared successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error clearing database: {str(e)}")
        flash('An error occurred while clearing the database.', 'error')
    
    return redirect(url_for('admin_dashboard'))

# Add error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    error_msg = str(error)
    logger.error(f"Internal server error: {error_msg}")
    return render_template('500.html', error=error_msg), 500

# Add database connection check
@app.before_request
def check_db_connection():
    try:
        with db.engine.connect() as conn:
            conn.execute(db.text('SELECT 1'))
    except Exception as e:
        logger.error(f"Database connection error: {str(e)}")
        db.session.rollback()
        return render_template('500.html', error=str(e)), 500

# Add cleanup tasks
@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.remove()

# Add a test route
@app.route('/test')
def test():
    try:
        # Test database connection
        with db.engine.connect() as conn:
            conn.execute(db.text('SELECT 1'))
        return jsonify({
            'status': 'success',
            'message': 'Database connection successful',
            'database_uri': app.config['SQLALCHEMY_DATABASE_URI'].replace(
                app.config['SQLALCHEMY_DATABASE_URI'].split('@')[0],
                '***'
            )
        })
    except Exception as e:
        logger.error(f"Test route error: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

if __name__ == '__main__':
    app.run(debug=True) 