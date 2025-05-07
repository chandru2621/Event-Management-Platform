from app import app, db, Event
from datetime import datetime, timedelta

def update_event():
    with app.app_context():
        # Get the event
        event = Event.query.get(1)  # Assuming event ID is 1
        if not event:
            print("Event not found!")
            return

        # Update event details
        event.description = "Join us for a wonderful birthday celebration! There will be food, music, and lots of fun activities."
        event.start_time = datetime.now() + timedelta(days=7)  # Event in 7 days
        event.end_time = event.start_time + timedelta(hours=3)  # 3-hour event
        event.venue = "Crystal Hall, 123 Party Street"
        event.timezone = "America/New_York"
        event.max_attendees = 100

        # Save changes
        db.session.commit()
        print(f"Updated event '{event.title}' with required details")

if __name__ == "__main__":
    update_event() 