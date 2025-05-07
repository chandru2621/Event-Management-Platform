from app import app, db, Event, TicketType
from decimal import Decimal

def add_ticket_type():
    with app.app_context():
        # Get the event
        event = Event.query.get(1)  # Assuming event ID is 1
        if not event:
            print("Event not found!")
            return

        # Create a new ticket type
        ticket_type = TicketType(
            name="General Admission",
            price=Decimal('50.00'),
            quantity=100,
            available=100,
            event_id=event.id
        )

        # Add to database
        db.session.add(ticket_type)
        db.session.commit()
        print(f"Added ticket type '{ticket_type.name}' to event '{event.title}'")

if __name__ == "__main__":
    add_ticket_type() 