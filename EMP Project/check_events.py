from app import app, db, Event, TicketType

def check_events():
    with app.app_context():
        events = Event.query.all()
        print("\nEvents in database:")
        for event in events:
            print(f"\nEvent: {event.title}")
            print(f"ID: {event.id}")
            print(f"Organizer: {event.organizer.username if event.organizer else 'None'}")
            print("\nTicket Types:")
            for ticket in event.ticket_types:
                print(f"- {ticket.name}: ${ticket.price} ({ticket.available} available)")
            print("-" * 50)

if __name__ == "__main__":
    check_events() 