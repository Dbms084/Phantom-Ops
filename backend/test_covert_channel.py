import time
import os
import sys

# Ensure the backend directory is in the import path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.stego.tcp_timestamp import start_covert_listener, send_ack_via_tcp_timestamp
from src.database import engine, Base, SessionLocal
from src.models import Message, User, Project

def test_covert_channel():
    print("Initializing test database...")
    Base.metadata.create_all(bind=engine)
    
    db = SessionLocal()
    # Add a mock user and project
    user = db.query(User).filter(User.username == "test_user").first()
    if not user:
        user = User(username="test_user")
        db.add(user)
        db.commit()
        db.refresh(user)
        
    # Create a project for the user
    project = db.query(Project).filter(Project.name == "test_project").first()
    if not project:
        project = Project(name="test_project", created_by=user.id)
        db.add(project)
        db.commit()
        db.refresh(project)
        
    msg = Message(
        sender_id=user.id,
        project_id=project.id,
        content="Covert channel test message",
        sensitivity="high",
        is_destroyed=False
    )
    db.add(msg)
    db.commit()
    db.refresh(msg)
    
    msg_id = int(msg.id) if msg.id is not None else 0  # type: ignore[arg-type]
    print(f"Created test message in DB. ID: {msg_id}, is_destroyed: {bool(msg.is_destroyed)}")
    db.close()
    
    # Start the sniffer listener
    listener_thread = start_covert_listener(port=9999)
    time.sleep(1) # Let sniffer warm up
    
    # Trigger sending packet
    print("Triggering packet send via Scapy...")
    send_ack_via_tcp_timestamp(message_id=msg_id, sender_ip="127.0.0.1", sender_port=9999)
    
    # Wait for sniffer to receive and update DB
    print("Waiting for packet sniffer processing...")
    time.sleep(3)
    
    db = SessionLocal()
    updated_msg = db.query(Message).filter(Message.id == msg_id).first()
    
    if updated_msg is None:
        print("\nFAILURE: Message not found in database post-test.")
        db.close()
        return
        
    is_destroyed = bool(updated_msg.is_destroyed)
    print(f"Post-test check in DB. Message ID: {msg_id}, is_destroyed: {is_destroyed}")
    
    if is_destroyed:
        print("\nSUCCESS: TCP Timestamp stego successfully transmitted the message_id and marked it destroyed in database!")
    else:
        print("\nFAILURE: Message was not marked destroyed.")
        
    db.close()

if __name__ == "__main__":
    test_covert_channel()