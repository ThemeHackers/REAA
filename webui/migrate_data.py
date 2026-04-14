#!/usr/bin/env python3
"""
Data Migration Script
Migrates existing file-based job data to database
"""

import os
import sys
import json
import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app
from models import db, Job, ChatHistory, SecurityReport

def migrate_jobs():
    """Migrate job data from file system to database"""
    data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
    
    if not os.path.exists(data_dir):
        print(f"Data directory not found: {data_dir}")
        return
    
    jobs_migrated = 0
    errors = []
    
    for job_id in os.listdir(data_dir):
        job_path = os.path.join(data_dir, job_id)
        
        if not os.path.isdir(job_path):
            continue
        
        try:
            status_file = os.path.join(job_path, 'status.json')
            if not os.path.exists(status_file):
                print(f"Skipping {job_id}: no status.json found")
                continue
            
            with open(status_file, 'r') as f:
                status_data = json.load(f)
            
            existing_job = Job.query.filter_by(id=job_id).first()
            if existing_job:
                print(f"Skipping {job_id}: already exists in database")
                continue
            
            job = Job(
                id=job_id,
                user_id='system',  # Default to system user for migrated jobs
                filename=status_data.get('filename', 'Unknown'),
                file_path=job_path,
                status=status_data.get('status', 'unknown'),
                priority=5,  # Default priority
                file_size=status_data.get('file_size'),
                created_at=datetime.datetime.fromtimestamp(status_data.get('created_at', 0)) if status_data.get('created_at') else datetime.datetime.utcnow(),
                error_message=status_data.get('error_message')
            )
            
            chat_file = os.path.join(job_path, 'chat_history.json')
            if os.path.exists(chat_file):
                with open(chat_file, 'r') as f:
                    chat_data = json.load(f)
                    
                for message in chat_data:
                    chat_history = ChatHistory(
                        job_id=job_id,
                        role=message.get('role'),
                        content=message.get('content'),
                        timestamp=datetime.datetime.fromtimestamp(message.get('timestamp', 0)) if message.get('timestamp') else datetime.datetime.utcnow()
                    )
                    db.session.add(chat_history)
            
            security_file = os.path.join(job_path, 'security_report.json')
            if os.path.exists(security_file):
                with open(security_file, 'r') as f:
                    security_data = json.load(f)
                    
                security_report = SecurityReport(
                    job_id=job_id,
                    report_type='comprehensive',
                    findings=security_data
                )
                db.session.add(security_report)
            
            db.session.add(job)
            jobs_migrated += 1
            print(f"Migrated job: {job_id}")
            
        except Exception as e:
            error_msg = f"Error migrating {job_id}: {str(e)}"
            print(error_msg)
            errors.append(error_msg)
    
    try:
        db.session.commit()
        print(f"\nMigration completed successfully!")
        print(f"Jobs migrated: {jobs_migrated}")
        if errors:
            print(f"\nErrors encountered: {len(errors)}")
            for error in errors:
                print(f"  - {error}")
    except Exception as e:
        db.session.rollback()
        print(f"Error committing to database: {str(e)}")

def create_default_admin():
    """Create default admin user"""
    from models import User
    
    admin = User.query.filter_by(username='admin').first()
    if admin:
        print("Admin user already exists")
        return
    
    admin = User(
        username='admin',
        email='admin@ai-reverse-engineering.local',
        role='admin'
    )
    admin.set_password('admin123')
    
    db.session.add(admin)
    db.session.commit()
    print("Created default admin user (username: admin, password: admin123)")
    print("Please change the default password after first login!")

if __name__ == '__main__':
    with app.app_context():
        print("Starting data migration...")
        print("=" * 50)
        
        migrate_jobs()
        
        print("\n" + "=" * 50)
        
        create_default_admin()
        
        print("\nMigration process completed!")
