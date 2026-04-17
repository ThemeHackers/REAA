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
from rich.console import Console
from rich.panel import Panel

console = Console()

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app
from models import db, Job, ChatHistory, SecurityReport

def migrate_jobs():
    """Migrate job data from file system to database"""
    data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')

    if not os.path.exists(data_dir):
        console.print(f"[red]Data directory not found: {data_dir}[/red]")
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
                console.print(f"[yellow]Skipping {job_id}: no status.json found[/yellow]")
                continue

            with open(status_file, 'r') as f:
                status_data = json.load(f)

            existing_job = Job.query.filter_by(id=job_id).first()
            if existing_job:
                console.print(f"[yellow]Skipping {job_id}: already exists in database[/yellow]")
                continue
            
            job = Job(
                id=job_id,
                user_id='system', 
                filename=status_data.get('filename', 'Unknown'),
                file_path=job_path,
                status=status_data.get('status', 'unknown'),
                priority=5,  
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
            console.print(f"[green]Migrated job: {job_id}[/green]")

        except Exception as e:
            error_msg = f"Error migrating {job_id}: {str(e)}"
            console.print(f"[red]{error_msg}[/red]")
            errors.append(error_msg)

    try:
        db.session.commit()
        console.print(f"\n[green]Migration completed successfully![/green]")
        console.print(f"[cyan]Jobs migrated: {jobs_migrated}[/cyan]")
        if errors:
            console.print(f"\n[red]Errors encountered: {len(errors)}[/red]")
            for error in errors:
                console.print(f"  [red]-[/red] {error}")
    except Exception as e:
        db.session.rollback()
        console.print(f"[red]Error committing to database: {str(e)}[/red]")

def create_default_admin():
    """Create default admin user"""
    from models import User

    admin_password = os.getenv('ADMIN_PASSWORD')
    if not admin_password:
        console.print("[red]ERROR: ADMIN_PASSWORD environment variable is required[/red]")
        console.print("[yellow]Please set ADMIN_PASSWORD before running migration[/yellow]")
        raise ValueError("ADMIN_PASSWORD environment variable is required for security")

    admin_username = os.getenv('ADMIN_USERNAME', 'admin')
    admin_email = os.getenv('ADMIN_EMAIL', 'admin@ai-reverse-engineering.local')

    admin = User.query.filter_by(username=admin_username).first()
    if admin:
        console.print("[yellow]Admin user already exists[/yellow]")
        return

    admin = User(
        username=admin_username,
        email=admin_email,
        role='admin'
    )
    admin.set_password(admin_password)

    db.session.add(admin)
    db.session.commit()
    console.print(f"[green]Created admin user (username: {admin_username})[/green]")
    console.print("[yellow]Remember to keep your password secure![/yellow]")

if __name__ == '__main__':
    with app.app_context():
        console.print(Panel(
            "[bold cyan]Starting data migration...[/bold cyan]",
            title="[bold]REAA Data Migration[/bold]",
            border_style="cyan"
        ))

        migrate_jobs()

        console.print(Panel(
            "[bold cyan]Creating default admin user...[/bold cyan]",
            title="[bold]Admin Setup[/bold]",
            border_style="cyan"
        ))

        create_default_admin()

        console.print(Panel(
            "[bold green]Migration process completed![/bold green]",
            title="[bold]Done[/bold]",
            border_style="green"
        ))
