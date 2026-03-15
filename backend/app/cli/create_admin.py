"""
CLI: Create an admin user or promote an existing user to admin.

Usage:
    docker compose -f docker-compose.prod.yml exec api \
        python -m app.cli.create_admin --email admin@sentinel.local --display-name "Admin"
"""

import argparse
import asyncio
import getpass
import sys

from sqlalchemy import select

from app.core.auth import hash_password
from app.core.database import AsyncSessionLocal
from app.models.enums import UserRole
from app.models.models import User


async def main(email: str, display_name: str) -> None:
    async with AsyncSessionLocal() as session:
        async with session.begin():
            result = await session.execute(select(User).where(User.email == email))
            existing = result.scalar_one_or_none()

            if existing:
                if existing.role == UserRole.ADMIN:
                    print(f"User {email} is already an admin.")
                    return
                answer = input(f"User {email} exists with role '{existing.role.value}'. Promote to admin? [y/N] ")
                if answer.strip().lower() != "y":
                    print("Aborted.")
                    return
                existing.role = UserRole.ADMIN
                print(f"Promoted {email} to admin.")
                return

            password = getpass.getpass("Password: ")
            confirm = getpass.getpass("Confirm password: ")
            if password != confirm:
                print("Error: passwords do not match.", file=sys.stderr)
                sys.exit(1)
            if len(password) < 8:
                print("Error: password must be at least 8 characters.", file=sys.stderr)
                sys.exit(1)

            user = User(
                email=email,
                password_hash=hash_password(password),
                display_name=display_name,
                role=UserRole.ADMIN,
            )
            session.add(user)
            print(f"Admin user {email} created successfully.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create an admin user")
    parser.add_argument("--email", required=True, help="Admin email address")
    parser.add_argument("--display-name", required=True, help="Display name")
    args = parser.parse_args()

    asyncio.run(main(args.email, args.display_name))
