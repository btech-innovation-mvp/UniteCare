"""Safe, non-destructive PostgreSQL connectivity check for UniteCare."""

import sys
import time

from sqlalchemy import text
from sqlalchemy.exc import OperationalError, SQLAlchemyError

from app.core.config import settings
from app.db.session import engine


def check_database_connection() -> bool:
    """Verify active database connectivity with a lightweight ping.

    Validates:
    1. SELECT 1 query response.
    2. Verification of current_database() matching expected 'unitecare_db'.
    3. Verification of current_user matching expected 'unitecare_user'.

    Returns:
        True if the database responds correctly, False otherwise.
    """
    # Sanitize database URL for logging (mask password)
    masked_url = settings.DATABASE_URL
    if "@" in masked_url and ":" in masked_url:
        try:
            proto, rest = masked_url.split("://", 1)
            user_pass, host_db = rest.split("@", 1)
            user = user_pass.split(":", 1)[0]
            masked_url = f"{proto}://{user}:****@{host_db}"
        except (ValueError, IndexError):
            masked_url = "postgresql://****:****@****"

    print(f"[*] Testing PostgreSQL connection to: {masked_url}")

    start_time = time.perf_counter()
    try:
        with engine.connect() as connection:
            # 1. Test basic ping
            ping_result = connection.execute(text("SELECT 1")).scalar()
            elapsed_ms = (time.perf_counter() - start_time) * 1000

            if ping_result != 1:
                print(f"[-] Unexpected query result: {ping_result}")
                return False

            # 2. Confirm current database name and user identity
            identity_query = text("SELECT current_database(), current_user, version()")
            db_name, db_user, db_version = connection.execute(identity_query).one()

            print(f"[+] Connection SUCCESSFUL! Latency: {elapsed_ms:.2f} ms")
            print(f"[+] Connected Database : {db_name}")
            print(f"[+] Connected User     : {db_user}")
            print(f"[+] Engine Version     : {db_version.split(',')[0]}")

            # Verify it is indeed UniteCare's database and not a colliding instance
            if db_name != "unitecare_db":
                print(
                    f"[-] ERROR: Connected to unexpected database '{db_name}', expected 'unitecare_db'!"
                )
                return False

            if db_user != "unitecare_user":
                print(
                    f"[-] ERROR: Connected as unexpected user '{db_user}', expected 'unitecare_user'!"
                )
                return False

            print("[+] Verified: Connected to the dedicated UniteCare PostgreSQL instance.")
            return True

    except OperationalError as exc:
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        print(f"[-] Database connection FAILED after {elapsed_ms:.2f} ms.")
        print(f"[-] Operational Error: {exc.orig if hasattr(exc, 'orig') else exc}")
        return False
    except SQLAlchemyError as exc:
        print(f"[-] SQLAlchemy Error: {exc}")
        return False
    except OSError as exc:
        print(f"[-] OS / Network Error: {exc}")
        return False


if __name__ == "__main__":
    success = check_database_connection()
    sys.exit(0 if success else 1)
