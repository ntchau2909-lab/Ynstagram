import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_PATH = BASE_DIR / "database.db"

def create_database() -> None:
    connection = sqlite3.connect(DATABASE_PATH)

    try:
        cursor = connection.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        connection.commit()
        print("Database và các bảng đã được tạo thành công.")

    except sqlite3.Error as error:
        print(f"Lỗi khi tạo database: {error}")
    finally:
        connection.close()

if __name__ == "__main__":
    create_database()