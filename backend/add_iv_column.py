import sqlite3

conn = sqlite3.connect("military_chat.db")
c = conn.cursor()

try:
    c.execute(
        "ALTER TABLE messages ADD COLUMN iv TEXT"
    )
    print("iv column added successfully")
except Exception as e:
    print(e)

conn.commit()
conn.close()