import sqlite3
from typing import List, Optional
from globals.system_related_globals import system_globals

class FileDB:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS files (
                    path TEXT PRIMARY KEY
                )
            """)
            conn.commit()
    
    def add(self, path: str, value: str = "") -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("INSERT OR REPLACE INTO files (path) VALUES (?)", (path,))
                conn.commit()
            return True
        except sqlite3.Error:
            return False
    
    def get(self, path: str) -> Optional[str]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT path FROM files WHERE path = ?", (path,))
                result = cursor.fetchone()
                return "" if result else None
        except sqlite3.Error:
            return None
    
    def get_all(self) -> List[str]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT path FROM files ORDER BY path")
                return [row[0] for row in cursor.fetchall()]
        except sqlite3.Error:
            return []
    
    def remove(self, path: str) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("DELETE FROM files WHERE path = ?", (path,))
                conn.commit()
                return cursor.rowcount > 0
        except sqlite3.Error:
            return False
    
    def remove_all(self) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM files")
                conn.commit()
            return True
        except sqlite3.Error:
            return False


file_db = FileDB(str(system_globals.AUTOMATION_ROOT_DIR / "file_db.sqlite"))