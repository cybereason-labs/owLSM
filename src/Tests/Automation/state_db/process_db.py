import sqlite3
import time
from typing import List, Tuple, Optional
from globals.system_related_globals import system_globals

class ProcessDB:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS processes (
                    pid INTEGER PRIMARY KEY,
                    start_time REAL NOT NULL
                )
            """)
            conn.commit()
    
    def add(self, pid: int, start_time: float = None) -> bool:
        if start_time is None:
            start_time = time.time()
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("INSERT OR REPLACE INTO processes (pid, start_time) VALUES (?, ?)", 
                           (pid, start_time))
                conn.commit()
            return True
        except sqlite3.Error:
            return False
    
    def get(self, pid: int) -> Optional[float]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT start_time FROM processes WHERE pid = ?", (pid,))
                result = cursor.fetchone()
                return result[0] if result else None
        except sqlite3.Error:
            return None
    
    def get_all(self) -> List[Tuple[int, float]]:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("SELECT pid, start_time FROM processes ORDER BY pid")
                return cursor.fetchall()
        except sqlite3.Error:
            return []
    
    def remove(self, pid: int) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute("DELETE FROM processes WHERE pid = ?", (pid,))
                conn.commit()
                return cursor.rowcount > 0
        except sqlite3.Error:
            return False
    
    def remove_all(self) -> bool:
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM processes")
                conn.commit()
            return True
        except sqlite3.Error:
            return False



process_db = ProcessDB(str(system_globals.AUTOMATION_ROOT_DIR / "process_db.sqlite"))