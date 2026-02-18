import sqlite3
import os
from globals.system_related_globals import system_globals
from Utils.logger_utils import logger

class OwlsmDB:
    def __init__(self, db_path: str):
        self.db_path = db_path



    def delete_table(self, table_name: str) -> bool:
        try:
            if not os.path.exists(self.db_path):
                logger.log_info(f"owLSM DB not found at {self.db_path}, nothing to delete")
                return True
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(f"DROP TABLE IF EXISTS {table_name}")
            conn.commit()
            conn.close()
            logger.log_info(f"Deleted table '{table_name}' from owLSM DB at {self.db_path}")
            return True
        except Exception as e:
            logger.log_error(f"Failed to delete table '{table_name}' from owLSM DB: {e}")
            return False

    def get_all_data_from_table(self, table_name: str) -> list:

        assert os.path.exists(self.db_path), f"Database file does not exist: {self.db_path}"
        
        conn = None
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
            if cursor.fetchone() is None:
                assert False, f"Table '{table_name}' does not exist in the database"
            
            cursor.execute(f"SELECT * FROM {table_name}")
            rows = cursor.fetchall()
            
            result = [dict(row) for row in rows]
            logger.log_info(f"Retrieved {len(result)} rows from table '{table_name}'")
            return result
            
        except sqlite3.Error as e:
            assert False, f"SQLite error while accessing table '{table_name}': {e}"
        finally:
            if conn:
                conn.close()


owlsm_db = OwlsmDB(str(system_globals.OWLSM_DB_PATH))