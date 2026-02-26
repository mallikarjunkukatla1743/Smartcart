import mysql.connector
import sqlite3
import os
from datetime import datetime, date

# Configuration from MySQL
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': 'root',
    'database': 'smartcartproject'
}

SQLITE_DB = 'smartcart.db'

def migrate():
    try:
        mysql_conn = mysql.connector.connect(**DB_CONFIG)
        mysql_cursor = mysql_conn.cursor()
        
        sqlite_conn = sqlite3.connect(SQLITE_DB)
        sqlite_cursor = sqlite_conn.cursor()
        
        # Get list of tables
        mysql_cursor.execute("SHOW TABLES")
        tables = [t[0] for t in mysql_cursor.fetchall()]
        
        for table in tables:
            print(f"Migrating table: {table}")
            
            # Get create table statement
            mysql_cursor.execute(f"SHOW CREATE TABLE {table}")
            create_stmt = mysql_cursor.fetchone()[1]
            
            # Basic conversion of MySQL CREATE TABLE to SQLite
            # This is a bit naive but might work for simple schemas
            sqlite_create = create_stmt.replace('AUTO_INCREMENT', 'AUTOINCREMENT')
            sqlite_create = sqlite_create.replace('`', '"')
            # Remove MySQL specific engine and charset options
            if 'ENGINE' in sqlite_create:
                sqlite_create = sqlite_create.split('ENGINE')[0].strip()
            # SQLite requires AUTOINCREMENT on INTEGER PRIMARY KEY only
            # and it shouldn't have a separate PRIMARY KEY (col) clause usually if it's already defined
            
            # For better reliability, let's just get the columns and types manually
            mysql_cursor.execute(f"DESCRIBE {table}")
            columns = mysql_cursor.fetchall()
            
            # columns: (Field, Type, Null, Key, Default, Extra)
            col_defs = []
            pk = None
            for col in columns:
                name, col_type, null, key, default, extra = col
                sqlite_type = col_type.split('(')[0].upper()
                if 'INT' in sqlite_type:
                    sqlite_type = 'INTEGER'
                elif 'VARCHAR' in sqlite_type or 'TEXT' in sqlite_type:
                    sqlite_type = 'TEXT'
                elif 'DECIMAL' in sqlite_type or 'FLOAT' in sqlite_type or 'DOUBLE' in sqlite_type:
                    sqlite_type = 'REAL'
                elif 'DATETIME' in sqlite_type or 'TIMESTAMP' in sqlite_type:
                    sqlite_type = 'TEXT' # SQLite uses TEXT for dates
                
                def_str = f'"{name}" {sqlite_type}'
                if key == 'PRI':
                    def_str += ' PRIMARY KEY'
                    if 'auto_increment' in extra:
                        def_str += ' AUTOINCREMENT'
                elif null == 'NO':
                    def_str += ' NOT NULL'
                
                col_defs.append(def_str)
            
            create_sql = f'CREATE TABLE IF NOT EXISTS "{table}" ({", ".join(col_defs)})'
            print(f"Executing: {create_sql}")
            sqlite_cursor.execute(f'DROP TABLE IF EXISTS "{table}"')
            sqlite_cursor.execute(create_sql)
            
            # Copy data
            mysql_cursor.execute(f"SELECT * FROM {table}")
            rows = mysql_cursor.fetchall()
            if rows:
                # Convert decimal.Decimal and other types that sqlite3 doesn't like
                import decimal
                converted_rows = []
                for row in rows:
                    new_row = []
                    for val in row:
                        if isinstance(val, decimal.Decimal):
                            new_row.append(float(val))
                        elif isinstance(val, (datetime, date)):
                            new_row.append(val.isoformat())
                        else:
                            new_row.append(val)
                    converted_rows.append(tuple(new_row))

                placeholders = ', '.join(['?' for _ in range(len(rows[0]))])
                insert_sql = f'INSERT INTO "{table}" VALUES ({placeholders})'
                sqlite_cursor.executemany(insert_sql, converted_rows)

        
        sqlite_conn.commit()
        print("Migration completed successfully!")
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if 'mysql_conn' in locals(): mysql_conn.close()
        if 'sqlite_conn' in locals(): sqlite_conn.close()

if __name__ == "__main__":
    migrate()
