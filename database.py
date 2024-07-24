import sqlite3

class Database:
    def __init__(self, db_name):
        self.conn = sqlite3.connect(db_name)
        self.cursor = self.conn.cursor()

    def create_table(self, table_name, columns):
        query = f"CREATE TABLE IF NOT EXISTS {table_name} ({', '.join(columns)})"
        self.cursor.execute(query)
        self.conn.commit()

    def insert_data(self, table_name, data):
        query = f"INSERT INTO {table_name} VALUES ({', '.join(['?' for _ in data])})"
        self.cursor.execute(query, data)
        self.conn.commit()

    def add_column(self, table_name, column_name, data_type):
        query = f"SELECT * FROM pragma_table_info('{table_name}') WHERE name = '{column_name}'"
        self.cursor.execute(query)
        if not self.cursor.fetchone():
            query = f"ALTER TABLE {table_name} ADD COLUMN {column_name} {data_type}"
            self.cursor.execute(query)
            self.conn.commit()
        else:
            print(f"Column '{column_name}' already exists in table '{table_name}'.")

    def close_connection(self):
        self.conn.close()