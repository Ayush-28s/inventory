import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
from datetime import datetime
import hashlib

class InventoryManagementSystem:
    def __init__(self, root):
        self.root = root
        self.root.title("Inventory Management System")
        self.root.geometry("1200x700")
        
        # Database setup
        self.conn = sqlite3.connect('inventory.db')
        self.create_tables()
        
        # User session
        self.current_user = None
        
        # Show login screen
        self.show_login_screen()

    def create_tables(self):
        cursor = self.conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL,
                full_name TEXT
            )
        ''')
        
        # Products table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                category TEXT,
                price REAL NOT NULL,
                quantity INTEGER NOT NULL,
                min_stock_level INTEGER DEFAULT 5,
                last_updated TEXT
            )
        ''')
        
        # Transactions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                product_id INTEGER,
                quantity INTEGER NOT NULL,
                transaction_type TEXT NOT NULL,  -- 'purchase' or 'sale'
                transaction_date TEXT NOT NULL,
                user_id INTEGER,
                notes TEXT,
                FOREIGN KEY (product_id) REFERENCES products(id),
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        
        # Create admin user if not exists
        cursor.execute("SELECT * FROM users WHERE username='admin'")
        if not cursor.fetchone():
            hashed_password = self.hash_password("admin123")
            cursor.execute(
                "INSERT INTO users (username, password, role, full_name) VALUES (?, ?, ?, ?)",
                ('admin', hashed_password, 'admin', 'Administrator')
            )
        
        self.conn.commit()

    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def verify_password(self, stored_password, provided_password):
        return stored_password == self.hash_password(provided_password)

    def show_login_screen(self):
        # Clear any existing widgets
        for widget in self.root.winfo_children():
            widget.destroy()
        
        # Login frame
        login_frame = ttk.Frame(self.root, padding="20")
        login_frame.pack(expand=True)
        
        # Username
        ttk.Label(login_frame, text="Username:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.username_entry = ttk.Entry(login_frame)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)
        
        # Password
        ttk.Label(login_frame, text="Password:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.password_entry = ttk.Entry(login_frame, show="*")
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)
        
        # Login button
        login_button = ttk.Button(login_frame, text="Login", command=self.authenticate_user)
        login_button.grid(row=2, column=0, columnspan=2, pady=10)
        
        # Focus on username field
        self.username_entry.focus()

    def authenticate_user(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showerror("Error", "Please enter both username and password")
            return
        
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, password, role, full_name FROM users WHERE username=?", (username,))
        user = cursor.fetchone()
        
        if user and self.verify_password(user[1], password):
            self.current_user = {
                'id': user[0],
                'username': username,
                'role': user[2],
                'full_name': user[3]
            }
            self.show_main_menu()
        else:
            messagebox.showerror("Error", "Invalid username or password")

    def show_main_menu(self):
        # Clear any existing widgets
        for widget in self.root.winfo_children():
            widget.destroy()
        
        # Main menu frame
        menu_frame = ttk.Frame(self.root, padding="20")
        menu_frame.pack(expand=True)
        
        # Welcome message
        welcome_label = ttk.Label(
            menu_frame, 
            text=f"Welcome, {self.current_user['full_name'] or self.current_user['username']}!",
            font=('Helvetica', 14)
        )
        welcome_label.grid(row=0, column=0, columnspan=2, pady=10)
        
        # Buttons
        buttons = [
            ("Manage Products", self.show_product_management),
            ("Inventory Report", self.show_inventory_report),
            ("Low Stock Alert", self.show_low_stock),
            ("Transaction History", self.show_transaction_history)
        ]
        
        if self.current_user['role'] == 'admin':
            buttons.append(("User Management", self.show_user_management))
        
        buttons.append(("Logout", self.logout))
        
        for i, (text, command) in enumerate(buttons, start=1):
            ttk.Button(
                menu_frame, 
                text=text, 
                command=command,
                width=20
            ).grid(row=i, column=0, columnspan=2, pady=5)

    def show_product_management(self):
        # Clear any existing widgets
        for widget in self.root.winfo_children():
            widget.destroy()
        
        # Main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Left frame - Add/Edit product
        left_frame = ttk.Frame(main_frame, padding="10")
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Product form
        ttk.Label(left_frame, text="Product Management", font=('Helvetica', 12, 'bold')).grid(row=0, column=0, columnspan=2, pady=10)
        
        # Form fields
        fields = [
            ("Name:", "name_entry"),
            ("Description:", "description_entry"),
            ("Category:", "category_entry"),
            ("Price:", "price_entry"),
            ("Quantity:", "quantity_entry"),
            ("Min Stock Level:", "min_stock_entry")
        ]
        
        self.form_entries = {}
        for i, (label, name) in enumerate(fields, start=1):
            ttk.Label(left_frame, text=label).grid(row=i, column=0, padx=5, pady=5, sticky="e")
            entry = ttk.Entry(left_frame)
            entry.grid(row=i, column=1, padx=5, pady=5, sticky="we")
            self.form_entries[name] = entry
        
        # Buttons
        button_frame = ttk.Frame(left_frame)
        button_frame.grid(row=len(fields)+1, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="Add Product", command=self.add_product).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Update Product", command=self.update_product).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear Form", command=self.clear_product_form).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Back to Menu", command=self.show_main_menu).pack(side=tk.RIGHT, padx=5)
        
        # Right frame - Product list
        right_frame = ttk.Frame(main_frame, padding="10")
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        ttk.Label(right_frame, text="Product List", font=('Helvetica', 12, 'bold')).pack(pady=10)
        
        # Treeview for products
        self.product_tree = ttk.Treeview(right_frame, columns=('id', 'name', 'category', 'price', 'quantity'), show='headings')
        self.product_tree.heading('id', text='ID')
        self.product_tree.heading('name', text='Name')
        self.product_tree.heading('category', text='Category')
        self.product_tree.heading('price', text='Price')
        self.product_tree.heading('quantity', text='Quantity')
        self.product_tree.column('id', width=50)
        self.product_tree.column('name', width=150)
        self.product_tree.column('category', width=100)
        self.product_tree.column('price', width=80)
        self.product_tree.column('quantity', width=80)
        self.product_tree.pack(fill=tk.BOTH, expand=True)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(right_frame, orient="vertical", command=self.product_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.product_tree.configure(yscrollcommand=scrollbar.set)
        
        # Bind selection event
        self.product_tree.bind('<<TreeviewSelect>>', self.on_product_select)
        
        # Load products
        self.load_products()
        
        # Action buttons for products
        action_frame = ttk.Frame(right_frame)
        action_frame.pack(pady=10)
        
        ttk.Button(action_frame, text="Delete Product", command=self.delete_product).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Add Stock", command=lambda: self.show_stock_dialog('add')).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Remove Stock", command=lambda: self.show_stock_dialog('remove')).pack(side=tk.LEFT, padx=5)

    def load_products(self):
        # Clear existing data
        for item in self.product_tree.get_children():
            self.product_tree.delete(item)
        
        # Fetch products from database
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, name, category, price, quantity FROM products ORDER BY name")
        products = cursor.fetchall()
        
        # Insert into treeview
        for product in products:
            self.product_tree.insert('', 'end', values=product)

    def on_product_select(self, event):
        selected_item = self.product_tree.focus()
        if not selected_item:
            return
        
        product_data = self.product_tree.item(selected_item)['values']
        if not product_data:
            return
        
        # Fetch complete product details
        cursor = self.conn.cursor()
        cursor.execute("SELECT name, description, category, price, quantity, min_stock_level FROM products WHERE id=?", (product_data[0],))
        product = cursor.fetchone()
        
        # Update form fields
        self.clear_product_form()
        self.form_entries['name_entry'].insert(0, product[0])
        self.form_entries['description_entry'].insert(0, product[1])
        self.form_entries['category_entry'].insert(0, product[2])
        self.form_entries['price_entry'].insert(0, product[3])
        self.form_entries['quantity_entry'].insert(0, product[4])
        self.form_entries['min_stock_entry'].insert(0, product[5])
        
        # Store current product ID
        self.current_product_id = product_data[0]

    def clear_product_form(self):
        for entry in self.form_entries.values():
            entry.delete(0, tk.END)
        if hasattr(self, 'current_product_id'):
            del self.current_product_id

    def validate_product_form(self):
        required_fields = ['name_entry', 'price_entry', 'quantity_entry']
        for field in required_fields:
            if not self.form_entries[field].get():
                messagebox.showerror("Error", f"Please fill in all required fields")
                return False
        
        try:
            float(self.form_entries['price_entry'].get())
            int(self.form_entries['quantity_entry'].get())
            if 'min_stock_entry' in self.form_entries and self.form_entries['min_stock_entry'].get():
                int(self.form_entries['min_stock_entry'].get())
        except ValueError:
            messagebox.showerror("Error", "Price and quantity must be valid numbers")
            return False
        
        return True

    def add_product(self):
        if not self.validate_product_form():
            return
        
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                '''INSERT INTO products 
                (name, description, category, price, quantity, min_stock_level, last_updated) 
                VALUES (?, ?, ?, ?, ?, ?, ?)''',
                (
                    self.form_entries['name_entry'].get(),
                    self.form_entries['description_entry'].get(),
                    self.form_entries['category_entry'].get(),
                    float(self.form_entries['price_entry'].get()),
                    int(self.form_entries['quantity_entry'].get()),
                    int(self.form_entries['min_stock_entry'].get() or 5),
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                )
            )
            product_id = cursor.lastrowid
            
            # Record transaction
            cursor.execute(
                '''INSERT INTO transactions 
                (product_id, quantity, transaction_type, transaction_date, user_id, notes) 
                VALUES (?, ?, ?, ?, ?, ?)''',
                (
                    product_id,
                    int(self.form_entries['quantity_entry'].get()),
                    'purchase',
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    self.current_user['id'],
                    'Initial stock'
                )
            )
            
            self.conn.commit()
            messagebox.showinfo("Success", "Product added successfully")
            self.load_products()
            self.clear_product_form()
        except sqlite3.Error as e:
            self.conn.rollback()
            messagebox.showerror("Database Error", str(e))

    def update_product(self):
        if not hasattr(self, 'current_product_id'):
            messagebox.showerror("Error", "Please select a product to update")
            return
        
        if not self.validate_product_form():
            return
        
        cursor = self.conn.cursor()
        try:
            # Get current quantity for comparison
            cursor.execute("SELECT quantity FROM products WHERE id=?", (self.current_product_id,))
            old_quantity = cursor.fetchone()[0]
            new_quantity = int(self.form_entries['quantity_entry'].get())
            
            # Update product
            cursor.execute(
                '''UPDATE products SET 
                name=?, description=?, category=?, price=?, quantity=?, min_stock_level=?, last_updated=?
                WHERE id=?''',
                (
                    self.form_entries['name_entry'].get(),
                    self.form_entries['description_entry'].get(),
                    self.form_entries['category_entry'].get(),
                    float(self.form_entries['price_entry'].get()),
                    new_quantity,
                    int(self.form_entries['min_stock_entry'].get() or 5),
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    self.current_product_id
                )
            )
            
            # Record transaction if quantity changed
            if old_quantity != new_quantity:
                transaction_type = 'purchase' if new_quantity > old_quantity else 'sale'
                quantity_change = abs(new_quantity - old_quantity)
                
                cursor.execute(
                    '''INSERT INTO transactions 
                    (product_id, quantity, transaction_type, transaction_date, user_id, notes) 
                    VALUES (?, ?, ?, ?, ?, ?)''',
                    (
                        self.current_product_id,
                        quantity_change,
                        transaction_type,
                        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        self.current_user['id'],
                        'Manual inventory adjustment'
                    )
                )
            
            self.conn.commit()
            messagebox.showinfo("Success", "Product updated successfully")
            self.load_products()
        except sqlite3.Error as e:
            self.conn.rollback()
            messagebox.showerror("Database Error", str(e))

    def delete_product(self):
        selected_item = self.product_tree.focus()
        if not selected_item:
            messagebox.showerror("Error", "Please select a product to delete")
            return
        
        product_data = self.product_tree.item(selected_item)['values']
        if not product_data:
            return
        
        if not messagebox.askyesno("Confirm", f"Are you sure you want to delete product '{product_data[1]}'?"):
            return
        
        cursor = self.conn.cursor()
        try:
            # Delete transactions first (due to foreign key constraint)
            cursor.execute("DELETE FROM transactions WHERE product_id=?", (product_data[0],))
            
            # Then delete the product
            cursor.execute("DELETE FROM products WHERE id=?", (product_data[0],))
            
            self.conn.commit()
            messagebox.showinfo("Success", "Product deleted successfully")
            self.load_products()
            self.clear_product_form()
        except sqlite3.Error as e:
            self.conn.rollback()
            messagebox.showerror("Database Error", str(e))

    def show_stock_dialog(self, action):
        selected_item = self.product_tree.focus()
        if not selected_item:
            messagebox.showerror("Error", "Please select a product")
            return
        
        product_data = self.product_tree.item(selected_item)['values']
        if not product_data:
            return
        
        dialog = tk.Toplevel(self.root)
        dialog.title(f"{action.capitalize()} Stock")
        dialog.geometry("300x200")
        
        ttk.Label(dialog, text=f"Product: {product_data[1]}").pack(pady=10)
        ttk.Label(dialog, text=f"Current Stock: {product_data[4]}").pack()
        
        ttk.Label(dialog, text="Quantity:").pack(pady=5)
        quantity_entry = ttk.Entry(dialog)
        quantity_entry.pack()
        
        ttk.Label(dialog, text="Notes:").pack(pady=5)
        notes_entry = ttk.Entry(dialog)
        notes_entry.pack()
        
        def process_stock():
            try:
                quantity = int(quantity_entry.get())
                if quantity <= 0:
                    raise ValueError
            except ValueError:
                messagebox.showerror("Error", "Please enter a valid positive number")
                return
            
            notes = notes_entry.get() or f"Stock {action}"
            
            cursor = self.conn.cursor()
            try:
                # Update product quantity
                if action == 'add':
                    new_quantity = product_data[4] + quantity
                else:
                    if product_data[4] < quantity:
                        messagebox.showerror("Error", "Not enough stock available")
                        return
                    new_quantity = product_data[4] - quantity
                
                cursor.execute
                   ( "UPDATE products SET quantity=?, last_updated=? WHERE id=?",)
                    (new_quantity, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), product_data[0])
                
                # Record transaction
                cursor.execute(
                    '''INSERT INTO transactions 
                    (product_id, quantity, transaction_type, transaction_date, user_id, notes) 
                    VALUES (?, ?, ?, ?, ?, ?)''',
                    (
                        product_data[0],
                        quantity,
                        'purchase' if action == 'add' else 'sale',
                        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        self.current_user['id'],
                        notes
                    )
                )
                
                self.conn.commit()
                messagebox.showinfo("Success", f"Stock {action}ed successfully")
                dialog.destroy()
                self.load_products()
                
                # Update form if this product is currently selected
                if hasattr(self, 'current_product_id') and self.current_product_id == product_data[0]:
                    self.form_entries['quantity_entry'].delete(0, tk.END)
                    self.form_entries['quantity_entry'].insert(0, str(new_quantity))
            except sqlite3.Error as e:
                self.conn.rollback()
                messagebox.showerror("Database Error", str(e))
        
        ttk.Button(dialog, text="Submit", command=process_stock).pack(pady=10)

    def show_inventory_report(self):
        # Clear any existing widgets
        for widget in self.root.winfo_children():
            widget.destroy()
        
        # Main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Title
        ttk.Label(main_frame, text="Inventory Report", font=('Helvetica', 14, 'bold')).pack(pady=10)
        
        # Filter frame
        filter_frame = ttk.Frame(main_frame)
        filter_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(filter_frame, text="Filter by Category:").pack(side=tk.LEFT, padx=5)
        
        # Category dropdown
        cursor = self.conn.cursor()
        cursor.execute("SELECT DISTINCT category FROM products WHERE category IS NOT NULL AND category != ''")
        categories = [row[0] for row in cursor.fetchall()]
        
        self.category_filter = tk.StringVar()
        category_dropdown = ttk.Combobox(filter_frame, textvariable=self.category_filter, values=["All"] + categories)
        category_dropdown.pack(side=tk.LEFT, padx=5)
        category_dropdown.set("All")
        
        ttk.Button(filter_frame, text="Apply Filter", command=self.load_filtered_report).pack(side=tk.LEFT, padx=5)
        
        # Export button
        ttk.Button(filter_frame, text="Export to CSV", command=self.export_report).pack(side=tk.RIGHT, padx=5)
        
        # Back button
        ttk.Button(filter_frame, text="Back to Menu", command=self.show_main_menu).pack(side=tk.RIGHT, padx=5)
        
        # Treeview for report
        self.report_tree = ttk.Treeview(
            main_frame, 
            columns=('id', 'name', 'category', 'price', 'quantity', 'value'), 
            show='headings'
        )
        
        # Configure columns
        self.report_tree.heading('id', text='ID')
        self.report_tree.heading('name', text='Name')
        self.report_tree.heading('category', text='Category')
        self.report_tree.heading('price', text='Price')
        self.report_tree.heading('quantity', text='Quantity')
        self.report_tree.heading('value', text='Total Value')
        
        self.report_tree.column('id', width=50, anchor='e')
        self.report_tree.column('name', width=200)
        self.report_tree.column('category', width=150)
        self.report_tree.column('price', width=80, anchor='e')
        self.report_tree.column('quantity', width=80, anchor='e')
        self.report_tree.column('value', width=100, anchor='e')
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=self.report_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.report_tree.configure(yscrollcommand=scrollbar.set)
        
        self.report_tree.pack(fill=tk.BOTH, expand=True)
        
        # Summary frame
        summary_frame = ttk.Frame(main_frame)
        summary_frame.pack(fill=tk.X, pady=10)
        
        self.total_items_label = ttk.Label(summary_frame, text="Total Items: 0")
        self.total_items_label.pack(side=tk.LEFT, padx=10)
        
        self.total_value_label = ttk.Label(summary_frame, text="Total Inventory Value: $0.00")
        self.total_value_label.pack(side=tk.LEFT, padx=10)
        
        # Load initial report
        self.load_filtered_report()

    def load_filtered_report(self):
        # Clear existing data
        for item in self.report_tree.get_children():
            self.report_tree.delete(item)
        
        # Build query based on filter
        category_filter = self.category_filter.get()
        if category_filter == "All":
            query = "SELECT id, name, category, price, quantity FROM products ORDER BY name"
            params = ()
        else:
            query = "SELECT id, name, category, price, quantity FROM products WHERE category=? ORDER BY name"
            params = (category_filter,)
        
        cursor = self.conn.cursor()
        cursor.execute(query, params)
        products = cursor.fetchall()
        
        total_items = 0
        total_value = 0.0
        
        # Insert into treeview
        for product in products:
            product_id, name, category, price, quantity = product
            total_value += price * quantity
            total_items += quantity
            
            self.report_tree.insert('', 'end', values=(
                product_id,
                name,
                category or 'N/A',
                f"${price:.2f}",
                quantity,
                f"${(price * quantity):.2f}"
            ))
        
        # Update summary
        self.total_items_label.config(text=f"Total Items: {total_items}")
        self.total_value_label.config(text=f"Total Inventory Value: ${total_value:.2f}")

    def export_report(self):
        # Get all data from the treeview
        items = self.report_tree.get_children()
        if not items:
            messagebox.showwarning("Warning", "No data to export")
            return
        
        # Prepare CSV content
        csv_content = "ID,Name,Category,Price,Quantity,Total Value\n"
        
        for item in items:
            values = self.report_tree.item(item)['values']
            csv_content += f"{values[0]},{values[1]},{values[2]},{values[3]},{values[4]},{values[5]}\n"
        
        # Add summary
        total_items = self.total_items_label.cget("text").split(": ")[1]
        total_value = self.total_value_label.cget("text").split(": ")[1]
        csv_content += f"\n{total_items},{total_value}"
        
        # Write to file
        try:
            with open("inventory_report.csv", "w") as f:
                f.write(csv_content)
            messagebox.showinfo("Success", "Report exported to inventory_report.csv")
        except IOError as e:
            messagebox.showerror("Error", f"Failed to export report: {str(e)}")

    def show_low_stock(self):
        # Clear any existing widgets
        for widget in self.root.winfo_children():
            widget.destroy()
        
        # Main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Title
        ttk.Label(main_frame, text="Low Stock Alert", font=('Helvetica', 14, 'bold')).pack(pady=10)
        
        # Back button
        ttk.Button(main_frame, text="Back to Menu", command=self.show_main_menu).pack(anchor='ne', pady=5)
        
        # Treeview for low stock items
        self.low_stock_tree = ttk.Treeview(
            main_frame, 
            columns=('id', 'name', 'category', 'quantity', 'min_stock'), 
            show='headings'
        )
        
        # Configure columns
        self.low_stock_tree.heading('id', text='ID')
        self.low_stock_tree.heading('name', text='Name')
        self.low_stock_tree.heading('category', text='Category')
        self.low_stock_tree.heading('quantity', text='Current Stock')
        self.low_stock_tree.heading('min_stock', text='Min Required')
        
        self.low_stock_tree.column('id', width=50, anchor='e')
        self.low_stock_tree.column('name', width=200)
        self.low_stock_tree.column('category', width=150)
        self.low_stock_tree.column('quantity', width=100, anchor='e')
        self.low_stock_tree.column('min_stock', width=100, anchor='e')
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=self.low_stock_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.low_stock_tree.configure(yscrollcommand=scrollbar.set)
        
        self.low_stock_tree.pack(fill=tk.BOTH, expand=True)
        
        # Load low stock items
        self.load_low_stock_items()

    def load_low_stock_items(self):
        # Clear existing data
        for item in self.low_stock_tree.get_children():
            self.low_stock_tree.delete(item)
        
        # Fetch low stock items
        cursor = self.conn.cursor()
        cursor.execute('''
            SELECT id, name, category, quantity, min_stock_level 
            FROM products 
            WHERE quantity <= min_stock_level
            ORDER BY (quantity - min_stock_level) ASC
        ''')
        low_stock_items = cursor.fetchall()
        
        if not low_stock_items:
            self.low_stock_tree.insert('', 'end', values=("", "No low stock items found", "", "", ""))
            return
        
        # Insert into treeview
        for item in low_stock_items:
            product_id, name, category, quantity, min_stock = item
            self.low_stock_tree.insert('', 'end', values=(
                product_id,
                name,
                category or 'N/A',
                quantity,
                min_stock
            ))

    def show_transaction_history(self):
        # Clear any existing widgets
        for widget in self.root.winfo_children():
            widget.destroy()
        
        # Main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Title
        ttk.Label(main_frame, text="Transaction History", font=('Helvetica', 14, 'bold')).pack(pady=10)
        
        # Filter frame
        filter_frame = ttk.Frame(main_frame)
        filter_frame.pack(fill=tk.X, pady=5)
        
        # Date range filter
        ttk.Label(filter_frame, text="From:").pack(side=tk.LEFT, padx=5)
        self.from_date_entry = ttk.Entry(filter_frame, width=10)
        self.from_date_entry.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(filter_frame, text="To:").pack(side=tk.LEFT, padx=5)
        self.to_date_entry = ttk.Entry(filter_frame, width=10)
        self.to_date_entry.pack(side=tk.LEFT, padx=5)
        
        # Type filter
        ttk.Label(filter_frame, text="Type:").pack(side=tk.LEFT, padx=5)
        self.type_filter = tk.StringVar()
        type_dropdown = ttk.Combobox(filter_frame, textvariable=self.type_filter, values=["All", "Purchase", "Sale"])
        type_dropdown.pack(side=tk.LEFT, padx=5)
        type_dropdown.set("All")
        
        # Product filter
        ttk.Label(filter_frame, text="Product:").pack(side=tk.LEFT, padx=5)
        self.product_filter = tk.StringVar()
        
        cursor = self.conn.cursor()
        cursor.execute("SELECT id, name FROM products ORDER BY name")
        products = cursor.fetchall()
        product_choices = ["All"] + [f"{pid} - {name}" for pid, name in products]
        
        product_dropdown = ttk.Combobox(filter_frame, textvariable=self.product_filter, values=product_choices)
        product_dropdown.pack(side=tk.LEFT, padx=5)
        product_dropdown.set("All")
        
        # Apply filter button
        ttk.Button(filter_frame, text="Apply Filter", command=self.load_transactions).pack(side=tk.LEFT, padx=5)
        
        # Back button
        ttk.Button(filter_frame, text="Back to Menu", command=self.show_main_menu).pack(side=tk.RIGHT, padx=5)
        
        # Treeview for transactions
        self.transaction_tree = ttk.Treeview(
            main_frame, 
            columns=('id', 'date', 'product', 'type', 'quantity', 'user', 'notes'), 
            show='headings'
        )
        
        # Configure columns
        self.transaction_tree.heading('id', text='ID')
        self.transaction_tree.heading('date', text='Date')
        self.transaction_tree.heading('product', text='Product')
        self.transaction_tree.heading('type', text='Type')
        self.transaction_tree.heading('quantity', text='Quantity')
        self.transaction_tree.heading('user', text='User')
        self.transaction_tree.heading('notes', text='Notes')
        
        self.transaction_tree.column('id', width=50, anchor='e')
        self.transaction_tree.column('date', width=120)
        self.transaction_tree.column('product', width=150)
        self.transaction_tree.column('type', width=80)
        self.transaction_tree.column('quantity', width=80, anchor='e')
        self.transaction_tree.column('user', width=100)
        self.transaction_tree.column('notes', width=200)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=self.transaction_tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.transaction_tree.configure(yscrollcommand=scrollbar.set)
        
        self.transaction_tree.pack(fill=tk.BOTH, expand=True)
        
        # Summary frame
        summary_frame = ttk.Frame(main_frame)
        summary_frame.pack(fill=tk.X, pady=10)
        
        self.total_transactions_label = ttk.Label(summary_frame, text="Total Transactions: 0")
        self.total_transactions_label.pack(side=tk.LEFT, padx=10)
        
        self.purchases_label = ttk.Label(summary_frame, text="Purchases: 0")
        self.purchases_label.pack(side=tk.LEFT, padx=10)
        
        self.sales_label = ttk.Label(summary_frame, text="Sales: 0")
        self.sales_label.pack(side=tk.LEFT, padx=10)
        
        # Load initial transactions
        self.load_transactions()

    def load_transactions(self):
        # Clear existing data
        for item in self.transaction_tree.get_children():
            self.transaction_tree.delete(item)
        
        # Build query based on filters
        query = '''
            SELECT t.id, t.transaction_date, p.name, t.transaction_type, 
                   t.quantity, u.username, t.notes
            FROM transactions t
            LEFT JOIN products p ON t.product_id = p.id
            LEFT JOIN users u ON t.user_id = u.id
            WHERE 1=1
        '''
        
        params = []
        
        # Date filter
        from_date = self.from_date_entry.get()
        to_date = self.to_date_entry.get()
        
        if from_date:
            query += " AND t.transaction_date >= ?"
            params.append(from_date)
        if to_date:
            query += " AND t.transaction_date <= ?"
            params.append(to_date)
        
        # Type filter
        trans_type = self.type_filter.get()
        if trans_type != "All":
            query += " AND t.transaction_type = ?"
            params.append(trans_type.lower())
        
        # Product filter
        product_filter = self.product_filter.get()
        if product_filter != "All" and " - " in product_filter:
            product_id = product_filter.split(" - ")[0]
            query += " AND t.product_id = ?"
            params.append(product_id)
        
        query += " ORDER BY t.transaction_date DESC"
        
        cursor = self.conn.cursor()
        cursor.execute(query, params)
        transactions = cursor.fetchall()
        
        # Counters for summary
       