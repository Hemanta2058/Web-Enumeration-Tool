# Web-Enumeration-Tool
from tkinter import *
from tkinter.scrolledtext import ScrolledText
from tkinter import messagebox, filedialog
import dns.resolver
import requests
import socket
from bs4 import BeautifulSoup
import whois
import csv
import json
from datetime import datetime
import sqlite3

result_data = []

# --- Authentication System Backend ---
def create_table():
    try:
        with sqlite3.connect("users.db") as conn:
            cursor = conn.cursor()
            cursor.execute('''CREATE TABLE IF NOT EXISTS users(
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                username TEXT NOT NULL UNIQUE,
                                password TEXT NOT NULL)''')
            conn.commit()
    except Exception as e:
        messagebox.showerror("DB Error", f"Error creating table:\n{e}")

def insert_user(username, password):
    try:
        with sqlite3.connect("users.db", timeout=10) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
            conn.commit()
    except sqlite3.IntegrityError:
        raise sqlite3.IntegrityError("Username already exists")
    except Exception as e:
        raise Exception(f"Database error: {e}")

def login_user(username, password):
    try:
        with sqlite3.connect("users.db", timeout=10) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
            return cursor.fetchone()
    except Exception as e:
        messagebox.showerror("DB Error", f"Login failed:\n{e}")
        return None

# --- Vulnerability Scanner Functions ---
def check_xss(url):
    payload = '<script>alert("XSS vulnerability")</script>'
    response = requests.get(url + payload)
    if payload in response.text:
        messagebox.showwarning("XSS Found", f"XSS vulnerability in: {url}")

def check_sql_injection(url):
    payload = "1' OR '1'='1"
    response = requests.get(url + "?id=" + payload)
    if "error" in response.text:
        messagebox.showwarning("SQLi Found", f"SQL Injection vulnerability in: {url}")

def scan_url(entry):
    target_url = entry.get()
    if not target_url:
        messagebox.showwarning("Error", "Please enter a URL.")
        return
    try:
        check_xss(target_url)
        check_sql_injection(target_url)
        messagebox.showinfo("Done", "Scan complete.")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def url_vulnerability_scanner():
    scanner = Tk()
    scanner.title("XSS & SQLi Scanner")
    Label(scanner, text="Enter URL:").pack(pady=5)
    entry = Entry(scanner, width=50)
    entry.pack()
    Button(scanner, text="Scan", command=lambda: scan_url(entry)).pack(pady=5)
    scanner.mainloop()

# --- Main Application GUI ---
def execute_main_app():
    def run_task(func):
        result_text.delete(1.0, END)
        result_data.clear()
        func()

    def export_report(format):
        file = filedialog.asksaveasfilename(defaultextension=f".{format}")
        if not file:
            return
        if format == "csv":
            with open(file, 'w', newline='') as f:
                writer = csv.writer(f)
                for line in result_data:
                    writer.writerow([line])
        elif format == "json":
            with open(file, 'w') as f:
                json.dump(result_data, f, indent=4)
        elif format == "html":
            with open(file, 'w') as f:
                f.write("<html><body><pre>" + "<br>".join(result_data) + "</pre></body></html>")
        messagebox.showinfo("Exported", f"Report saved as {file}")

    def get_label_frame(master, title, row, column):
        frame = LabelFrame(master, text=title, padx=10, pady=10, font=("Arial", 10, "bold"))
        frame.grid(row=row, column=column, padx=5, pady=5, sticky="nsew")
        return frame

    def show_result(line):
        result_text.insert(END, line + "\n")
        result_data.append(line)

    main = Tk()
    main.title("Web Enumeration Tool")
    main.geometry("900x700")
    main.config(bg="lightgray")

    for i in range(4): main.grid_rowconfigure(i, weight=1)
    for i in range(2): main.grid_columnconfigure(i, weight=1)

    dns_frame = get_label_frame(main, "DNS Record Enumeration", 0, 0)
    http_frame = get_label_frame(main, "HTTP Response Analysis", 0, 1)
    port_frame = get_label_frame(main, "Port Scanning", 1, 0)
    sub_frame = get_label_frame(main, "Subdomain Finder", 1, 1)
    tech_frame = get_label_frame(main, "Web Technology Detection", 2, 0)
    scrape_frame = get_label_frame(main, "Website Scraping", 2, 1)
    whois_frame = get_label_frame(main, "WHOIS Lookup", 3, 0)
    ns_frame = get_label_frame(main, "nslookup", 3, 1)

    dns_domain_entry = Entry(dns_frame); dns_domain_entry.pack()
    Button(dns_frame, text="Enumerate DNS", command=lambda: run_task(enumerate_dns_records)).pack(pady=5)

    http_url_entry = Entry(http_frame); http_url_entry.pack()
    Button(http_frame, text="Analyze HTTP Response", command=lambda: run_task(analyze_http_response)).pack(pady=5)

    port_hostname_entry = Entry(port_frame); port_hostname_entry.pack()
    Button(port_frame, text="Scan Ports", command=lambda: run_task(scan_ports)).pack(pady=5)

    subdomain_domain_entry = Entry(sub_frame); subdomain_domain_entry.pack()
    Button(sub_frame, text="Find Subdomains", command=lambda: run_task(find_subdomains)).pack(pady=5)

    content_url_entry = Entry(tech_frame); content_url_entry.pack()
    Button(tech_frame, text="Analyze Content", command=lambda: run_task(content_fingerprinting)).pack(pady=5)

    scrape_url_entry = Entry(scrape_frame); scrape_url_entry.pack()
    Button(scrape_frame, text="Scrape Website", command=lambda: run_task(scrape_website)).pack(pady=5)

    whois_domain_entry = Entry(whois_frame); whois_domain_entry.pack()
    Button(whois_frame, text="Perform Lookup", command=lambda: run_task(perform_whois_lookup)).pack(pady=5)

    nslookup_domain_entry = Entry(ns_frame); nslookup_domain_entry.pack()
    Button(ns_frame, text="Perform nslookup", command=lambda: run_task(perform_nslookup)).pack(pady=5)

    result_frame = LabelFrame(main, text="Result", padx=10, pady=10)
    result_frame.grid(row=4, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")
    result_text = ScrolledText(result_frame, height=10)
    result_text.pack(fill=BOTH, expand=True)

    menu = Menu(main)
    file_menu = Menu(menu, tearoff=0)
    file_menu.add_command(label="Generate Report")
    file_menu.add_command(label="Export as CSV", command=lambda: export_report("csv"))
    file_menu.add_command(label="Export as JSON", command=lambda: export_report("json"))
    file_menu.add_command(label="Export as HTML", command=lambda: export_report("html"))
    file_menu.add_separator()
    file_menu.add_command(label="Exit", command=main.destroy)
    menu.add_cascade(label="File", menu=file_menu)
    menu.add_command(label="SQL and XSS Vulnerability Scanner", command=url_vulnerability_scanner)
    main.config(menu=menu)

    def enumerate_dns_records():
        try:
            domain = dns_domain_entry.get()
            show_result(f"DNS Records for {domain}:")
            for r in ['A', 'AAAA', 'MX', 'CNAME', 'NS']:
                answers = dns.resolver.resolve(domain, r)
                for answer in answers:
                    show_result(f"{r}: {answer}")
        except Exception as e:
            show_result(str(e))

    def analyze_http_response():
        try:
            url = http_url_entry.get()
            res = requests.get(url)
            show_result(f"HTTP Status: {res.status_code}")
            for k, v in res.headers.items():
                show_result(f"{k}: {v}")
        except Exception as e:
            show_result(str(e))

    def scan_ports():
        try:
            host = port_hostname_entry.get()
            ip = socket.gethostbyname(host)
            show_result(f"Scanning ports for {host}...")
            ports = {21: 'ftp', 80: 'http', 443: 'https'}
            for port, name in ports.items():
                s = socket.socket(); s.settimeout(1)
                if s.connect_ex((ip, port)) == 0:
                    show_result(f"Port {port} ({name}) is open")
                s.close()
        except Exception as e:
            show_result(str(e))

    def find_subdomains():
        try:
            domain = subdomain_domain_entry.get()
            res = requests.get(f"https://crt.sh/?q=%.{domain}&output=json")
            subs = {i['name_value'] for i in res.json()}
            show_result(f"Subdomains for {domain}:")
            for s in subs:
                show_result(s)
        except Exception as e:
            show_result(str(e))

    def content_fingerprinting():
        try:
            url = content_url_entry.get()
            html = requests.get(url).text.lower()
            technologies = {
                "React framework": ["react"],
                "Django framework": ["django"],
                "Express.js framework": ["express"],
                "Bootstrap framework": ["bootstrap"],
                "jQuery library": ["jquery"],
                "Angular framework": ["angular"]
            }
            found = False
            for name, keywords in technologies.items():
                for keyword in keywords:
                    if keyword in html:
                        show_result(f"{name} detected.")
                        found = True
                        break
            if not found:
                show_result("No known web frameworks detected.")
        except Exception as e:
            show_result(str(e))

    def scrape_website():
        try:
            soup = BeautifulSoup(requests.get(scrape_url_entry.get()).content, 'html.parser')
            show_result("Title: " + soup.title.string)
            for a in soup.find_all('a'):
                href = a.get('href')
                if href:
                    show_result(href)
        except Exception as e:
            show_result(str(e))

    def perform_whois_lookup():
        try:
            info = whois.whois(whois_domain_entry.get())
            show_result(str(info))
        except Exception as e:
            show_result(str(e))

    def perform_nslookup():
        try:
            domain = nslookup_domain_entry.get()
            answers = dns.resolver.resolve(domain, 'A')
            for answer in answers:
                show_result(str(answer))
        except Exception as e:
            show_result(str(e))

    main.mainloop()

# --- Login GUI ---
def launch_login_gui():
    create_table()
    login_root = Tk()
    login_root.title("Login System")
    login_root.geometry("400x500")

    Label(login_root, text="Signup", font=("Arial", 18, "bold")).pack(pady=10)
    signup_username = Entry(login_root); signup_username.pack()
    signup_password = Entry(login_root, show="*"); signup_password.pack()
    Button(login_root, text="Signup", command=lambda: handle_signup()).pack(pady=10)

    Label(login_root, text="Login", font=("Arial", 18, "bold")).pack(pady=10)
    login_username = Entry(login_root); login_username.pack()
    login_password = Entry(login_root, show="*"); login_password.pack()
    Button(login_root, text="Login", command=lambda: handle_login()).pack(pady=10)

    def handle_signup():
        username = signup_username.get()
        password = signup_password.get()
        if not username or not password:
            messagebox.showerror("Error", "Username and password are required")
            return
        try:
            insert_user(username, password)
            messagebox.showinfo("Success", "Account created successfully")
        except sqlite3.IntegrityError as ie:
            messagebox.showerror("Error", str(ie))
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def handle_login():
        username = login_username.get()
        password = login_password.get()
        if not username or not password:
            messagebox.showerror("Error", "Username and password required")
            return
        user = login_user(username, password)
        if user:
            messagebox.showinfo("Success", "Login successful")
            login_root.destroy()
            execute_main_app()
        else:
            messagebox.showerror("Error", "Invalid credentials")

    login_root.mainloop()

launch_login_gui()
