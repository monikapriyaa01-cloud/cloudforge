CertWatch local project

Files:
- app.py: Flask backend that checks public HTTPS certificate expiry.
- certwatch_interactive_dashboard.html: interactive dashboard.

Run in VS Code terminal:
1. python -m pip install flask
2. python app.py
3. Open http://127.0.0.1:5000
4. Open Certificates, enter example.com, and click Check certificate.

Keep the terminal running. Stop the server with Ctrl+C.
This is a local prototype: no scheduled checks, email notifications, database, login, or cloud deployment yet. Do not expose Flask's development server directly to the public internet.
