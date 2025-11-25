# LinkVerse - Advanced URL Shortener API

A robust and secure backend API for shortening URLs, built with Flask. This project demonstrates modern backend practices including stateless authentication, security measures, and third-party integrations.

## 🚀 Key Features

*   **User Management:** Secure Registration & Login.
*   **Authentication:** Stateless JWT (JSON Web Token) implementation.
*   **Core Logic:** URL Shortening with unique ID generation.
*   **QR Code Integration:** Auto-generates QR codes for every shortened link.
*   **Security:**
    *   Password Hashing (SHA-256).
    *   API Rate Limiting (Preventing spam/DDoS).
    *   Input Sanitization (XSS protection).
*   **Admin Panel:** Protected routes for Admin to manage users and links.
*   **Database:** Relational schema with User-Link relationships.

## 🛠️ Tech Stack

*   **Language:** Python 3
*   **Framework:** Flask
*   **Database:** SQLite (SQLAlchemy ORM)
*   **Libraries:** Flask-JWT-Extended, Flask-Limiter, Qrcode, Werkzeug

## ⚙️ How to Run

1.  **Clone the repo:**
    ```bash
    git clone https://github.com/YOUR_USERNAME/LinkVerse-API.git
    ```
2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
3.  **Run the application:**
    ```bash
    python app.py
    ```

## 🔗 API Endpoints

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| `POST` | `/register` | Register a new user | ❌ |
| `POST` | `/login` | Login and get JWT Token | ❌ |
| `POST` | `/create_link` | Create a short URL | ✅ |
| `GET` | `/links` | Get all user links | ✅ |
| `GET` | `/qr/<short_url>`| Get QR Code image | ✅ |
| `GET` | `/admin/users` | (Admin) View all users | ✅ (Admin) |
