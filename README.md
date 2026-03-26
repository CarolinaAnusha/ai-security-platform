# 🔐 AI Security Analyzer Platform

## 📌 Overview

The AI Security Analyzer Platform is a full-stack web application designed to analyze text, logs, SQL queries, chat data, and uploaded files to detect sensitive information and potential security vulnerabilities. The system combines rule-based detection techniques with AI-generated insights to provide meaningful security analysis.

---

## 🎯 Objectives

* Detect sensitive information such as passwords, API keys, and tokens
* Identify common vulnerabilities like SQL injection and brute-force attacks
* Provide risk scoring and severity classification
* Generate actionable insights using AI
* Support both text-based and file-based analysis

---

## 🧠 Key Features

### 🔍 Detection Capabilities

* Password detection (supports `=`, `:`, `-`)
* API keys and authentication tokens
* Credit card numbers
* Email addresses and phone numbers
* SQL injection patterns
* Hardcoded secrets
* Debug logs and stack traces
* Brute-force login attempts

---

### 📊 Analysis Output

* Risk Score (numerical)
* Risk Level (Low / Medium / High / Critical)
* Detailed findings with line numbers
* Timeline view for logs
* AI-generated insights (Groq)
* Static fallback insights

---

### 📁 File Upload Support

* Supported formats: `.txt`, `.log`, `.pdf`, `.doc`, `.docx`
* Maximum size: 10MB

---

## 🏗️ System Architecture

The system is divided into multiple layers:

* **Frontend Layer**
  Handles user interaction, input submission, and result visualization

* **Backend Layer**
  Manages API requests and orchestrates analysis

* **Processing Layer**
  Performs detection, risk scoring, and policy enforcement

* **AI Layer**
  Generates insights using Groq API or static fallback logic

---

## ⚙️ Tech Stack

### Frontend

* React.js
* CSS

### Backend

* Node.js
* Express.js
* Multer (file uploads)
* express-rate-limit

### AI Integration

* Groq API (LLaMA 3.1)

---

## 🔐 Security Features

* CORS protection
* Rate limiting for API and file uploads
* Sensitive data masking
* Environment variable handling (`.env`)
* File type validation

---

## 🔗 API Endpoints

### POST `/analyze`

Analyzes raw text input

**Request Example:**

```json
{
  "content": "password - admin123",
  "input_type": "text"
}
```

---

### POST `/analyze/file`

Analyzes uploaded files

**Form Data:**

* `file`: uploaded file
* `options`: optional JSON configuration

---

### GET `/health`

Returns system status and configuration

---

## ⚙️ Working Flow

1. User submits text or uploads a file
2. Frontend sends request to backend API
3. Backend processes input through:

   * Detection Engine
   * Risk Engine
   * Policy Engine
4. AI insights are generated (or fallback used)
5. Final structured response is returned to frontend

---

## 🚀 Deployment

* **Frontend:** Hosted on Render (Static Site)
* **Backend:** Hosted on Render (Web Service)

---

## 🧪 Testing

### Sample Input:

```
password - admin123
api key - xyz123abc
credit card - 1234 5678 9012 3456
```

### Expected Output:

* Multiple sensitive data detections
* Risk level: High or Critical
* Insights suggesting mitigation steps

---

## ⚠️ Limitations

* Detection is primarily regex-based
* Limited parsing for non-text file formats
* No authentication or user management

---

## 🔮 Future Enhancements

* User authentication system
* Dashboard with analytics
* Machine learning-based detection
* Exportable reports (PDF/CSV)
* Real-time monitoring

---

## 👩‍💻 Author

Anusha

---

## 📜 License

This project is intended for academic and demonstration purposes.
