<p align="center" style="position: relative;">
  <a href="https://github.com/librecap/librecap-server" style="display: inline-flex; align-items: center;">
      <picture>
          <source height="128" media="(prefers-color-scheme: dark)" srcset="https://github.com/librecap/librecap/releases/download/v0.1.0-img/LibreCap-dark.webp">
          <source height="128" media="(prefers-color-scheme: light)" srcset="https://github.com/librecap/librecap/releases/download/v0.1.0-img/LibreCap-light.webp">
          <img height="128" alt="LibreCap Logo" src="https://github.com/librecap/librecap/releases/download/v0.1.0-img/LibreCap-light.webp">
      </picture>
      <span style="font-size: 1.5em; font-weight: bold;">(Server)</span>
  </a>
</p>

<p align="center">
    A fast and efficient Actix-based server implementing the LibreCap challenge and PoW system.
</p>

<p align="center">
  <a href="https://github.com/librecap/librecap">
    <img src="https://img.shields.io/badge/JS_Library-blue?style=for-the-badge&logo=javascript" alt="JS Library">
  </a>
  <a href="https://github.com/librecap/librecap-server">
    <img src="https://img.shields.io/badge/Server-green?style=for-the-badge&logo=rust" alt="Server">
  </a>
  <a href="https://github.com/librecap/librecap-gateway">
    <img src="https://img.shields.io/badge/Gateway-red?style=for-the-badge&logo=linux" alt="Gateway">
  </a>
</p>

## 🚀 Quick Start

Want to add LibreCap to your Actix app? Add this to your `Cargo.toml`:
```toml
[dependencies]
librecap-server = { git = "https://github.com/librecap/librecap-server", branch = "main" }
```

And update your `main.rs`:
```rust
use librecap_server::{add_librecap, initialize_app_state};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let app_state = initialize_app_state().await;
    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            .configure(add_librecap)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
```

Remember to start Redis first: `redis-server --daemonize yes`

## 🌟 Overview

LibreCap is an open-source CAPTCHA Box alternative designed with privacy and data protection in mind. Unlike commercial CAPTCHA solutions that may collect user data, LibreCap prioritizes privacy while providing effective bot detection.

This repository contains the server component of the LibreCap system, which is responsible for:
- Generating proof-of-work (PoW) challenges
- Creating and verifying image-based CAPTCHA challenges
- Maintaining security through cryptographic verification

The client-side component can be found at: https://github.com/librecap/librecap

## ✨ Features

- **Tiered Proof-of-Work System**: Uses computational challenges to filter out basic bots
- **Privacy-Focused Image Captchas**: Generates visual challenges while respecting user privacy
- **Redis-Based Session Management**: Maintains security state efficiently
- **Rate Limiting**: Prevents abuse through tiered difficulty increases
- **Performance**: Fast response times with minimal resource usage

## 📦 Installation

### Use Cargo (Recommended)

To integrate LibreCap into your existing Actix web application, follow these steps:

1. Add the dependency to your `Cargo.toml`:
```toml
[dependencies]
librecap-server = { git = "https://github.com/librecap/librecap-server", branch = "main" }
actix-web = "4"
```

2. Set up Redis (required for session management):
```bash
redis-server --daemonize yes
```

3. Integrate LibreCap into your Actix application:
```rust
use actix_web::{App, HttpServer};
use librecap_server::{add_librecap, initialize_app_state};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize the LibreCap state (connects to Redis and loads resources)
    let app_state = initialize_app_state().await;

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            // Add LibreCap routes and services
            .configure(add_librecap)
            // Your existing routes and services go here
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
```

The server will now expose LibreCap endpoints at `/librecap/v1/*`. Configure your client-side LibreCap instance to point to these endpoints.

### Use Git

```bash
git clone https://github.com/librecap/librecap-server.git
cd librecap-server
```

```bash
redis-server --daemonize yes --port 6379
cargo run --release
```

## 🐳 Docker setup

Your favorite fish is here to help you!

```bash
docker-compose build
docker-compose up -d
```

## ⚙️ API Endpoints

### GET `/librecap/v1/initial`

Initiates a new CAPTCHA verification flow by providing an initial PoW challenge.

**Response:**
- Binary data containing two PoW challenges with different difficulty levels
- Each challenge includes a nonce, timestamp, hardness parameter, and cryptographic signature

### POST `/librecap/v1/challenge`

Validates the solution to the initial PoW challenge and returns an image CAPTCHA challenge.

**Request:**
- Binary data containing the solved PoW challenge (nonce, timestamp, signature, hardness, solution)

**Response:**
- Binary data containing:
  - Image CAPTCHA challenge data
  - Reference images and distractor images
  - Cryptographic information for later verification
  - The user needs to identify which grid cells match the reference image

## 🧠 Technical Implementation

### Proof of Work System

The PoW system requires clients to perform computational work before receiving a CAPTCHA challenge, helping to:
- Reduce server load from automated attacks
- Create a cost for verification attempts
- Filter out basic bots before showing visual challenges

The system uses a tiered approach with increasing difficulty levels:
1. Initial challenge with moderate difficulty
2. Secondary challenge with higher difficulty 
3. Image challenge with additional verification steps

### Image CAPTCHA Mechanism

The image captcha system:
- Loads and preprocesses images from a dataset
- Randomly selects target and distractor images
- Applies visual manipulations that are easy for humans to parse but difficult for AI
- Uses cryptographic verification to prevent tampering

### Security Features

- **Cryptographic Signatures**: All challenges contain HMAC signatures to prevent forgery
- **Nonce Tracking**: Prevents replay attacks by tracking used nonces in Redis
- **Time-Limited Challenges**: All challenges expire after a set period
- **IP and User-Agent Verification**: Challenges are bound to specific client identifiers

## 🔧 Configuration

The server can be configured using environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `HOST` | Server host address | 0.0.0.0 |
| `PORT` | Server port | 8080 |
| `WORKERS` | Number of worker threads | 16 |
| `DATASET_PATH` | Path to image dataset | ai_dogs.pkl |
| `REDIS_URL` | Redis connection URL | - |
| `REDIS_HOST` | Redis host | 127.0.0.1 |
| `REDIS_PORT` | Redis port | 6379 |
| `REDIS_PASSWORD` | Redis password | - |


## 👥 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the project
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

Copyright 2025 LibreCap Contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.