# WardSeal OIDC Sample App

This is a sample Golang application demonstrating how to integrate with the WardSeal Identity Platform using OpenID Connect (OIDC).

## Prerequisites

1.  **WardSeal Services**: Ensure WardSeal is running (`docker-compose up`).
2.  **Hosts File**: Ensure your `/etc/hosts` has the following entry:
    ```
    127.0.0.1 auth.wardseal.local
    ```
3.  **Go**: Installed on your machine (v1.23+ recommended).

## Setup & Registration

1.  **Register the Client**: Run the provided script to register this sample app in WardSeal's database.
    ```bash
    ./register-client.sh
    ```
    This registers a client with ID `sample-oidc-client` for the `shield-corp` tenant.

2.  **Install Dependencies**:
    ```bash
    go mod tidy
    ```

## Running the App

Run the application with the required environment variables:

```bash
export OIDC_CLIENT_ID=sample-oidc-client
export OIDC_CLIENT_SECRET=sample-client-secret
export OIDC_ISSUER=http://auth.wardseal.local/t/admin-system
export OIDC_REDIRECT_URL=http://localhost:8080/callback
export PORT=8080

go run main.go
```

## Testing the Flow

1.  Open [http://localhost:8080](http://localhost:8080) in your browser.
2.  Click **Login with WardSeal**.
3.  You will be redirected to WardSeal for authentication.
4.  After successful login, you will be redirected back to `http://localhost:8080/callback`.
5.  The app will exchange the authorization code for tokens, verify the ID token, and display your profile information.

## OIDC Endpoints (Discovery)

The application automatically discovers OIDC endpoints from:
`http://auth.wardseal.local/t/shield-corp/.well-known/openid-configuration`
