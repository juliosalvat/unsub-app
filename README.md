# Constant Contact Unsubscribe Tool

This Python script allows you to unsubscribe multiple contacts from Constant Contact using their API. The script reads email addresses from a CSV file and processes them in batch.

## Prerequisites

- Python 3.6 or higher
- Constant Contact API credentials (API Key, Client Secret, Access Token, and Refresh Token)
- CSV file with email addresses to unsubscribe

## Installation

1. Clone this repository or download the files
2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

3. Create a `.env` file based on the `.env.example` template:

```bash
cp .env.example .env
```

4. Edit the `.env` file and add your Constant Contact API credentials:

```
CONSTANT_CONTACT_API_KEY=your_api_key_here
CONSTANT_CONTACT_ACCESS_TOKEN=your_access_token_here
CONSTANT_CONTACT_REFRESH_TOKEN=your_refresh_token_here
CONSTANT_CONTACT_CLIENT_SECRET=your_client_secret_here
CONSTANT_CONTACT_REDIRECT_URI=your_redirect_uri_here
TOKEN_EXPIRY=0  # Will be updated automatically when token is refreshed
```

## CSV File Format

The CSV file should have a header row with an "email" column. Example:

```
email
user1@example.com
user2@example.com
user3@example.com
```

## Usage

Run the script with the path to your CSV file:

```bash
python unsubscribe_contacts.py your_file.csv
```

The script will:

1. Check if the access token is expired and refresh it if needed
2. Read all email addresses from the CSV file
3. Look up each contact in Constant Contact
4. Unsubscribe each contact if found
5. Print a summary of the results

## Token Refresh Process

The script includes automatic token refresh functionality:

- Before processing any emails, it checks if the access token is expired or about to expire
- If a token expires during operation (401 Unauthorized response), it automatically refreshes the token and retries the operation
- When a token is refreshed, the script updates the `.env` file with the new tokens and expiry time
- The `TOKEN_EXPIRY` value is stored as a Unix timestamp and is automatically updated when tokens are refreshed

## Output

The script provides detailed output of the process:

- Which emails were successfully unsubscribed
- Which emails were not found in your Constant Contact account
- Any errors that occurred during the process
- A summary of the results

## Getting Constant Contact API Credentials

To use this script, you need to:

1. Create a Constant Contact developer account at https://developer.constantcontact.com/
2. Create an API key and client secret
3. Generate an access token and refresh token with appropriate permissions

### Obtaining Refresh Token

To get a refresh token:

1. Set up an OAuth 2.0 application in the Constant Contact developer portal
2. Configure the redirect URI for your application
3. Use the authorization code flow to obtain both an access token and refresh token
4. Store these tokens in your `.env` file

For more information, refer to the [Constant Contact API documentation](https://developer.constantcontact.com/api_guide/index.html).
