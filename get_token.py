#!/usr/bin/env python3
"""
Get Constant Contact Access Token

This script exchanges an authorization code for access and refresh tokens.
"""

import os
import sys
import requests
import json
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get credentials from .env file
API_KEY = os.getenv('CONSTANT_CONTACT_API_KEY')
CLIENT_SECRET = os.getenv('CONSTANT_CONTACT_CLIENT_SECRET')
REDIRECT_URI = os.getenv('CONSTANT_CONTACT_REDIRECT_URI')

def get_tokens(auth_code):
    """Exchange authorization code for access and refresh tokens."""
    
    # Token endpoint
    token_url = 'https://authz.constantcontact.com/oauth2/default/v1/token'
    
    # Request headers
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    # Request data
    data = {
        'grant_type': 'authorization_code',
        'code': auth_code,
        'redirect_uri': REDIRECT_URI,
        'client_id': API_KEY,
        'client_secret': CLIENT_SECRET
    }
    
    try:
        # Send request
        print(f"Sending token request to {token_url}...")
        response = requests.post(token_url, headers=headers, data=data)
        
        # Check response
        print(f"Response status code: {response.status_code}")
        
        if response.status_code != 200:
            print("Error getting tokens:")
            print(response.text)
            return None
        
        # Parse response
        token_data = response.json()
        
        # Extract tokens
        access_token = token_data.get('access_token')
        refresh_token = token_data.get('refresh_token')
        expires_in = token_data.get('expires_in')
        
        if not all([access_token, refresh_token, expires_in]):
            print("Error: Incomplete token data received")
            print(f"Response data: {token_data}")
            return None
        
        # Print tokens
        print("\nToken information:")
        print(f"Access Token: {access_token}")
        print(f"Refresh Token: {refresh_token}")
        print(f"Expires In: {expires_in} seconds")
        
        # Update .env file
        update_env_file(access_token, refresh_token)
        
        return token_data
    
    except Exception as e:
        print(f"Error: {e}")
        return None

def update_env_file(access_token, refresh_token):
    """Update the .env file with new tokens."""
    try:
        # Read current .env file
        env_lines = []
        if os.path.exists('.env'):
            with open('.env', 'r') as f:
                env_lines = f.readlines()
        
        # Update token values
        access_token_updated = False
        refresh_token_updated = False
        expiry_updated = False
        
        for i, line in enumerate(env_lines):
            if line.startswith('CONSTANT_CONTACT_ACCESS_TOKEN='):
                env_lines[i] = f'CONSTANT_CONTACT_ACCESS_TOKEN={access_token}\n'
                access_token_updated = True
            elif line.startswith('CONSTANT_CONTACT_REFRESH_TOKEN='):
                env_lines[i] = f'CONSTANT_CONTACT_REFRESH_TOKEN={refresh_token}\n'
                refresh_token_updated = True
            elif line.startswith('TOKEN_EXPIRY='):
                env_lines[i] = f'TOKEN_EXPIRY=0\n'
                expiry_updated = True
        
        # Add tokens if not updated
        if not access_token_updated:
            env_lines.append(f'CONSTANT_CONTACT_ACCESS_TOKEN={access_token}\n')
        if not refresh_token_updated:
            env_lines.append(f'CONSTANT_CONTACT_REFRESH_TOKEN={refresh_token}\n')
        if not expiry_updated:
            env_lines.append(f'TOKEN_EXPIRY=0\n')
        
        # Write updated .env file
        with open('.env', 'w') as f:
            f.writelines(env_lines)
        
        print("\n.env file updated with new tokens.")
    
    except Exception as e:
        print(f"Error updating .env file: {e}")
        print("Please manually update your .env file with the new tokens.")

def main():
    """Main function."""
    if len(sys.argv) != 2:
        print("Usage: python get_token.py <authorization_code>")
        print("\nTo get an authorization code:")
        print(f"1. Open this URL in your browser:")
        print(f"   https://authz.constantcontact.com/oauth2/default/v1/authorize?client_id={API_KEY}&redirect_uri={REDIRECT_URI}&response_type=code&scope=contact_data")
        print("2. Log in to your Constant Contact account")
        print("3. Authorize the application")
        print("4. Copy the code parameter from the redirect URL")
        print("5. Run this script with the code as an argument")
        sys.exit(1)
    
    auth_code = sys.argv[1]
    get_tokens(auth_code)

if __name__ == "__main__":
    main() 