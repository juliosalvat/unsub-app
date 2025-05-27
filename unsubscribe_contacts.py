#!/usr/bin/env python3
"""
Unsubscribe Contacts Script

This script reads email addresses from a CSV file and unsubscribes them from Constant Contact.
"""

import os
import sys
import csv
import json
import time
import requests
import pandas as pd
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Constant Contact API credentials
API_KEY = os.getenv('CONSTANT_CONTACT_API_KEY')
ACCESS_TOKEN = os.getenv('CONSTANT_CONTACT_ACCESS_TOKEN')
REFRESH_TOKEN = os.getenv('CONSTANT_CONTACT_REFRESH_TOKEN')
TOKEN_EXPIRY = os.getenv('TOKEN_EXPIRY')
CLIENT_SECRET = os.getenv('CONSTANT_CONTACT_CLIENT_SECRET')
REDIRECT_URI = os.getenv('CONSTANT_CONTACT_REDIRECT_URI')

# Debug print
print("Loaded environment variables:")
print(f"API_KEY: {'*' * 5}{API_KEY[-5:] if API_KEY else 'None'}")
print(f"ACCESS_TOKEN: {'*' * 5}{ACCESS_TOKEN[-5:] if ACCESS_TOKEN else 'None'}")
print(f"REFRESH_TOKEN: {'*' * 5}{REFRESH_TOKEN[-5:] if REFRESH_TOKEN else 'None'}")
print(f"TOKEN_EXPIRY: {TOKEN_EXPIRY}")
print(f"CLIENT_SECRET: {'*' * 5}{CLIENT_SECRET[-5:] if CLIENT_SECRET else 'None'}")
print(f"REDIRECT_URI: {REDIRECT_URI}")

# API endpoints
BASE_URL = 'https://api.cc.email/v3'
AUTH_URL = 'https://authz.constantcontact.com/oauth2/default/v1/token'

def handle_expired_tokens():
    """Handle expired tokens using authorization code flow."""
    global ACCESS_TOKEN, REFRESH_TOKEN, TOKEN_EXPIRY
    
    try:
        print("\n" + "="*80)
        print("TOKEN RENEWAL REQUIRED")
        print("="*80)
        print("\nYour access and refresh tokens are expired or invalid.")
        print("\nTo continue, you need to manually get a new authorization code.")
        print("\nFollow these steps:")
        print("1. Visit this URL in your browser:")
        
        # Create the authorization URL with the allowed redirect URI
        redirect_uri = "https://localhost"
        auth_params = {
            'response_type': 'code',
            'client_id': API_KEY,
            'redirect_uri': redirect_uri,
            'scope': 'contact_data campaign_data offline_access',
            'state': 'applyNow'
        }
        auth_url = 'https://authz.constantcontact.com/oauth2/default/v1/authorize?' + '&'.join([f"{k}={v}" for k, v in auth_params.items()])
        
        print("\n" + auth_url)
        print("\n2. Log in with your Constant Contact credentials")
        print("3. Authorize the application when prompted")
        print("4. You will be redirected to a URL like: https://localhost/?code=XXXX&state=applyNow")
        print("5. Copy the authorization code (the part between 'code=' and '&state=')")
        
        # Get the authorization code from the user
        print("\nPaste the authorization code here:")
        auth_code = input("Authorization code: ").strip()
        
        if not auth_code:
            print("No authorization code provided. Cannot continue.")
            return False
        
        # Exchange the authorization code for tokens
        print("\nExchanging authorization code for tokens...")
        
        # Prepare the request data
        data = {
            'grant_type': 'authorization_code',
            'code': auth_code,
            'client_id': API_KEY,
            'client_secret': CLIENT_SECRET,
            'redirect_uri': redirect_uri
        }
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json'
        }
        
        response = requests.post(
            AUTH_URL,
            data=data,
            headers=headers
        )
        
        print(f"Token exchange response status: {response.status_code}")
        
        if response.status_code == 200:
            token_data = response.json()
            ACCESS_TOKEN = token_data['access_token']
            REFRESH_TOKEN = token_data['refresh_token']
            TOKEN_EXPIRY = int(time.time()) + token_data.get('expires_in', 3600)
            
            # Update the .env file
            update_env_file({
                'CONSTANT_CONTACT_ACCESS_TOKEN': ACCESS_TOKEN,
                'CONSTANT_CONTACT_REFRESH_TOKEN': REFRESH_TOKEN,
                'TOKEN_EXPIRY': str(TOKEN_EXPIRY)
            })
            
            print("\nSuccessfully obtained new tokens!")
            return True
        else:
            print(f"Failed to exchange authorization code for tokens. Status: {response.status_code}")
            print(f"Response: {response.text}")
            
            # Give the user another chance
            print("\nWould you like to try again with a different authorization code? (y/n)")
            retry = input("Try again? ").strip().lower()
            if retry == 'y':
                return handle_expired_tokens()
            else:
                return False
    
    except Exception as e:
        print(f"Error during token renewal: {e}")
        return False

def refresh_access_token():
    """Refresh the access token using the refresh token."""
    global ACCESS_TOKEN, REFRESH_TOKEN, TOKEN_EXPIRY
    
    if not REFRESH_TOKEN:
        print("Error: Refresh token not found in environment variables.")
        print("Need to get a new authorization code...")
        return handle_expired_tokens()
    
    try:
        # Prepare the request data
        data = {
            'grant_type': 'refresh_token',
            'refresh_token': REFRESH_TOKEN,
            'client_id': API_KEY,
            'client_secret': CLIENT_SECRET
        }
        
        # Set the headers
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json'
        }
        
        print("Attempting to refresh access token...")
        response = requests.post(
            AUTH_URL,
            data=data,
            headers=headers
        )
        
        # Print the response for debugging
        print(f"Refresh token response status: {response.status_code}")
        
        if response.status_code == 200:
            token_data = response.json()
            ACCESS_TOKEN = token_data['access_token']
            REFRESH_TOKEN = token_data['refresh_token']
            TOKEN_EXPIRY = int(time.time()) + token_data.get('expires_in', 3600)
            
            # Update the .env file
            update_env_file({
                'CONSTANT_CONTACT_ACCESS_TOKEN': ACCESS_TOKEN,
                'CONSTANT_CONTACT_REFRESH_TOKEN': REFRESH_TOKEN,
                'TOKEN_EXPIRY': str(TOKEN_EXPIRY)
            })
            
            print("Successfully refreshed access token!")
            return True
        elif response.status_code == 400:
            # If refresh token is invalid, try to get new authorization code
            print("Refresh token is invalid or expired.")
            print("Need to get a new authorization code...")
            return handle_expired_tokens()
        else:
            print(f"Failed to refresh access token. Status code: {response.status_code}")
            return handle_expired_tokens()
    
    except Exception as e:
        print(f"Error refreshing access token: {e}")
        return False

def update_env_file(updates):
    """Update the .env file with new values."""
    try:
        # Read the current .env file
        with open('.env', 'r') as file:
            lines = file.readlines()
        
        # Update the values
        new_lines = []
        for line in lines:
            for key, value in updates.items():
                if line.startswith(f"{key}="):
                    line = f"{key}={value}\n"
                    break
            new_lines.append(line)
        
        # Write the updated .env file
        with open('.env', 'w') as file:
            file.writelines(new_lines)
        
        print("Successfully updated .env file with new tokens.")
        return True
    except Exception as e:
        print(f"Error updating .env file: {e}")
        return False

def check_token_expiry():
    """Check if the access token is expired and refresh if needed."""
    global ACCESS_TOKEN, REFRESH_TOKEN, TOKEN_EXPIRY
    
    if not TOKEN_EXPIRY:
        # If no expiry time is set, assume token needs refresh
        print("No token expiry time found. Attempting to refresh access token...")
        if refresh_access_token():
            print("Token refreshed successfully.")
            return
        else:
            print("Token refresh failed, continuing with existing access token.")
            return
    
    current_time = int(time.time())
    try:
        expiry_time = int(TOKEN_EXPIRY)
        
        # Refresh token if it's expired or about to expire in the next 5 minutes
        if current_time >= (expiry_time - 300):
            print("Access token expired or about to expire. Refreshing...")
            if refresh_access_token():
                print("Token refreshed successfully.")
                return
            else:
                print("Token refresh failed, continuing with existing access token.")
                return
    except ValueError:
        print(f"Invalid TOKEN_EXPIRY value: {TOKEN_EXPIRY}. Attempting to refresh token...")
        if refresh_access_token():
            print("Token refreshed successfully.")
            return
        else:
            print("Token refresh failed, continuing with existing access token.")
            return

def read_emails_from_csv(csv_file):
    """Read email addresses from a CSV file."""
    try:
        df = pd.read_csv(csv_file)
        
        # Check if 'email' column exists
        if 'email' not in df.columns:
            print("Error: CSV file must contain a column named 'email'")
            sys.exit(1)
        
        # Extract emails and remove duplicates
        emails = df['email'].dropna().drop_duplicates().tolist()
        return emails
    
    except Exception as e:
        print(f"Error reading CSV file: {e}")
        sys.exit(1)

def get_contact_id(email):
    """Get the contact ID for a given email address."""
    global ACCESS_TOKEN
    
    # Debug: Show part of the access token being used
    token_preview = ACCESS_TOKEN[:20] + '...' if ACCESS_TOKEN else 'None'
    print(f"Using access token: {token_preview}")
    
    headers = {
        'Authorization': f'Bearer {ACCESS_TOKEN}',
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    
    params = {
        'email': email
    }
    
    try:
        print(f"Searching for contact with email: {email}")
        response = requests.get(f"{BASE_URL}/contacts", headers=headers, params=params)
        
        # Print response status and headers for debugging
        print(f"Response status code: {response.status_code}")
        print(f"Response headers: {response.headers}")
        
        # Check if token expired (401 Unauthorized)
        if response.status_code == 401:
            print("Received 401 Unauthorized. Access token has expired.")
            print("Attempting to refresh the token...")
            if refresh_access_token():
                print("Token refreshed successfully. Retrying the request...")
                # Update headers with new token
                headers['Authorization'] = f'Bearer {ACCESS_TOKEN}'
                # Retry the request
                response = requests.get(f"{BASE_URL}/contacts", headers=headers, params=params)
                print(f"Retry response status code: {response.status_code}")
            else:
                print("Failed to refresh token. Cannot continue with this request.")
                return None
        
        # Handle 400 Bad Request errors
        if response.status_code == 400:
            print(f"Bad Request Error when searching for {email}:")
            try:
                error_data = response.json()
                if isinstance(error_data, dict) and 'error_key' in error_data:
                    print(f"Error Key: {error_data.get('error_key')}")
                    print(f"Error Message: {error_data.get('error_message')}")
                else:
                    print(f"Response: {error_data}")
            except:
                print(f"Response: {response.text}")
            
            print("\nThis may be due to:")
            print("1. Invalid email format")
            print("2. API limitations or restrictions")
            print("3. Rate limiting (too many requests)")
            print("\nSkipping this email and continuing...")
            return None
        
        response.raise_for_status()
        
        data = response.json()
        contacts = data.get('contacts', [])
        
        if not contacts:
            print(f"No contact found with email: {email}")
            return None
        
        contact_id = contacts[0].get('contact_id')
        if not contact_id:
            print(f"Contact found but no contact_id for email: {email}")
            return None
        
        print(f"Found contact ID: {contact_id}")
        return contact_id
    
    except requests.exceptions.RequestException as e:
        print(f"Error searching for contact {email}: {e}")
        if hasattr(e, 'response') and e.response:
            try:
                error_data = e.response.json()
                print(f"Error details: {json.dumps(error_data, indent=2)}")
            except:
                print(f"Response: {e.response.text}")
        return None

def unsubscribe_contact(contact_id):
    """Unsubscribe a contact using their contact ID."""
    global ACCESS_TOKEN
    
    if not contact_id:
        return False
    
    headers = {
        'Authorization': f'Bearer {ACCESS_TOKEN}',
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    
    try:
        print(f"Unsubscribing contact with ID: {contact_id}")
        
        # First, get the contact details to ensure we have the correct format
        get_response = requests.get(f"{BASE_URL}/contacts/{contact_id}", headers=headers)
        
        # Check if token expired (401 Unauthorized)
        if get_response.status_code == 401:
            print("Access token expired during operation.")
            print("Attempting to refresh the token...")
            if refresh_access_token():
                print("Token refreshed successfully. Retrying the request...")
                # Update headers with new token
                headers['Authorization'] = f'Bearer {ACCESS_TOKEN}'
                # Retry the request
                get_response = requests.get(f"{BASE_URL}/contacts/{contact_id}", headers=headers)
                print(f"Retry response status code: {get_response.status_code}")
            else:
                print("Failed to refresh token. Cannot continue with this request.")
                return False
        
        # Handle 404 Not Found errors
        if get_response.status_code == 404:
            print(f"Contact ID {contact_id} not found. This may be a test contact or an invalid ID.")
            return False
        
        get_response.raise_for_status()
        
        # Get the contact data
        contact_data = get_response.json()
        email_address = contact_data.get('email_address', {}).get('address', 'Unknown email')
        print(f"Retrieved contact details for: {email_address}")
        
        # Get the current permission_to_send value to understand what values are accepted by the API
        current_permission = contact_data.get('email_address', {}).get('permission_to_send')
        print(f"Current permission_to_send value: {current_permission}")
        
        # Create a copy of the contact data to modify
        updated_contact = contact_data.copy()
        
        # Update the email_address section to change permission_to_send
        if 'email_address' in updated_contact:
            # Try with the value that matches the API documentation
            updated_contact['email_address']['permission_to_send'] = 'implicit'
            
            # Add opt-out fields
            updated_contact['email_address']['opt_out_source'] = 'Contact'
            updated_contact['email_address']['opt_out_date'] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        
        # Set the update_source
        updated_contact['update_source'] = 'Contact'
        
        # Also remove from all lists
        updated_contact['list_memberships'] = []
        
        print(f"Sending complete update with permission_to_send=implicit and opt_out fields")
        response = requests.put(f"{BASE_URL}/contacts/{contact_id}", headers=headers, json=updated_contact)
        
        # Check if token expired (401 Unauthorized)
        if response.status_code == 401:
            print("Access token expired during update operation.")
            print("Attempting to refresh the token...")
            if refresh_access_token():
                print("Token refreshed successfully. Retrying the update...")
                # Update headers with new token
                headers['Authorization'] = f'Bearer {ACCESS_TOKEN}'
                # Retry the request
                response = requests.put(f"{BASE_URL}/contacts/{contact_id}", headers=headers, json=updated_contact)
                print(f"Retry update response status code: {response.status_code}")
            else:
                print("Failed to refresh token. Cannot continue with the update.")
                return False
        
        if response.status_code < 400:
            print(f"Successfully updated contact with unsubscribe status")
            return True
        
        print(f"Complete update failed (HTTP {response.status_code}), trying alternative approach...")
        
        # Try with a different permission value
        if 'email_address' in updated_contact:
            updated_contact['email_address']['permission_to_send'] = 'unsubscribed'
        
        print(f"Trying with permission_to_send=unsubscribed")
        alt_response = requests.put(f"{BASE_URL}/contacts/{contact_id}", headers=headers, json=updated_contact)
        
        # Check for 401 on alternative approach
        if alt_response.status_code == 401 and refresh_access_token():
            headers['Authorization'] = f'Bearer {ACCESS_TOKEN}'
            alt_response = requests.put(f"{BASE_URL}/contacts/{contact_id}", headers=headers, json=updated_contact)
        
        if alt_response.status_code < 400:
            print(f"Successfully updated contact with unsubscribe status")
            return True
        
        # Try one more approach - use the direct contact status endpoint
        print(f"Trying direct contact status update")
        status_data = {
            "status": "OPTOUT",
            "source": "Contact"
        }
        
        status_response = requests.patch(f"{BASE_URL}/contacts/{contact_id}/status", headers=headers, json=status_data)
        
        # Check for 401 on status approach
        if status_response.status_code == 401 and refresh_access_token():
            headers['Authorization'] = f'Bearer {ACCESS_TOKEN}'
            status_response = requests.patch(f"{BASE_URL}/contacts/{contact_id}/status", headers=headers, json=status_data)
        
        if status_response.status_code < 400:
            print(f"Successfully updated contact status to OPTOUT")
            return True
        
        # As a last resort, try to use the action endpoint
        print(f"Trying action endpoint to unsubscribe contact")
        action_data = {
            "action_type": "UNSUBSCRIBE",
            "source": "Contact"
        }
        
        action_response = requests.post(f"{BASE_URL}/contacts/{contact_id}/actions", headers=headers, json=action_data)
        
        # Check for 401 on action approach
        if action_response.status_code == 401 and refresh_access_token():
            headers['Authorization'] = f'Bearer {ACCESS_TOKEN}'
            action_response = requests.post(f"{BASE_URL}/contacts/{contact_id}/actions", headers=headers, json=action_data)
        
        if action_response.status_code < 400:
            print(f"Successfully triggered unsubscribe action for contact")
            return True
        
        print(f"All approaches failed. Unable to unsubscribe contact.")
        print(f"Please consider manually unsubscribing this contact through the Constant Contact web interface.")
        return False
    
    except requests.exceptions.RequestException as e:
        print(f"Error unsubscribing contact {contact_id}: {e}")
        if hasattr(e, 'response') and e.response:
            try:
                error_data = e.response.json()
                print(f"Error details: {json.dumps(error_data, indent=2)}")
            except:
                print(f"Response: {e.response.text}")
        return False

def main():
    """Main function to process the CSV and unsubscribe contacts."""
    global ACCESS_TOKEN
    
    print("Starting unsubscribe process...")
    
    # Re-read the access token directly from the .env file to avoid any parsing issues
    try:
        with open('.env', 'r') as env_file:
            for line in env_file:
                if line.startswith('CONSTANT_CONTACT_ACCESS_TOKEN='):
                    ACCESS_TOKEN = line.strip().split('=', 1)[1]
                    # Remove any quotes if present
                    if ACCESS_TOKEN.startswith('"') and ACCESS_TOKEN.endswith('"'):
                        ACCESS_TOKEN = ACCESS_TOKEN[1:-1]
                    elif ACCESS_TOKEN.startswith("'") and ACCESS_TOKEN.endswith("'"):
                        ACCESS_TOKEN = ACCESS_TOKEN[1:-1]
                    print(f"Successfully loaded access token from .env file: {ACCESS_TOKEN[:15]}...")
                    break
    except Exception as e:
        print(f"Error reading access token from .env file: {e}")
    
    if not API_KEY:
        print("Error: Constant Contact API key not found in environment variables.")
        print("Please set CONSTANT_CONTACT_API_KEY in .env file.")
        sys.exit(1)
    
    if not ACCESS_TOKEN:
        print("Error: Constant Contact access token not found in environment variables.")
        print("Please set CONSTANT_CONTACT_ACCESS_TOKEN in .env file.")
        sys.exit(1)
    
    # Check if token needs to be refreshed
    print("Checking if token needs to be refreshed...")
    check_token_expiry()
    
    if len(sys.argv) != 2:
        print("Usage: python unsubscribe_contacts.py <csv_file>")
        sys.exit(1)
    
    csv_file = sys.argv[1]
    
    # Check if file exists
    if not os.path.isfile(csv_file):
        print(f"Error: File '{csv_file}' not found.")
        sys.exit(1)
    
    # Read emails from CSV
    print(f"Reading emails from {csv_file}...")
    emails = read_emails_from_csv(csv_file)
    print(f"Found {len(emails)} unique email addresses.")
    
    # Process each email
    success_count = 0
    not_found_count = 0
    error_count = 0
    not_found_emails = []  # Track emails that weren't found
    
    # Add rate limiting
    rate_limit = 5  # seconds between requests
    print(f"Using rate limit of {rate_limit} seconds between requests to avoid API limits.")
    
    for i, email in enumerate(emails, 1):
        print(f"Processing {i}/{len(emails)}: {email}")
        
        # Get contact ID
        contact_id = get_contact_id(email)
        
        # If we get a 401 response, try refreshing the token once
        if not contact_id and i == 1:
            print("First request failed. Attempting to refresh token...")
            if refresh_access_token():
                print("Token refreshed. Retrying...")
                contact_id = get_contact_id(email)
        
        if not contact_id:
            print(f"  Contact not found for {email}")
            not_found_count += 1
            not_found_emails.append(email)
            # Wait between requests to avoid rate limiting
            if i < len(emails):
                print(f"Waiting {rate_limit} seconds before next request...")
                time.sleep(rate_limit)
            continue
        
        # Unsubscribe contact
        unsubscribe_success = unsubscribe_contact(contact_id)
        
        # If unsubscribe fails due to authorization, try refreshing token
        if not unsubscribe_success:
            print("Unsubscribe failed. Checking if token refresh is needed...")
            if refresh_access_token():
                print("Token refreshed. Retrying unsubscribe...")
                unsubscribe_success = unsubscribe_contact(contact_id)
        
        if unsubscribe_success:
            print(f"  Successfully unsubscribed {email}")
            success_count += 1
        else:
            print(f"  Failed to unsubscribe {email}")
            error_count += 1
        
        # Wait between requests to avoid rate limiting
        if i < len(emails):
            print(f"Waiting {rate_limit} seconds before next request...")
            time.sleep(rate_limit)
    
    # Print summary
    print("\nUnsubscribe Summary:")
    print(f"  Total emails processed: {len(emails)}")
    print(f"  Successfully unsubscribed: {success_count}")
    print(f"  Contacts not found: {not_found_count}")
    print(f"  Errors during unsubscribe: {error_count}")
    
    # Print not found emails
    if not_found_emails:
        print("\nEmails not found in Constant Contact:")
        for email in not_found_emails:
            print(f"  - {email}")
        print("\nNOTE: These emails may not be in your Constant Contact account or may already be unsubscribed.")

if __name__ == "__main__":
    main() 