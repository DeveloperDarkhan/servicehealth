import socket
import requests

# Get local IP address
def get_local_ip():
    try:
        # Connect to an external host; doesn't have to be reachable
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        return local_ip
    except Exception as e:
        return f"Error obtaining local IP: {e}"

# Get public IP address
def get_public_ip():
    try:
        response = requests.get('https://api.ipify.org?format=json')
        response.raise_for_status()
        return response.json()['ip']
    except Exception as e:
        return f"Error obtaining public IP: {e}"

if __name__ == "__main__":
    print("Local IP Address:", get_local_ip())
    print("Public IP Address:", get_public_ip())
