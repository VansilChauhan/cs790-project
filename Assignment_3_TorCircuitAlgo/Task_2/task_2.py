# Standard libraries
import random
import threading
import re
import base64
import requests

# For scraping latest consensus
from bs4 import BeautifulSoup

# Tor control library
from stem.control import Controller, EventType

# Downloads the most recent Tor relay consensus file from the Tor Project's collector
def fetch_latest_consensus():
    # Base URL where recent consensus files are hosted
    base_url = "https://collector.torproject.org/recent/relay-descriptors/consensuses/"
    
    # Request the directory listing from the Tor metrics collector
    response = requests.get(base_url)
    if response.status_code != 200:
        raise Exception(f"Failed to list consensus files: {response.status_code}")
    
    # Parse the HTML response to extract links to consensus files
    soup = BeautifulSoup(response.text, 'html.parser')
    links = [a['href'] for a in soup.find_all('a', href=True) if 'consensus' in a['href']]
    links = sorted(links, reverse=True)  # Sort to get the most recent file first

    # Get the most recent consensus file
    latest_file = links[0]
    print(f"📄 Latest consensus file: {latest_file}")

    # Build the full URL to the consensus file and fetch it
    consensus_url = base_url + latest_file
    consensus_resp = requests.get(consensus_url)
    if consensus_resp.status_code != 200:
        raise Exception(f"Failed to fetch consensus: {consensus_resp.status_code}")
    
    print("✅ Successfully fetched latest consensus.")
    
    # Save the consensus file to disk as 'consensus.txt'
    with open("consensus.txt", "w", encoding='utf-8') as f:
        f.write(consensus_resp.text)


# Relay class to store parsed information about Tor relays
class Relay:
    def __init__(self, fingerprint, nickname, flags, bandwidth, address, or_port):
        self.fingerprint = fingerprint
        self.nickname = nickname
        self.flags = set(flags)
        self.bandwidth = bandwidth
        self.address = address
        self.or_port = or_port

    def __repr__(self):
        return f"<Relay {self.nickname} ({self.fingerprint[:6]}...) {self.flags} BW={self.bandwidth} IP={self.address}:{self.or_port}>"

# Parses a Tor consensus file to extract relay information
def parse_consensus_file(path):
    relays = []
    with open(path, 'r') as f:
        content = f.read()

    # Break the file into relay sections, starting with 'r ' lines
    relay_sections = re.split(r'\nr ', '\n' + content)

    for section in relay_sections[1:]:
        lines = section.splitlines()
        try:
            # Parse the 'r' line to extract identity information
            r_parts = lines[0].split()
            nickname = r_parts[0]
            fingerprint_b64 = r_parts[1]
            address = r_parts[5]
            or_port = int(r_parts[6])

            # Convert fingerprint from base64 to hex format
            fingerprint_hex = base64.b64decode(fingerprint_b64 + '==').hex().upper()

            # Extract relay flags from the 's' line
            s_line = next((l for l in lines if l.startswith('s ')), '')
            flags = s_line.split()[1:] if s_line else []

            # Extract bandwidth information from the 'w' line
            w_line = next((l for l in lines if l.startswith('w ')), '')
            bandwidth = 0
            if w_line:
                bw_match = re.search(r'Bandwidth=(\d+)', w_line)
                if bw_match:
                    bandwidth = int(bw_match.group(1))

            # Create Relay object and add to the list
            relay = Relay(fingerprint_hex, nickname, flags, bandwidth, address, or_port)
            relays.append(relay)

        except Exception as e:
            print(f"Failed to parse relay section: {e}")
            continue

    return relays

# Helper function to select a relay based on bandwidth-weighted probability
def weighted_choice(relays):
    total_bw = sum(r.bandwidth for r in relays if r.bandwidth > 0)
    if total_bw == 0:
        return random.choice(relays)
    r = random.uniform(0, total_bw)
    upto = 0
    for relay in relays:
        if relay.bandwidth <= 0:
            continue
        upto += relay.bandwidth
        if upto >= r:
            return relay
    return random.choice(relays)

# Guard relay selection logic
def select_guard(relays):
    eligible = [r for r in relays if 'Guard' in r.flags and 'Running' in r.flags and 'Valid' in r.flags]
    return weighted_choice(eligible)

# Middle relay selection logic (excluding certain nodes)
def select_middle(relays, exclude):
    eligible = [r for r in relays if 'Running' in r.flags and 'Valid' in r.flags and r not in exclude]
    return weighted_choice(eligible)

# Exit relay selection logic
def select_exit(relays, exclude):
    eligible = [r for r in relays if 'Exit' in r.flags and 'Running' in r.flags and 'Valid' in r.flags and r not in exclude]
    return weighted_choice(eligible)

# Creates a custom n-hop circuit using given relays
def create_n_hop_circuit(controller, relays, hop_count):
    circuit_id = -1
    for attempt in range(15):
        print(f"Attempt {attempt+1}/15")

        try:
            guard = select_guard(relays)
            exit_node = select_exit(relays, exclude={guard})

            middle_nodes = []
            used_nodes = {guard, exit_node}

            # Select unique middle nodes
            for _ in range(hop_count - 2):
                node = select_middle(relays, exclude=used_nodes)
                if node is None:
                    raise Exception("Unable to find unique middle node")
                middle_nodes.append(node)
                used_nodes.add(node)

            # Build circuit using selected relays
            circuit = [guard.fingerprint] + [n.fingerprint for n in middle_nodes] + [exit_node.fingerprint]
            circuit_id = controller.new_circuit(path=circuit, await_build=True)
            break

        except Exception as e:
            print(f"Failed to build circuit: {e}")
    return int(circuit_id)

# Attaches new streams to a custom circuit using an event listener
def attach_stream_to_circuit(controller, circuit_id):
    def attach_stream(stream):
        try:
            if stream.status == 'NEW':
                controller.attach_stream(stream.id, circuit_id)
        except Exception as e:
            print(f"Failed to attach stream {stream.id}: {e}")

    controller.add_event_listener(attach_stream, EventType.STREAM)
    controller.set_conf('__LeaveStreamsUnattached', '1')
    print(f"Attached listener to EventType.STREAM")

# Resets Tor configuration to default behavior
def reset_tor_config(controller):
    try:
        controller.remove_event_listener(EventType.STREAM)
        print(f"Success: Removed event listener")
    except Exception as e:
        print(f"Warning: could not remove stream listener – {e}")

    try:
        controller.reset_conf('__LeaveStreamsUnattached')
        print(f"Success: Reset config")
    except Exception as e:
        print(f"Warning: could not reset config – {e}")

# Sends a GET request through the Tor SOCKS proxy
def send_get_request(url):
    proxies = {
        'http': 'socks5h://127.0.0.1:9050',
        'https': 'socks5h://127.0.0.1:9050',
    }

    try:
        response = requests.get(url, proxies=proxies, timeout=10)
        print(f"Status Code: {response.status_code}")
        print("Response Snippet:")
        print(response.text[:500])  # print only first 500 characters
        return response.text
    except requests.RequestException as e:
        print(f"Request failed: {e}")
        return None

# Returns all currently built circuits
def get_available_circuits(controller):
    circuits = controller.get_circuits()
    available_circuits = []
    for circ in circuits:
        if circ.status != 'BUILT':
            continue
        available_circuits.append(circ)
    return available_circuits

# Prints a list of all built circuits
def print_available_circuits(controller):
    print("-" * 20)
    print("Available circuits")
    for i, circ in enumerate(available_circuits):
        print(f"{i+1}. Circuit id: {circ.id} (hops: {len(circ.path)})")
    print("-" * 20)

# ---- MAIN SCRIPT BEGINS ----

try:
    fetch_latest_consensus()  # Fetch the latest consensus from Tor directory
finally:
    relays = parse_consensus_file("consensus.txt")  # Parse the consensus file

# Connect to the Tor control port
with Controller.from_port(port=9051) as controller:
    controller.authenticate()
    print("Connected to Tor!")

    is_quit = False
    try:
        while not is_quit:
            available_circuits = get_available_circuits(controller)
            if len(available_circuits) == 0:
                # If no circuit exists, prompt user to create one or exit
                print("--------------------------")
                print("No circuits available")
                print("==========================")
                print(f"1. Create custom circuit")
                print(f"2. Exit")
                choice = int(input("Choose: "))
                print("--------------------------")
                if choice == 1:
                    hop_count = int(input("Specify required hop count: "))
                    circuit_id = create_n_hop_circuit(controller=controller, relays=relays, hop_count=hop_count)
                    if circuit_id > 0:
                        print(f"Circuit id: {circuit_id}")
                    else:
                        print(f"Failed to create circuit! Try again...")
                else:
                    is_quit = True
            else:
                # Menu when circuits are available
                print("===========================================")
                print(f"1. List all available circuit")
                print(f"2. Create custom circuit")
                print(f"3. Attach stream to custom circuit")
                print(f"4. Reset stream configurations")
                print(f"5. GET request")
                print(f"6. Close tor circuit")
                print(f"7. Exit")
                choice = int(input("Choose: "))
                print("--------------------------")
                if choice == 1:
                    print_available_circuits(controller)

                elif choice == 2:
                    hop_count = int(input("Specify required hop count: "))
                    print("It may take a while. If it takes too long (~15-20s)... please retry.")
                    circuit_id = create_n_hop_circuit(controller=controller, relays=relays, hop_count=hop_count)
                    if circuit_id > 0:
                        print(f"Circuit id: {circuit_id}")
                    else:
                        print(f"Failed to create circuit! Try again...")

                elif choice == 3:
                    print_available_circuits(controller)
                    selected_circ = input("Enter Circuit ID: ")
                    stream_attached = threading.Event()
                    attach_stream_to_circuit(controller=controller, circuit_id=selected_circ)

                elif choice == 4:
                    reset_tor_config(controller=controller)

                elif choice == 5:
                    url = input("Enter url: ")
                    send_get_request(url)

                elif choice == 6:
                    print_available_circuits(controller)
                    selected_circ = input("Enter Circuit ID: ")
                    controller.close_circuit(selected_circ)
                    print(f"Closed circuit {selected_circ}")

                else:
                    is_quit = True
    except Exception as e:
        print(f"Error: {e}")

    finally:
        # Always reset config and close controller when exiting
        reset_tor_config(controller)
        controller.close()
