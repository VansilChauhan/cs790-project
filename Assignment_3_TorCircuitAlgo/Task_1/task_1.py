import random
import threading
import requests
from stem.control import Controller, EventType

proxies = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
}

def pick_relays(relays, required_flags):
    options = [r for r in relays if all(flag in r.flags for flag in required_flags)]
    return random.choice(options) if options else None

def create_4_hop_circuit(controller):
    circuit_id = -1
    relays = list(controller.get_network_statuses())

    for attempt in range(15):
        print(f"Attempt {attempt + 1}/15")

        try:
            guard = pick_relays(relays, ["Guard", "Fast", "Running", "Stable", "Valid"])
            middle_1 = pick_relays(relays, ["Fast", "Running", "Stable", "Valid"])
            middle_2 = pick_relays(relays, ["Fast", "Running", "Stable", "Valid"])
            exit_node = pick_relays(relays, ["Exit", "Fast", "Running", "Stable", "Valid"])

            if not all([guard, middle_1, middle_2, exit_node]):
                print("Could not find suitable relays, retrying...")
                continue
            
            fps = {r.fingerprint for r in [guard, middle_1, middle_2, exit_node]}
            if len(fps) < 4:
                print("Duplicate relays detected, retrying...")
                continue
            
            path = [guard.fingerprint, middle_1.fingerprint, middle_2.fingerprint, exit_node.fingerprint]
            circuit_id = controller.new_circuit(path=path, await_build=True)

            print("Picked Relays: ")
            print(f"Guard     : {guard.fingerprint} ({guard.nickname})")
            print(f"Middle #1 : {middle_1.fingerprint} ({middle_1.nickname})")
            print(f"Middle #2 : {middle_2.fingerprint} ({middle_2.nickname})")
            print(f"Exit      : {exit_node.fingerprint} ({exit_node.nickname})")
            break
        except Exception as e:
            print(f"Failed to build circuit: {e}")
    return int(circuit_id)


def close_circuit(controller, circuit_id):
    controller.close_circuit(circuit_id)
    print(f"Closed circuit {circuit_id}")


def get_available_custom_ciruits(controller):
    circuits = controller.get_circuits()
    circuits_with_4_hops = []
    for circ in circuits:
        if circ.status != 'BUILT':
            continue
        
        if len(circ.path) == 4:
            circuits_with_4_hops.append(int(circ.id))
    return circuits_with_4_hops

def close_all_custom_circuits(controller):
    circuits_with_4_hops = get_available_custom_ciruits(controller)
    for circ in circuits_with_4_hops:
        close_circuit(controller=controller, circuit_id=circ)

def tor_default_get_request(url):
    res = requests.get(url, proxies=proxies)
    print(res.status_code)
    print(res.text[:500])

def tor_custom_get_request(controller, url, circ):
    controller.set_conf('__LeaveStreamsUnattached', '1')
    stream_attached = threading.Event()

    def attach_stream(stream):
        if stream.status == 'NEW':
            print(f"Attaching stream {stream.id} to circuit {circ}")
            try:
                controller.attach_stream(stream.id, circ)
                stream_attached.set()
            except Exception as e:
                print(f"Failed to attach stream: {e}")
    
    controller.add_event_listener(attach_stream, EventType.STREAM)

    try:
        print(f"Making request to {url}")
        response_thread = threading.Thread(target=lambda: requests.get(url, proxies=proxies))
        response_thread.start()

        stream_attached.wait(timeout=10)

        response_thread.join()
        print("Request completed.")
    
    finally:
        controller.remove_event_listener(attach_stream)
        controller.reset_conf('__LeaveStreamsUnattached')



with Controller.from_port(port=9051) as controller:
    controller.authenticate()
    
    is_quit = False
    try:
        while not is_quit:
            circuits_with_4_hops = get_available_custom_ciruits(controller)
            if len(circuits_with_4_hops) == 0:
                print("--------------------------")
                print("No Custom 4 hops circuits available")
                print("==========================")
                print(f"1. Create 4 hop circuit")
                print(f"2. Exit")
                choice = int(input("Choose: "))
                print("--------------------------")
                if choice == 1:
                    circuit_id = create_4_hop_circuit(controller)
                    if circuit_id > 0:
                        print(f"Circuit id: {circuit_id}")
                    else:
                        print(f"Faild to create circuit! Try again...")
                else:
                    is_quit = True
            
            else:
                print("========================================")
                print(f"1. Simple get request through tor default")
                print(f"2. Simple get request through custom tor circuits")
                print(f"3. Close all custom circuits")
                print(f"4. Exit")
                choice = int(input("Choose: "))
                print("--------------------------")
                if choice < 3:
                    url = input("Enter url: ")
                    if choice == 1:
                        tor_default_get_request(url)
                    elif choice == 2:
                        print("-" * 20)
                        print("Available custom 4 hop circuits")
                        for i, circ in enumerate(circuits_with_4_hops):
                            print(f"{i+1}. Circuit id: {circ}")
                        print("-" * 20)
                        selected_circ = input("Enter Circuit ID: ")
                        tor_custom_get_request(controller=controller, url=url, circ=selected_circ)

                elif choice == 3:
                    close_all_custom_circuits(controller=controller)
                else:
                    is_quit = True
                
    except Exception as e:
        print(f"Error: {e}")
        
    finally:
        controller.close()

print("End!")



