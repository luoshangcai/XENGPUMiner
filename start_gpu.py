import time, json, requests, time, hashlib, string, threading, re, configparser, os, psutil
from passlib.hash import argon2
from random import choice, randrange
from datetime import datetime
from tqdm import tqdm

import pynvml
import argparse
import configparser

# Set up argument parser
parser = argparse.ArgumentParser(description="Process optional account and worker arguments.")
parser.add_argument('--account', type=str, help='The account value to use.')
parser.add_argument('--worker', type=int, help='The worker id to use.')

# Parse the arguments
args = parser.parse_args()

# Access the arguments via args object
account = args.account
worker_id = args.worker

# For example, to print the values
print(f'Account: {account}, Worker ID: {worker_id}')

# Load the configuration file
config = configparser.ConfigParser()
config_file_path = 'config.conf'

if os.path.exists(config_file_path):
    config.read(config_file_path)
else:
    raise FileNotFoundError(f"The configuration file {config_file_path} was not found.")

# Ensure that the required settings are present
required_settings = ['difficulty', 'memory_cost', 'cores', 'account', 'server_url']
if not all(key in config['Settings'] for key in required_settings):
    missing_keys = [key for key in required_settings if key not in config['Settings']]
    raise KeyError(f"Missing required settings: {', '.join(missing_keys)}")

# Override account from config file with command line argument if provided
if not args.account:
    account = config['Settings']['account']

# Access other settings
difficulty = int(config['Settings']['difficulty'])
memory_cost = int(config['Settings']['memory_cost'])
cores = int(config['Settings']['cores'])
server_url = config['Settings']['server_url']

updated_memory_cost = 10000 # just initialize it

# Gpu info
pynvml.nvmlInit()
gpu_count = pynvml.nvmlDeviceGetCount()
gpu_handles = []
for i in range(gpu_count):
    gpu_handles.append(pynvml.nvmlDeviceGetHandleByIndex(i))


def hash_value(value):
    return hashlib.sha256(value.encode()).hexdigest()


def build_merkle_tree(elements, merkle_tree={}):
    if len(elements) == 1:
        return elements[0], merkle_tree

    new_elements = []
    for i in range(0, len(elements), 2):
        left = elements[i]
        right = elements[i + 1] if i + 1 < len(elements) else left
        combined = left + right
        new_hash = hash_value(combined)
        merkle_tree[new_hash] = {'left': left, 'right': right}
        new_elements.append(new_hash)
    return build_merkle_tree(new_elements, merkle_tree)


def is_within_five_minutes_of_hour():
    timestamp = datetime.now()
    minutes = timestamp.minute
    return 0 <= minutes < 5 or 55 <= minutes < 60


def write_difficulty_to_file(difficulty, filename='difficulty.txt'):
    with open(filename, 'w') as file:
        file.write(difficulty)


def update_memory_cost_periodically():
    global memory_cost
    global updated_memory_cost
    while True:
        updated_memory_cost = fetch_difficulty_from_server()
        if updated_memory_cost != memory_cost:
            write_difficulty_to_file(updated_memory_cost)
            print(f"Updating difficulty to {updated_memory_cost}")
            memory_cost = updated_memory_cost
        time.sleep(20)  # Fetch every # seconds


# Function to get difficulty level from the server
def fetch_difficulty_from_server():
    global memory_cost
    try:
        response = requests.get(f'{server_url}/difficulty')
        response_data = response.json()
        return str(response_data['difficulty'])
    except Exception as e:
        print(f"An error occurred while fetching difficulty: {e}")
        return memory_cost  # Return last value if fetching fails
    

def get_pid_by_name(pname):
    pids = psutil.process_iter()
    res = []
    for pid in pids:
        if (pid.name() == pname):
            res.append(pid.pid)
    return res


def monitor_miner_process():
    # Check the miner process periodically   
    while True:     
        miner_list = get_pid_by_name('xen')
        if len(miner_list) > 0:
            # check all gpu mem
            memtotal = 0
            memused = 0
            for gpu in gpu_handles:
                meminfo = pynvml.nvmlDeviceGetMemoryInfo(gpu)
                memtotal += int(meminfo.total/1024**3)
                memused += round(meminfo.used/1024**3, 3)
            memused_pct = memused / memtotal
            if memused_pct < 0.60 or memused_pct > 0.996:
                print(f"\nMemory not in efficiency range ({memused} / {memtotal}). Restarting...")
                for pid in miner_list:
                    os.system(f"kill {pid}")
            time.sleep(1)
            miner_list = get_pid_by_name('xen')

        if len(miner_list) == 0:
            # batch_size = int(memtotal * 0.825 * 1024 ** 2 / int(updated_memory_cost))
            print(f"\nNo miners are running. Starting...")
            for i in range(gpu_count):
                os.system(f"nohup ./xen -d{i} &")
                print(f"Miner is running on GPU {i}")

        time.sleep(10)


def submit_pow(account_address, key, hash_to_verify):
    # Download last block record
    try:
        # Attempt to download the last block record
        response = requests.get(f"{server_url}:4445/getblocks/lastblock", timeout=10)  # Adding a timeout of 10 seconds
    except requests.exceptions.RequestException as e:
        # Handle any exceptions that occur during the request
        print(f"An error occurred: {e}")
        return None  # Optionally return an error value or re-raise the exception

    if response.status_code != 200:
        # Handle unexpected HTTP status codes
        print(f"Unexpected status code {response.status_code}: {response.text}")
        return None  # Optionally return an error value

    if response.status_code == 200:
        records = json.loads(response.text)
        verified_hashes = []

        for record in records:
            block_id = record.get('block_id')
            record_hash_to_verify = record.get('hash_to_verify')
            record_key = record.get('key')
            account = record.get('account')

            # Verify each record using Argon2
            if record_key is None or record_hash_to_verify is None:
                print(f'Skipping record due to None value(s): record_key: {record_key}, record_hash_to_verify: {record_hash_to_verify}')
                continue  # skip to the next record

            if argon2.verify(record_key, record_hash_to_verify):
                verified_hashes.append(hash_value(str(block_id) + record_hash_to_verify + record_key + account))

        # If we have any verified hashes, build the Merkle root
        if verified_hashes:
            merkle_root, _ = build_merkle_tree(verified_hashes)

            # Calculate block ID for output (using the last record for reference)
            output_block_id = int(block_id / 100)

            # Prepare payload for PoW
            payload = {
                'account_address': account_address,
                'block_id': output_block_id,
                'merkle_root': merkle_root,
                'key': key,
                'hash_to_verify': hash_to_verify
            }

            # Send POST request
            pow_response = requests.post(f'{server_url}:4446/send_pow', json=payload)

            if pow_response.status_code == 200:
                print(f"Proof of Work successful: {pow_response.json()}")
            else:
                print(f"Proof of Work failed: {pow_response.json()}")

            print(f"Block ID: {output_block_id}, Merkle Root: {merkle_root}")

    else:
        print("Failed to fetch the last block.")

# ANSI escape codes
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
RESET = "\033[0m"

normal_blocks_count = 0
super_blocks_count = 0
xuni_blocks_count = 0
def submit_block(key):
    global updated_memory_cost  # Make it global so that we can update it
    found_valid_hash = False

    global normal_blocks_count
    global super_blocks_count
    global xuni_blocks_count

    argon2_hasher = argon2.using(time_cost=difficulty, salt=b"XEN10082022XEN", memory_cost=updated_memory_cost, parallelism=cores, hash_len = 64)
    hashed_data = argon2_hasher.hash(key)

    for target in stored_targets:
        if target in hashed_data[-87:]:
        # Search for the pattern "XUNI" followed by a digit (0-9)
            if re.search("XUNI[0-9]", hashed_data) and is_within_five_minutes_of_hour():
                found_valid_hash = True
                break
            elif target == "XEN11":
                found_valid_hash = True
                capital_count = sum(1 for char in re.sub('[0-9]', '', hashed_data) if char.isupper())
                if capital_count >= 65:
                    print(f"{RED}Superblock found{RESET}")
                break
            else:
                found_valid_hash = False
                break

    if found_valid_hash:
        print(f"\n{RED}Found valid hash for target {target}{RESET}")
        # Prepare the payload
        payload = {
            "hash_to_verify": hashed_data,
            "key": key,
            "account": account,
            "attempts": "130000",
            "hashes_per_second": "1000",
            "worker": worker_id  # Adding worker information to the payload
        }
        print(payload)

        max_retries = 5
        retries = 0
        while retries <= max_retries:
            # Make the POST request
            response = requests.post(f'{server_url}/verify', json=payload)
            # Print the HTTP status code
            print("HTTP Status Code:", response.status_code)

            if found_valid_hash and response.status_code == 200:
                if "XUNI" in hashed_data:
                    xuni_blocks_count += 1
                    break
                elif "XEN11" in hashed_data:
                    capital_count = sum(1 for char in re.sub('[0-9]', '', hashed_data) if char.isupper())
                    if capital_count >= 65:
                        super_blocks_count += 1
                    else:
                        normal_blocks_count += 1

            if target == "XEN11" and found_valid_hash and response.status_code == 200:
                #submit proof of work validation of last sealed block
                submit_pow(account, key, hashed_data)

            if response.status_code != 500:  # If status code is not 500, break the loop
                print("Server Response:", response.json())
                break
            
            retries += 1
            print(f"Retrying... ({retries}/{max_retries})")
            time.sleep(3)  # You can adjust the sleep time
            # Print the server's response
            try:
                print("Server Response:", response.json())
            except Exception as e:
                print("An error occurred:", e)

    return key, hashed_data


def monitor_blocks_directory():
    counter = 0
    with tqdm(total=None, dynamic_ncols=True, desc=f"{GREEN}Mining{RESET}", unit=f" {GREEN}Blocks{RESET}") as pbar:
        while True:
            XENDIR = f"gpu_found_blocks_tmp/"
            if not os.path.exists(XENDIR):
                os.makedirs(XENDIR)
            for filename in os.listdir(XENDIR):
                filepath = os.path.join(XENDIR, filename)
                with open(filepath, 'r') as f:
                    data = f.read()
                submit_block(data)
                os.remove(filepath)
                pbar.update(1)

            superblock = f"{RED}super:{super_blocks_count}{RESET} "
            block = f"{GREEN}normal:{normal_blocks_count}{RESET} "
            xuni = f"{BLUE}xuni:{xuni_blocks_count}{RESET} "
            
            if super_blocks_count == 0 and normal_blocks_count == 0 and xuni_blocks_count == 0:
                pbar.set_postfix({"Details": f"No blocks were mined."}, refresh=True)
            else:
                pbar.set_postfix({"Details": f"{superblock}{block}{xuni}"}, refresh=True)

            time.sleep(0.8)  # Check every 1 seconds


if __name__ == "__main__":
    stored_targets = ['XEN11', 'XUNI']
    print(f"Mining with: {account} in GPU mode, GPU Count: {gpu_count}")

    #Start difficulty monitoring thread
    difficulty_thread = threading.Thread(target=update_memory_cost_periodically)
    difficulty_thread.daemon = True  # This makes the thread exit when the main program exits
    difficulty_thread.start()

    miner_thread = threading.Thread(target=monitor_miner_process)
    miner_thread.daemon = True
    miner_thread.start()

    submit_thread = threading.Thread(target=monitor_blocks_directory)
    submit_thread.daemon = True  # This makes the thread exit when the main program exits
    submit_thread.start()
    
    try:
        while True:  # Loop forever
            time.sleep(10)  # Sleep for 10 seconds
    except KeyboardInterrupt:
        print("Main thread is finished")