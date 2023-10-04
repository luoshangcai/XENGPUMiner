import math, time, json, requests, time, hashlib, string, threading, re, configparser, os, re, psutil
from passlib.hash import argon2
from random import choice, randrange
from datetime import datetime

import pynvml
import argparse
import configparser

STORED_TARGETS = ['XEN11', 'XUNI']

# Set dev account address
DEV_FEE_ACCOUNT = "0x1A2b791c7c8634eD444DAf5109abaeD84A888888"

# Load the configuration file
CONFIG = configparser.ConfigParser()
CONFIG_PATH = 'config.conf'

if os.path.exists(CONFIG_PATH):
    CONFIG.read(CONFIG_PATH)
else:
    raise FileNotFoundError(f"The configuration file {CONFIG_PATH} was not found.")

# Ensure that the required settings are present
REQ_SETTINGS = ['difficulty', 'memory_cost', 'cores', 'account', 'server_url']
if not all(key in CONFIG['Settings'] for key in REQ_SETTINGS):
    missing_keys = [key for key in REQ_SETTINGS if key not in CONFIG['Settings']]
    raise KeyError(f"Missing required settings: {', '.join(missing_keys)}")

# Set account address
ACCOUNT = CONFIG['Settings']['account']

# Access other settings
DIFFICULTY = int(CONFIG['Settings']['difficulty'])
MEMORY_COST = int(CONFIG['Settings']['memory_cost'])
CORES = int(CONFIG['Settings']['cores'])
SERVER_URL = CONFIG['Settings']['server_url']

UPDATED_MEMORY_COST = 10000 # just initialize it

# Gpu info
pynvml.nvmlInit()
GPU_COUNT = pynvml.nvmlDeviceGetCount()
GPU_HANDLES = []
GPU_STATS = []
HASHRATE_SUM = 0
for i in range(GPU_COUNT):
    GPU_HANDLES.append(pynvml.nvmlDeviceGetHandleByIndex(i))
    GPU_STATS.append({
        'mem': 0,
        'memused': 0,
        'temperature': 0,
        'hashrate': 0
    })

# Mining Tasks
TASK_LIST = []

# Logs and stats
NORMAL_BLKCNT = 0
SUPER_BLKCNT = 0
XUNI_BLKCNT = 0
MINED_BLOCKS = []
LOGS = []

def add_task(account_address, blocks_to_mine):
    global TASK_LIST
    if re.match("^0x[0-9a-fA-F]{40}$", account_address) and float(blocks_to_mine) > 0:
        TASK_LIST.append([account_address, int(blocks_to_mine)])
    else:
        raise KeyError(f"{account_address} is not a vaild ethereum address")


def log_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


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
    global MEMORY_COST
    global UPDATED_MEMORY_COST
    while True:
        UPDATED_MEMORY_COST = fetch_difficulty_from_server()
        if UPDATED_MEMORY_COST != MEMORY_COST:
            write_difficulty_to_file(UPDATED_MEMORY_COST)
            MEMORY_COST = UPDATED_MEMORY_COST
        time.sleep(30)  # Fetch every # seconds


# Function to get difficulty level from the server
def fetch_difficulty_from_server():
    global MEMORY_COST
    global LOGS
    try:
        response = requests.get(f'{SERVER_URL}/difficulty')
        response_data = response.json()
        return str(response_data['difficulty'])
    except Exception as e:
        LOGS.append(['Error', log_time(), f"An error occurred while fetching difficulty: {e}"])
        return MEMORY_COST  # Return last value if fetching fails
    
    
def execCmd(cmd):
    h = os.popen(cmd)
    r = h.read()
    h.close()
    return r


def get_pid_by_name(pname):
    pids = psutil.process_iter()
    res = []
    for pid in pids:
        if (pid.name() == pname):
            res.append(pid.pid)
    return res


def submit_pow(account_address, key, hash_to_verify):
    global LOGS
    # Download last block record
    try:
        # Attempt to download the last block record
        response = requests.get(f"{SERVER_URL}:4445/getblocks/lastblock", timeout=10)  # Adding a timeout of 10 seconds
    except requests.exceptions.RequestException as e:
        # Handle any exceptions that occur during the request
        LOGS.append(['Error', log_time(), f"An error occurred while fetching blocks: {e}"])
        return None  # Optionally return an error value or re-raise the exception

    if response.status_code != 200:
        # Handle unexpected HTTP status codes
        LOGS.append(['Error', log_time(), f"Unexpected status code {response.status_code}: {response.text}"])
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
                LOGS.append(['Error', log_time(), f'Skipping record due to None value(s): record_key: {record_key}, record_hash_to_verify: {record_hash_to_verify}'])
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
            pow_response = requests.post(f'{SERVER_URL}:4446/send_pow', json=payload)

            if pow_response.status_code == 200:
                LOGS.append(['Info', log_time() ,f"Proof of Work successful: {pow_response.json().get('message')}"])
            else:
                LOGS.append(['Error', log_time(), f"Proof of Work failed: {pow_response.json().get('message')}"])
                return None

            LOGS.append(['Block', log_time(), f"Block ID: {output_block_id}, Merkle Root: {merkle_root}"])
            return output_block_id
        
    return None


def submit_block(account_address, key):
    global UPDATED_MEMORY_COST  # Make it global so that we can update it
    global LOGS
    global MINED_BLOCKS
    global NORMAL_BLKCNT
    global XUNI_BLKCNT
    global SUPER_BLKCNT

    argon2_hasher = argon2.using(time_cost=DIFFICULTY, salt=b"XEN10082022XEN", memory_cost=UPDATED_MEMORY_COST, parallelism=CORES, hash_len = 64)
    hashed_data = argon2_hasher.hash(key)
    found_valid_hash = False

    for target in STORED_TARGETS:
        if target in hashed_data[-87:]:
        # Search for the pattern "XUNI" followed by a digit (0-9)
            if re.search("XUNI[0-9]", hashed_data) and is_within_five_minutes_of_hour():
                found_valid_hash = True
                break
            elif target == "XEN11":
                found_valid_hash = True
                capital_count = sum(1 for char in re.sub('[0-9]', '', hashed_data) if char.isupper())
                if capital_count >= 65:
                    LOGS.append(['Block', log_time(), "Super block found."])
                    # Mine Superblocks to Owner, Ignoring the current task address
                    account_address = ACCOUNT
                break
            else:
                found_valid_hash = False
                break

    if found_valid_hash:
        LOGS.append(['Block', log_time(), f"{target} block found."])
        # Prepare the payload
        payload = {
            "hash_to_verify": hashed_data,
            "key": key,
            "account": account_address,
            "attempts": "100000",
            "hashes_per_second": "1000",
            "worker": "aqua-miner"  # Adding worker information to the payload
        }

        max_retries = 5
        retries = 0
        while retries <= max_retries:
            # Make the POST request
            response = requests.post(f'{SERVER_URL}/verify', json=payload)

            if found_valid_hash and response.status_code == 200:
                if target == "XUNI":
                    XUNI_BLKCNT += 1
                    MINED_BLOCKS.append([log_time(), target])
                    
                elif target == "XEN11":
                    capital_count = sum(1 for char in re.sub('[0-9]', '', hashed_data) if char.isupper())
                    #submit proof of work validation of last sealed block
                    block_id = submit_pow(account_address, key, hashed_data)
                    
                    is_superblock = False
                    if capital_count >= 65:
                        is_superblock = True
                    if block_id:
                        if is_superblock:
                            SUPER_BLKCNT += 1
                            MINED_BLOCKS.append([log_time(), "SUPER!"])
                        else:
                            NORMAL_BLKCNT += 1
                            MINED_BLOCKS.append([log_time(), target])

            if response.status_code != 500:  # If status code is not 500, break the loop
                LOGS.append(['Info', log_time(), f"Server Response: {response.json().get('message')}"])
                break
            
            retries += 1
            # print(f"Retrying... ({retries}/{max_retries})")
            time.sleep(3)  # You can adjust the sleep time
            # Print the server's response
            if retries > max_retries:
                LOGS.append(['Error', log_time(), "An error occurred while connecting server."])

    return key, target, hashed_data


def monitor_blocks_directory():
    global TASK_LIST
    while True:
        XENDIR = f"gpu_found_blocks_tmp/"
        mining_account = ACCOUNT

        while len(TASK_LIST) and TASK_LIST[0][1] <= 0:
            del TASK_LIST[0]
        if len(TASK_LIST):
            mining_account = TASK_LIST[0][0]

        if not os.path.exists(XENDIR):
            os.makedirs(XENDIR)
        for filename in os.listdir(XENDIR):
            filepath = os.path.join(XENDIR, filename)
            with open(filepath, 'r') as f:
                data = f.read()
            # submit block using current mining account
            k, target, hashed = submit_block(mining_account, data)
            os.remove(filepath)
            if target == 'XEN11' and len(TASK_LIST):
                TASK_LIST[0][1] -= 1

        time.sleep(0.8)  # Check every 1 seconds


def monitor_task_files():
    global LOGS
    while True:
        TASKFILE = f"task.in"
        if not os.path.exists(TASKFILE):
            os.system(f"touch {TASKFILE}")
        else:
            with open(TASKFILE, 'r') as f:
                content = f.read()
            if content:
                tasks = content.split('\n')
                for task in tasks:
                    props = task.split(' ')
                    if len(props) == 2: 
                        try:
                            add_task(props[0], props[1]) 
                        except Exception as e:
                            LOGS.append(['Error', log_time(), f"An error occured while adding tasks: {e}"])
                os.system(f"cat /dev/null > {TASKFILE}")
            
        time.sleep(10)


def monitor_miner_process():
    global GPU_STATS
    global HASHRATE_SUM
    global LOGS
    # Check the miner process periodically   
    while True:     
        miner_list = get_pid_by_name('xen')
        if len(miner_list) > 0:
            # check all gpu mem
            memtotal = 0
            memused = 0
            memused_pct = 0
            HASHRATE_SUM = 0
            for i in range(GPU_COUNT):
                gpu = GPU_HANDLES[i]
                meminfo = pynvml.nvmlDeviceGetMemoryInfo(gpu)
                GPU_STATS[i]["mem"] = int(meminfo.total/1024**3)
                GPU_STATS[i]["memused"] = round(meminfo.used/1024**3, 3)
                GPU_STATS[i]["memusedpct"] = round(GPU_STATS[i]["memused"] / GPU_STATS[i]["mem"] * 100, 1)
                memtotal += GPU_STATS[i]["mem"] 
                memused += GPU_STATS[i]["memused"]
                # Check miner log
                log_file = f"miner_stat_{i}.out"
                logs = execCmd(f"tail -1000 {log_file}")
                hashes = []
                if logs:
                    logs = logs.split('\n')
                    for log in logs:
                        nums = log.split(' ')
                        if len(nums) == 2:
                            try:
                                t = int(nums[0])
                                hash_total = int(nums[1])
                                hashes.append([t, hash_total])
                            except Exception as e:
                                pass
                if hashes:
                    GPU_STATS[i]["hashtotal"] = hashes[-1][1]
                    hash_rate = (hashes[-1][1] - hashes[0][1]) / (hashes[-1][0] - hashes[0][0]) * 1000
                    GPU_STATS[i]["hashrate"] = round(hash_rate, 2)
                    HASHRATE_SUM += GPU_STATS[i]["hashrate"]
                    
            if memtotal > 0:
                memused_pct = memused / memtotal
            if memused_pct > 0.996:
                LOGS.append(['Error', log_time(), "Memory used exceed. Restarting..."])
                for pid in miner_list:
                    os.system(f"kill {pid}")
            time.sleep(1)
            miner_list = get_pid_by_name('xen')

        if len(miner_list) == 0:
            # batch_size = int(memtotal * 0.95 * 1024 ** 2 / int(updated_memory_cost))
            print(f"\nNo miners are running. Starting...")
            for i in range(GPU_COUNT):
                os.system(f"nohup ./xen -d {i} > miner_stat_{i}.out &")
                # print(f"Miner is running on GPU {i}")

        time.sleep(10)


if __name__ == "__main__":
    RUNNING_START = datetime.now().timestamp()
    
    def uptime():
        seconds = datetime.now().timestamp() - RUNNING_START
        sec = math.floor(seconds % 60)
        minute = int((seconds // 60) % 60)
        hour = int((seconds // 3600) % 24)
        day = int(seconds // 86400)
        if sec < 10:
            sec = f"0{sec}"
        if minute < 10:
            minute = f"0{minute}"
        if hour < 10:
            hour = f"0{hour}"
        res = f"{hour}:{minute}:{sec}"
        if day > 0:
            res = f"{day}:" + res
        return res
    
    miner_list = get_pid_by_name('xen')
    if len(miner_list) > 0:
        print(f"Miners are already running. Exiting...")
    
    else:
        # Start difficulty monitoring thread
        difficulty_thread = threading.Thread(target=update_memory_cost_periodically)
        difficulty_thread.daemon = True  # This makes the thread exit when the main program exits
        difficulty_thread.start()

        miner_thread = threading.Thread(target=monitor_miner_process)
        miner_thread.daemon = True
        miner_thread.start()

        task_thread = threading.Thread(target=monitor_task_files)
        task_thread.daemon = True
        task_thread.start()

        submit_thread = threading.Thread(target=monitor_blocks_directory)
        submit_thread.daemon = True  # This makes the thread exit when the main program exits
        submit_thread.start()
        
        # TUI Settings
        from rich import print, box
        from rich.console import group, Group
        from rich.padding import Padding
        from rich.layout import Layout
        from rich.panel import Panel
        from rich.columns import Columns
        from rich.table import Table
        from rich.text import Text
        from rich.live import Live

        from pyfiglet import Figlet

        fig = Figlet(font='roman', width=40)

        banner_ascii = [
"`8.`8888.      ,8' 8 8888888888   b.             8          ,8.       ,8.           8 8888 b.             8 8 8888888888   8 888888888o.  ",
" `8.`8888.    ,8'  8 8888         888o.          8         ,888.     ,888.          8 8888 888o.          8 8 8888         8 8888    `88. ",
"  `8.`8888.  ,8'   8 8888         Y88888o.       8        .`8888.   .`8888.         8 8888 Y88888o.       8 8 8888         8 8888     `88 ",
"   `8.`8888.,8'    8 8888         .`Y888888o.    8       ,8.`8888. ,8.`8888.        8 8888 .`Y888888o.    8 8 8888         8 8888     ,88 ",
"    `8.`88888'     8 888888888888 8o. `Y888888o. 8      ,8'8.`8888,8^8.`8888.       8 8888 8o. `Y888888o. 8 8 888888888888 8 8888.   ,88'",
"    .88.`8888.     8 8888         8`Y8o. `Y88888o8     ,8' `8.`8888' `8.`8888.      8 8888 8`Y8o. `Y88888o8 8 8888         8 888888888P'  ",
"    8'`8.`8888.    8 8888         8   `Y8o. `Y8888    ,8'   `8.`88'   `8.`8888.     8 8888 8   `Y8o. `Y8888 8 8888         8 8888`8b  ..",
"   8'  `8.`8888.   8 8888         8      `Y8o. `Y8   ,8'     `8.`'     `8.`8888.    8 8888 8      `Y8o. `Y8 8 8888         8 8888 `8b. .",
"  8'    `8.`8888.  8 8888         8         `Y8o.`  ,8'       `8        `8.`8888.   8 8888 8         `Y8o.` 8 8888         8 8888   `8b.  ",
"  8'      `8.`8888. 8 888888888888 8            `Yo ,8'         `         `8.`8888.  8 8888 8            `Yo 8 888888888888 8 8888     `88",
            " "
        ]
        # Define Layout
        layout = Layout()

        layout.split_column(
            Layout(name="banner"),
            Layout(name="info"),
            Layout(name="monitor"),
            Layout(name="logs")
        )

        layout["info"].split_row(
            Layout(name="general"),
            Layout(name="blocks")
        )
        layout["general"].ratio = 1
        layout["blocks"].ratio = 2

        layout["monitor"].split_row(
            Layout(name="gpu"),
            Layout(name="task"),
            Layout(name="blocklist")
        )
        layout["gpu"].ratio = 3
        layout["task"].ratio = 2
        layout["blocklist"].ratio = 4

        layout["banner"].size = 15
        layout["info"].size = 10
        layout["logs"].size = 6

        # Define Components
        def update_layout_general():
            blockcnt = NORMAL_BLKCNT + SUPER_BLKCNT
            blockrate = ((datetime.now().timestamp() - RUNNING_START) / 60) / (blockcnt if blockcnt > 0 else 1)
            
            General = Table(expand=True, box=box.SIMPLE, show_header=False)
            General.add_column("Item")
            General.add_column("Value")
            for i in range(2):
                General.add_row()
            General.add_row("Up Time", uptime())
            General.add_row("Difficulty", str(UPDATED_MEMORY_COST))
            General.add_row("Hash Rate", str(round(HASHRATE_SUM, 2)))
            General.add_row("min / block", str(round(blockrate, 2)))
            return General

        
        def update_layout_gpu():
            GPU_Stats = Table(expand=True, box=box.SIMPLE)
            GPU_Stats.add_column("GPU #", style="cyan")
            GPU_Stats.add_column("Mem")
            GPU_Stats.add_column("Mem%")
            GPU_Stats.add_column("Hash/s")
            GPU_Stats.add_column("Total")
            for i in range(GPU_COUNT):
                hash_total = GPU_STATS[i].get('hashtotal', 0)
                if hash_total > 1000000:
                    hash_total = f"{round(hash_total/1000000, 3)} M"
                elif hash_total > 1000:
                    hash_total = f"{round(hash_total/1000, 3)} K"
                GPU_Stats.add_row(
                    Text(f"GPU {i}", style="cyan"), 
                    f"{round(GPU_STATS[i].get('memused', 0), 1)}/{round(GPU_STATS[i].get('mem', 0), 0)} GiB", 
                    f"{GPU_STATS[i].get('memusedpct', 0)}%", 
                    f"{round(GPU_STATS[i].get('hashrate', 0), 1)}",
                    f"{hash_total}", 
                )
            return GPU_Stats


        def update_layout_task():
            Tasks = Table(expand=True, box=box.SIMPLE, show_header=False)
            for task in TASK_LIST:
                addr = f"{task[0][:6]}...{task[0][-4:]}"
                Tasks.add_row(addr, str(task[1]))
            if not len(TASK_LIST):
                Tasks.add_row(f"{ACCOUNT[:6]}...{ACCOUNT[-4:]}", "INF")
            return Tasks


        def update_layout_blocklist():
            blocks = []
            if len(MINED_BLOCKS):
                for block in reversed(MINED_BLOCKS[-40:]):
                    t = Text(block[0].split(" ")[-1])
                    style = "green"
                    if block[1] == "XUNI":
                        style = "magenta"
                    if block[1] == "SUPER!":
                        style = "red"
                    t.append(f" {block[1]}", style=style)
                    blocks.append(t)
                
            BlockList = Columns(blocks, expand=True, equal=True)
            return Padding(BlockList, 1)


        def update_layout_blocks(sup, normal, xuni):
            Blocks = Table(expand=True, box=box.SIMPLE, show_header=False)
            Blocks.add_column('Super Block', style="red")
            Blocks.add_column('Normal Block', style="green")
            Blocks.add_column('XUNI Block', style="magenta")
            Blocks.add_row(
                Text(fig.renderText(str(sup))),
                Text(fig.renderText(str(normal))),
                Text(fig.renderText(str(xuni)))
            )
            Blocks.add_row('Super Blocks', 'Normal Blocks', 'XUNI Blocks')
            return Blocks


        def update_layout_logs():
            Logs = Table(expand=True, box=box.SIMPLE, show_header=False)
            Logs.add_column("Time", ratio=2)
            Logs.add_column("Type", ratio=1)
            Logs.add_column("Message", ratio=6)
            for log in LOGS[-5:]:
                style = "green"
                if log[0] == 'Error':
                    style = "red"
                if log[0] == 'Block':
                    style = "cyan"
                Logs.add_row(
                    log[1],
                    Text(log[0], style=style),
                    log[2]
                )
            return Logs
        
        @group()
        def print_banner():
            for line in banner_ascii:
                yield Text(line, style="cyan bold", justify="center")


        # Fill Layout
        layout["banner"].update(
            Group(
                print_banner(),
                Text("XENBlocks GPU Miner", justify="center"),
                Text("Ver 0.0.1", justify="center")
            )
        )
        
        def update_layouts():
            layout["general"].update(
                update_layout_general()
            )
            layout["blocks"].update(
                update_layout_blocks(SUPER_BLKCNT, NORMAL_BLKCNT, XUNI_BLKCNT)
            )
            layout["gpu"].update(
                Panel(update_layout_gpu(), title="GPU Stats")
            )
            layout["task"].update(
                Panel(update_layout_task(), title="Tasks")
            )
            layout["blocklist"].update(
                Panel(update_layout_blocklist(), title="Blocks")
            )
            layout["logs"].update(
                update_layout_logs()
            )
        update_layouts()
        
        with Live(layout, refresh_per_second = 1) as live:
            while True:
                update_layouts()
                time.sleep(0.9)
    