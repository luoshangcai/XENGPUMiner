sudo apt install python3-pip
sudo apt install vim
sudo apt update || apt update
sudo apt install -y build-essential ocl-icd-opencl-dev cmake gcc g++ python3-pip htop nano psmisc tmux || apt install -y build-essential ocl-icd-opencl-dev cmake gcc g++ python3-pip htop nano psmisc tmux
chmod +x build.sh
./build.sh -cuda_arch sm_86
pip install -U -r requirements.txt
python3 app.py
