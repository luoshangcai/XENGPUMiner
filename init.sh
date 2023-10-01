sudo apt update || apt update
sudo apt install -y build-essential ocl-icd-opencl-dev cmake gcc g++ python3-pip htop nano psmisc || apt install -y build-essential ocl-icd-opencl-dev cmake gcc g++ python3-pip htop nano psmisc
chmod +x build.sh
./build.sh -cuda_arch sm_86
pip install -U -r requirements.txt
