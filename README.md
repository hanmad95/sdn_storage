# sdn_storage
Software Defined Network Storage Project

How to use the provided System:


1.Open Mininet and run one of the provided Topologies (example: MyTopo.py in GUI_UDP folder)
sudo mn --custom GUI_UDP/MyTopo.py --topo mytopo --controller remote --mac --link tc


2.Run the Storage_Controller.py (in GUI_UDP folder) on a seperate Terminal with Ryu-Manager with --observe-links.
ryu-manager --observe-links Storage_Controller.py


3.Open the Xterm for a host (example: h1) execute the GUI with Python 2.7
python ./GUI_UDP/GUI/Storage_GUI.py


4.In the GUI select "Upload File", and then proceed to select a file (maybe one of the images in GUI_UDP/GUI folder) and wait till upload is finished.


5. After uploading, open xterm of another host (or in the xterm of the same host) and start the GUI again and then proceed to download the file by clicking "Download File" button.
After clicking the "Load Table" button, you will see a list of files stored in the network, click the file which you want to download and select "Download". Wait for download to finish.
And check the directory (from where the terminal was started) for the download file named as "Received_Sorted_" + filename.
