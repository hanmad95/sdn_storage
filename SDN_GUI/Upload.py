import tkFileDialog
import Tkinter as tk
import numpy as np
import os
import socket
import time
from scapy.all import *
import json
import ast

#=========================================================================================================================
# Upload
#=========================================================================================================================

class Upload_Window:
    # Initialize Variables and Layout 
    def __init__(self, master):
        self.BUFFER_SIZE = 1400
        self.stop=False
        self.dest_ip_upload = "10.0.0.250"
        self.master = master
        self.master.title("Upload")
        self.can = tk.Canvas(self.master, width=600, height=400)
        self.can.pack()
        self.label1=tk.Label(self.master, text="Please select a file:")
        self.label1.place(relx=0.2,rely=0.2)
        self.loadbutton = tk.Button(self.master, text="Load File", fg="blue", bg="white",command=self.select_file)
        self.loadbutton.place(relx=0.5, rely=0.2)
        self.uploadbutton = tk.Button(self.master, state='disabled', text="Upload File", fg="blue", bg="white",command=self.upload_req)
        self.uploadbutton.place(relx=0.2, rely=0.85)
        self.exitbutton = tk.Button(self.master,text="Close",fg="blue",bg="white", command=self.master.destroy)
        self.exitbutton.place(relx=0.375, rely=0.85)

    #=========================================================================================================================
    # Functions
    #=========================================================================================================================
    
    # Ask for file to upload
    def select_file(self):
        # Current Path
        current_dir = os.path.dirname(os.path.abspath(__file__))
        # Select File Path
        self.filepath = tkFileDialog.askopenfilename(initialdir=current_dir,title="Select File")
        # Filename
        self.filename =str( os.path.basename(self.filepath))
        # Size of selected file
        self.filesize = os.path.getsize(self.filepath)

        # Show selected File
        self.label2=tk.Label(self.master, text=str("-> ")+str(self.filename), fg="blue")
        self.label2.place(relx=0.2,rely=0.4)
        self.label3=tk.Label(self.master, text=str(self.filesize)+str("  Bytes"),fg="blue")
        self.label3.place(relx=0.5, rely=0.4)

        # Activate Upload Button
        self.uploadbutton.configure(state='normal')

    # Create upload request
    def upload_req(self):
        num_pkts = int(np.ceil(self.filesize / self.BUFFER_SIZE)) + 1
        print("Number of packets sent", num_pkts)
        upload_req_string = "Upload_Request" + ":" + self.filename + ":" + str(num_pkts)
        send(IP(dst="10.0.0.240")/ICMP()/Raw(load=upload_req_string))
        sniff(filter="icmp",count=0, prn=self.handler_controller, stop_filter = self.stop_upload)

    #Stopfilter for sniffing
    def stop_upload(self,packet):
        if self.stop==True:
            return True
        else:
            return False
    
    # Handle incoming ACK from controller
    def handler_controller(self,packet):
        print("Packet is" ,packet )
        a = packet
        rx_packet = vars(a[0])
        print(rx_packet, type(rx_packet))
        if ICMP in rx_packet['payload']:
            if Raw in rx_packet["payload"]["ICMP"]:
                data = rx_packet["payload"].load
                final_data = data.split(";")
                if final_data[0] == 'ACK':
                    print("ACK received")
                    self.upload_file(final_data[1],final_data[2])
                    self.stop = True

                    return

    # Upload the file and change GUI 
    def upload_file(self,dest_ip, dest_port):
        f = open(self.filepath, "rb")
        file_empty = False
        count=0
        while not file_empty:
            bytes_read1 = f.read(self.BUFFER_SIZE)
            print("After read",bytes_read1)
            if bytes_read1 == '':
                file_empty = True
            else:
                count += 1
                bytes_read = "xxxxxxxxxxxx" + "MyPack" + "$slt$" + str(count) + "$slt$" + str(bytes_read1)
                # "xxx..." is added as Scapy was coverting the UDP packet to DNS packet which was leading to the first 12 bytes of the recived packet to be considered as DNS header
                # So, to counter this we add 12 bytes of padding after which the sequence number is added before the raw data
                sendp(Ether(src="00:00:00:00:00:11", dst="00:00:00:00:00:22")/IP(dst=dest_ip)/UDP(dport=int(dest_port))/ Raw(load=bytes_read))
                
        f.close()

        print("Number of packets sent", count)
        print("File Completly Send")
        self.label4=tk.Label(self.master, text="SEND SUCCESFULL",fg="green")
        self.label4.place(relx=0.7, rely=0.4)
        self.uploadbutton.configure(state='disabled')
        self.label3.configure(fg="green")
        self.label2.configure(fg="green")

        return True




