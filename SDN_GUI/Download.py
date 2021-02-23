import Tkinter as tk
import numpy as np
import math
import time
from scapy.all import *
import json
import ast
import Upload as up

#=========================================================================================================================
# Upload Process 
#=========================================================================================================================

class Download_Window:

    # Define Layout and Variables
    def __init__(self, master):
        self.vars1=[]
        self.stop1=False
        self.BUFFER_SIZE = 1400
        self.dest_ip_download = "10.0.0.200"

        self.pkt_array = []
        self.g_counter = 0
        self.size = 0
        self.rx_fname = ''

        self.master = master
        self.master.title("Download")
        self.can = tk.Canvas(self.master, width=600, height=400)
        self.can.pack()
        self.label1=tk.Label(self.master, text="Please Load Available Files:")
        self.label1.place(relx=0.2,rely=0.2)

        self.tablebutton = tk.Button(self.master,text="Load Table",fg="blue",bg="white",command=self.download_req)
        self.tablebutton.place(relx= 0.6, rely=0.2)
        self.downloadbutton = tk.Button(self.master, state='disabled', text="Download", fg="blue", bg="white",command=self.download_file1)
        self.downloadbutton.place(relx=0.2, rely=0.85)
        self.exitbutton = tk.Button(self.master,text="Close",fg="blue",bg="white", command=self.master.destroy)
        self.exitbutton.place(relx=0.375, rely=0.85)
        
    #=========================================================================================================================
    # Functions
    #=========================================================================================================================
    
    # Send download request, triggered by clicking on "Load Table"
    def download_req(self):
        send(IP(dst="10.0.0.200")/ICMP()/Raw(load="Download_Request;"))
        sniff(filter="icmp",count=0, prn=self.handler_download_controller,stop_filter=self.stop_download1)
    
    # Stopfilter for sniffing process
    def stop_download1(self,packet):
        if self.stop1==True:
            self.stop1 = False
            return True
        else:
            return False
    
    # Represent database in the GUI
    def show_list(self,data_list):
        print("Show List")
        print(data_list)
        self.data_list = data_list
        
        #Create Checkbar
        l=1
        for k in range(len(data_list)):
            var = tk.IntVar()
            data_list[k][0] = data_list[k][0][1:-1]
            print("data_list[k]",data_list[k][0])
            self.bar = tk.Checkbutton(self.master, text=data_list[k][0],variable =var)
            self.vars1.append(var)
            self.bar.place(relx=0.2,rely=(0.05*l)+0.3)
            l=l+1

        self.downloadbutton.configure(state="normal")
        return
    
    # Change GUI, when downloading was successfull
    def change_gui(self):
        try:
            del self.label4
        except:
            pass
        
        self.label2=tk.Label(self.master, text="Download Successfull!            ",fg="green")
        self.label2.place(relx=0.2,rely=0.75)
        self.downloadbutton.configure(fg="green")
        
    # Handling ACK from initial download request: 
    def handler_download_controller(self,packet):
        data_download = []
        a = packet
        rx_packet = vars(a[0])

        if ICMP in rx_packet['payload']:
            if Raw in rx_packet["payload"]["ICMP"]:
                data = rx_packet["payload"].load
                final_data = data.split(";")
                print("final_data",final_data)

                if final_data[0] == 'ACK':
                    downloaded = final_data[1]
                    downloaded = downloaded[:-1]
                    downloaded = downloaded[1:]
                    data_download.append(final_data[1])

                    res = [e.strip('[]') for e in downloaded.split('], [')]
                    new_res_list = []
                    for m in range(0,len(res)):
                        new_res = res[m].split(',')
                        new_res_list.append(new_res)

                    print("List of Files available in the network")
                    for n in range(0,len(new_res_list)):
                        print(str(n+1) + ". " + new_res_list[n][0])

                    #Print List of Available Items
                    self.show_list(new_res_list)
                    self.stop1=True
                    return

                elif final_data[0]=="No files present in network to download":
                    print("Nothing is stored")
                    self.label2=tk.Label(self.master, text="Nothing is stored",fg="red")
                    self.label2.place(relx=0.2,rely=0.4)
                    self.stop1=True
                    return

    # Called when a packet which matches the filter is received, it stores all these packtes in a buffer and re-arranges when all packets are received completely
    def funcc(self,packet):
        a = packet
        f = open("Received_Unsorted_" + self.rx_fname, "ab")
        packet.show()
        print(a,type(a))
        print("\n",a[0],type(a[0]))
        print("Step2")
        rx_packet = vars(a[0])
        print(rx_packet, type(rx_packet))
        if UDP in rx_packet['payload']:
            if Raw in rx_packet["payload"]["UDP"]:
                data = rx_packet["payload"].load
                print(data,type(data))
  
		if data.find("MyPack") != -1: 
		    temp = data.split("$slt$")
	            self.pkt_array.append([int(temp[1]), temp[2]])
                    self.g_counter += 1
                if data != "END_OF_FILE":
                    f.write(data)
                else:
                    f.close()
                    print("Donwload Complete")
                    return True
        f.close()
        if self.g_counter == self.size: # Size of packets in terms of packets
            self.handle_pkt()
    
    # Create Download File Request
    def download_file1(self):
        checkbar_files = list(map((lambda var: var.get()),self.vars1))
        if int(sum(checkbar_files))>1:
            self.label4=tk.Label(self.master, text="Please select only one file!",fg="red")
            self.label4.place(relx=0.2,rely=0.75)
            return

        counter = 0
        for logic in checkbar_files:
            if logic == 0:
                pass
            else:
                download_file_req = "Download_File_Request" + ":" + str(counter + 1)
                send(IP(dst="10.0.0.220")/ICMP()/Raw(download_file_req))
                print("data_list",self.data_list,type(self.data_list))
                ip = self.data_list[counter][2]
                ip = ip[ip.find("('") + len("('"):ip.find("')")]
                self.size = int(self.data_list[counter][1])
                self.rx_fname = self.data_list[counter][0]
                print("Size of file to download",self.size)
                self.download_file2(ip,self.data_list[counter][3])

            counter=counter+1


    # Sniff for file to download
    def download_file2(self,dst_ip,dst_port):

        print("Start Download...")
        f = open("Received_Unsorted_" + self.rx_fname, "wb")
        print("Step1")
        filter_string = "udp and host " + dst_ip + " and port " + dst_port
        f.close()
        print("filter string",filter_string)
        data = ''
        print("Step1")
        dont_stop = True
        print("Step1")
        count = 0
        while dont_stop:
            print("Step2")
            sniff(filter=filter_string, count=0, prn=self.funcc, stop_filter=self.stop_download1)
            print("Step2")
            self.change_gui()
            dont_stop = False


    # Sort the received file 
    def handle_pkt(self):
        f = open("Received_Sorted_" + self.rx_fname, "wb")
        print("Len of packet array:", len(self.pkt_array))
        print("g_counter", self.g_counter)
    
        sorted_list = [0]*(len(self.pkt_array))
        for i in self.pkt_array:
	    print("seq's", i[0])
        for i in range(self.g_counter):
	    print(self.pkt_array[i][0])
            print("self.pkt_array[i][1]", self.pkt_array[i][1])
	    print("self.pkt_array[i][0] - 1", self.pkt_array[i][0] - 1)
	    sorted_list[self.pkt_array[i][0] - 1] = str(self.pkt_array[i][1])
	    print("type(self.pkt_array[i][1]): ", type(self.pkt_array[i][1]))
        for i in range(len(sorted_list)):
	    print("type(sorted_list[i]):  ", type(sorted_list[i]))
        for i in range(len(sorted_list)):
	    print("i:  ", i)
	    print(sorted_list[i])
	    print("type(sorted_list[i]): ", type(sorted_list[i]))
	    f.write(str(sorted_list[i]))
        f.close()
        print("HANDLE_PACKET")
        self.stop1=True



