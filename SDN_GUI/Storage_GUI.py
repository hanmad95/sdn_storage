import Tkinter as tk
import os
import sys
import math

#==========================================================================================================================
# Funktionen Import:
#==========================================================================================================================

from Upload import Upload_Window
from Download import Download_Window
from Plot_Topo import print_Topo


#=========================================================================================================================
# Main Menue Class
#=========================================================================================================================


class MainMenue:
    # Initialize variables and create the GUI Main Menue 
    def __init__(self, master):
        print(os.path.dirname(__file__))
        self.current_dir = os.path.dirname(__file__)
        self.background_path = self.current_dir + str(r"/Background.GIF")
        self.master = master
        self.master.title("SDN Storage GUI")
        self.can = tk.Canvas(self.master, width=800, height=500)
        self.can.pack()
        self.bgimage = tk.PhotoImage(file=self.background_path)
        self.bglabel = tk.Label(self.master, image= self.bgimage)
        self.bglabel.place(relwidth=1,relheight=1)
        self.buttonframe = tk.Frame(self.master)
        self.buttonframe.place(relx=0.3,rely=0.3,relwidth=0.4,relheight=0.4)
        self.button1 = tk.Button(self.buttonframe, text ="Upload File",fg="blue", bg="white", command=self.upload_window)
        self.button1.place(relx=0,rely=0,relwidth=1,relheight=0.2)
        self.button2 = tk.Button(self.buttonframe, text ="Download File",fg="blue", bg="white", command=self.download_window)
        self.button2.place(relx=0,rely=0.2,relwidth=1,relheight=0.2)
        self.button3 = tk.Button(self.buttonframe, text ="Plot Topology",fg="blue", bg="white", command=self.plot_topo)
        self.button3.place(relx=0,rely=0.4,relwidth=1,relheight=0.2)        
        
        self.exitbutton = tk.Button(self.buttonframe,text="Exit",fg="blue", bg="white", command=self.master.destroy)
        self.exitbutton.place(relx=0,rely=0.8,relwidth=1,relheight=0.2)

    # Execute Print Toplogy if button is pressed
    def plot_topo(self):
        self.new = print_Topo()        
        self.new.print_req()

    # Execute the Upload Process if button is pressed
    def upload_window(self):
        self.newWindow = tk.Toplevel(self.master)
        w = self.newWindow.winfo_screenwidth()
        self.newWindow.geometry("600x400+%d+%d" %(int(round(w*0.4)),0))
        self.new = Upload_Window(self.newWindow)
        
    # Execute the Download Process if button is pressed 
    def download_window(self):
        self.newWindow = tk.Toplevel(self.master)
        w = self.newWindow.winfo_screenwidth()
        self.newWindow.geometry("600x400+%d+%d" %(int(round(w*0.4)),0))
        self.new = Download_Window(self.newWindow)

#=========================================================================================================================
# Main File Execution
#=========================================================================================================================

def main():
    root = tk.Tk()
    root.geometry("800x500+%d+%d" %(0,0)) 
    app = MainMenue(root)
    root.mainloop()

if __name__ == "__main__":
    main()
