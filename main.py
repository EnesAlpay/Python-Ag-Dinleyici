import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff
import threading

def packet_callback(packet):
    output_text.insert(tk.END, f"{packet.summary()}\n")
    output_text.yview(tk.END)  

def start_capture():

    sniff(prn=packet_callback, iface="eth0")

def start_sniffing_thread():

    threading.Thread(target=start_capture, daemon=True).start()


root = tk.Tk()
root.title("Ağ Trafiği Yakalama Aracı")


output_text = scrolledtext.ScrolledText(root, width=80, height=20)
output_text.pack()


start_button = tk.Button(root, text="Başlat", command=start_sniffing_thread)
start_button.pack()

root.mainloop()
