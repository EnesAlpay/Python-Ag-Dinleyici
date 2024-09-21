import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff
import threading

def packet_callback(packet):
    # Paket bilgilerini metin kutusuna ekle
    output_text.insert(tk.END, f"{packet.summary()}\n")
    output_text.yview(tk.END)  # En son eklenen metne kaydır

def start_capture():
    # Ağ trafiğini yakalamak için scapy kullan
    sniff(prn=packet_callback, iface="eth0")  # 'eth0' arayüzünü kullan

def start_sniffing_thread():
    # Yeni bir iş parçacığı başlat
    threading.Thread(target=start_capture, daemon=True).start()

# GUI oluşturma
root = tk.Tk()
root.title("Ağ Trafiği Yakalama Aracı")

# Metin kutusu oluştur
output_text = scrolledtext.ScrolledText(root, width=80, height=20)
output_text.pack()

# Başlat butonu
start_button = tk.Button(root, text="Başlat", command=start_sniffing_thread)
start_button.pack()

root.mainloop()
