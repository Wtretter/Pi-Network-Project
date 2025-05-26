import time


watched_file = "./caught-packets.hex"


file_contents = None
while True:
    with open(watched_file, "r") as data_file:
        new_data = data_file.read()
        
    if file_contents != None and new_data != file_contents:
        print("New data recieved")

    file_contents = new_data
            
    time.sleep(.05)