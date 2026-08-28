import os
import string

#Detects USB file: pm_install.key
def find_file_usb(target_filename="pm_install.key"):

    for drive in string.ascii_uppercase:
        #finds all the drives on the computer
        path = f"{drive}:\\"

        if not os.path.exists(path):
            continue
        
        #checks for filename in each drive
        try:
            if target_filename in os.listdir(path):
                return os.path.join(path, target_filename), path
        except PermissionError:
            continue

    return None, None
