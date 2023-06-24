# RAID-Storage-Legends
file storage system over multiple local computers.

instructions:
add mac addresses of all storage computers to allowed_mac_addrs.txt with the following format - aa:bb:cc:dd:ee:ff with a single space between each mac address.
run main_server.py on your designated server computer.
change the ip address and storage path in the settings file that is located on the storage computers to match the server's local ip address.
change server_ip.txt on the client's machiene to match the server's ip address.
run main_client.py for the client's side, and run main_storage.py for each storage computer to connect to server.
