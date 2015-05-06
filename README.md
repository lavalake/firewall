# firewall
program the OpenFlow controller POX and use it to  implement two applications: firewall and flowspace slice

To run this application,
1. Copy the controller.py, mininetSlice.py module and two firewall policies files to the ~/pox directory on your VM
2. Run Pox controller:
	$ sudo ~/pox/pox.py controller
3. In another terminal, run the network topology
	$ sudo python ~/pox/mininetSlice.py

To test the application,
1. You can check the firewall application is working by using pingall commands in mininet.
You should see all hosts can connect to each other except the links specified in the firewall-policies.csv

2. You can verify the port number policies by testing the 80 port between h1 and h5 as below:
	mininet > h5 iperf -s -p 80 &
	mininet > h1 iperf -c h5 -p 80
	mininet > h1 iperf -c h5 -p 81
	


