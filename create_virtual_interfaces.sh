for i in $(seq 0 $1); do
	sudo ip link add eth0$i type dummy;
	sudo ip link set dev eth0$i mtu 65536;
	sudo ip link set eth0$i up;
done

# sudo ip link add eth00 type dummy
# sudo ip link add eth01 type dummy
# sudo ip link add eth02 type dummy
# sudo ip link set dev eth00 mtu 65536
# sudo ip link set dev eth01 mtu 65536
# sudo ip link set dev eth02 mtu 65536
# sudo ip link set eth00 up
# sudo ip link set eth01 up
# sudo ip link set eth02 up
