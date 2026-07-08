sudo ip netns del client 2>/dev/null || true
sudo ip netns del fluxguard 2>/dev/null || true
sudo ip netns del backend 2>/dev/null || true
sudo ip netns add client
sudo ip netns add fluxguard
sudo ip netns add backend
sudo ip link add veth-client type veth peer name veth-fg-in
sudo ip link add veth-fg-out type veth peer name veth-backend
sudo ip link set veth-client netns client
sudo ip link set veth-fg-in netns fluxguard
sudo ip link set veth-fg-out netns fluxguard
sudo ip link set veth-backend netns backend
sudo ip netns exec client ip addr add 10.0.1.1/24 dev veth-client
sudo ip netns exec fluxguard ip addr add 10.0.1.2/24 dev veth-fg-in
sudo ip netns exec fluxguard ip addr add 10.0.2.1/24 dev veth-fg-out
sudo ip netns exec backend ip addr add 10.0.2.2/24 dev veth-backend
sudo ip netns exec client ip link set lo up
sudo ip netns exec client ip link set veth-client up
sudo ip netns exec fluxguard ip link set lo up
sudo ip netns exec fluxguard ip link set veth-fg-in up
sudo ip netns exec fluxguard ip link set veth-fg-out up
sudo ip netns exec backend ip link set lo up
sudo ip netns exec backend ip link set veth-backend up
sudo ip netns exec client ip route add default via 10.0.1.2
sudo ip netns exec backend ip route add default via 10.0.2.1
sudo ip netns exec fluxguard sysctl -w net.ipv4.ip_forward=1
