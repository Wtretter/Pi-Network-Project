ip netns add left-ns
ip netns add right-ns

ip link add name lefty netns left-ns type veth peer name lefty
ip link add name righty netns right-ns type veth peer name righty

ip link set dev lefty up
ip link set dev righty up

ip netns exec left-ns ip link set dev lefty up
ip netns exec right-ns ip link set dev righty up

ip netns exec left-ns ip addr add 10.0.0.1/24 dev lefty
ip netns exec right-ns ip addr add 10.0.1.1/24 dev righty

ip netns exec left-ns ip route add 10.0.1.0/24 dev lefty
ip netns exec right-ns ip route add 10.0.0.0/24 dev righty

ip netns exec left-ns ip addr add fd40:d9ed:3c8e::1/64 dev lefty
ip netns exec left-ns ip route add fd96:da19:e20c::/64 dev lefty

ip netns exec right-ns ip addr add fd96:da19:e20c::1/64 dev righty
ip netns exec right-ns ip route add fd40:d9ed:3c8e::/64 dev righty
