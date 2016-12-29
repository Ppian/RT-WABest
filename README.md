# RT-WABest
A Novel End-to-end Bandwidth Estimation Tool in IEEE 802.11 wireless network
##How to Compile
`gcc RTWABest.c -o RTWABest.c -pthread`
##How to use
```
RTWABest -c src_ip -h dest_ip
  [-s packet_size_bytes]
  [-n num_packet_pair]
  [-m train_length]
  [-r packet_train_rate]
```

**Note:**

1. Only support GNU/Linux
2. Run this program with root privilege. (for the sake of using raw socket) 
