# wirespeed

Measures the real wire speed between two NICs on the same Windows PC.

Traffic between two local IPs never touches the cable, cus Windows delivers it inside the TCP/IP stack, even if you bind to a specific NIC. 

wirespeed goes around the stack. It sends raw ethernet frames out of src NIC via [npcap](https://npcap.com) and counts the received ones that on the dst.

## Build

Needs MSVC and CMake:

    cmake -B build
    cmake --build build --config Release

The exe would be in `build\Release\`.

## Use

Needs [npcap](https://npcap.com) and a cable between the two NICs.

    wirespeed                             # list wired NICs
    wirespeed "Ethernet 2" "Ethernet 3"   # flood src -> dst until ctrl+c
    wirespeed 12 17 9014                  # NICs by index, 9014 byte jumbo frames

Each second it prints the rate arriving on dst and `% of line`; 100% means the cable is saturated (about 984 Mbit/s of 1514-byte frames on 1 GbE). ctrl+c prints frames sent, received and lost.

- Frames default to the largest both NICs allow: 1514 bytes, more with jumbo frames on.
- Run elevated if Npcap is restricted to Administrators (an install option).
- Use a direct cable. Behind a switch that hasn't learned dst's MAC, the flood reaches every port.
- To load both directions at once, run `wirespeed dst src` in another terminal.
