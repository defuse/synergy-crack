In the 'captures' folder, you will find wireshark packet captures of Synergy
communications with CTR, GCM, OFB, and CFB encryption. The crack.rb script is
able to crack CTR, GCM, and OFB, but not CFB.

For example, to crack the CTR capture, run:

$ tcptrace -e captures/capture_ctr_abc
$ ruby crack.rb b2a_contents.dat a2b_contents.dat

If you want to crack your own Synergy's traffic, use this wireshark filter:
    tcp.srcport == 24800 || tcp.dstport == 24800
