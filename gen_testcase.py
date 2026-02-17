# oxagast
# use:
#   tcpdump -w ~/capture.pcap 'port 9000'
#   python3 pcap_gen_testcases.py ~/capture.pcap
# this will create a testcase directory of each destination port filled with files each
# the data section of the packets in the pcap file.  One packet is one file.  TCP header
# info is stripped.

import os
import sys
import argparse

try:
    import scapy.all as scapy
except ImportError:
    import scapy


def write_testcase(data, output_dir, pdir, index):
    if not os.path.exists(output_dir + "/" + pdir):
        os.mkdir(output_dir + "/" + pdir)
    out = open(
        output_dir + "/" + pdir + "/pcap.data_packet." + str(index) + ".dat", "wb"
    )
    out.write(data)


def parse_pcap(pcap_path, srcp, dstp):
    print(
        "Generating testcases based on " + sys.argv[1] + ".  This will take a while..."
    )
    s = 0
    packets = scapy.rdpcap(pcap_path)
    for p in packets:
        if p.haslayer("TCP"):
            raw_d = p["TCP"].payload.original
            sport = p["TCP"].sport
            dport = p["TCP"].dport
            dport_dir = str(dport)
            if (srcp is None or sport == srcp) and (dstp is None or dport == dstp):
                if raw_d is not None and len(raw_d) > 0:
                    print(raw_d)
                    write_testcase(raw_d, args.output, dport_dir, s)
                    s = s + 1
    print("Generated " + str(s) + " testcases.")


parser = argparse.ArgumentParser(
    description="Generate testcases from a .pcap file.", prog="gen_testcases"
)
parser.add_argument("pcap_file", help="The .pcap file to parse.")
parser.add_argument(
    "-o",
    "--output",
    help="The output directory for the testcases.",
    default="testcases",
)
parser.add_argument(
    "-s",
    "--source-port",
    help="Only generate testcases for this destination port.",
    type=int,
)
parser.add_argument(
    "-d",
    "--dest-port",
    help="Only generate testcases for this destination port.",
    type=int,
)
args = parser.parse_args()
if not os.path.exists(args.pcap_file):
    print("The .pcap file does not exist.")
    sys.exit(1)
if not os.path.exists(args.output):
    os.mkdir(args.output)
parse_pcap(args.pcap_file, args.source_port, args.dest_port)
print("Done.")
sys.exit(0)
