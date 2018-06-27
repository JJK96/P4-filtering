# Filtering DDoS traffic using the P4 programming language

This repository contains the results used in writing the attached paper.

The content is as follows:

```
ftp-big                            # The big dataset as described in the paper
├── after_training.png             # Result of the training phase
├── test-pkt1                      # Test with packet threshold=1 and Days threshold = 1
│   └── rates.txt                  # Rates as described in the paper
├── test-pkt5                      # Test with packet threshold=5 and Days threshold = 1
│   └── rates.txt                  # Rates as described in the paper 
└── test-pkt5-differences          # Test with packet threshold=5 and Days threshold = 1 including differences between python and P4
    ├── difference_num_packets.txt # Difference in number of packets
    ├── not_seen.txt               # IP addresses that were seen by P4 but not by python
    └── rates.txt                  # Rates as described in the paper 
ftp-small                          # The small dataset as described in the paper
├── after_training.png             # Result of the training phase
└── test                           # Test with packet threshold=5 and Days threshold = 1
    ├── daysdiff.txt               # Difference in number of days between Python and P4
    └── rates.txt                  # Rates as described in the paper 
program.p4                         # The P4 implemenation of History-Based IP Filtering (HIF)
paper.pdf                          # The paper
```
