# ScareCrowUnpack
The script was created to statically unpack binary data covered by the ScareCrow packer (https://github.com/optiv/ScareCrow). 

A detailed description and functionality can be found in the presentation https://offzone.moscow/getfile/?bmFtZT1BLkdyaWdvcnlhbl9ELktvbG9za292X0FQVCBhdHRhY2tzIG9uIFJ1c3NpYW4gY29tcGFuaWVzIGluIEgxIDIwMjItIGhpZ2hsaWdodHMucGRmJklEPTI0MDg=

Algorithm of the script:
1) loads the file as a PE image (unfortunately, because of the large size of the binary files, it takes quite a long time =();
2) searches for the start of the function responsible for decryption;
3) searches for the end of this function;
4) disassembles the binary data, parses the assembly instructions and their arguments, gets the offsets at which the encrypted load fragments are stored;
5) also takes the encryption key and initialization vector for the AES-CBC from the disassembled listing;
6) forms a coded and encrypted payload from fragments;
7) decodes, decrypts the data, and then performs the unhexlify procedure.

To get the payload, run the script with the --f parameter, passing it the path to the file. The output file will be created in the same directory labeled "_payload_decr.bin"
