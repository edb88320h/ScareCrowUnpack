# ScareCrowUnpack
<h2>Overwiew</h2>
The script was created to statically unpack binary data covered by the ScareCrow packer (https://github.com/optiv/ScareCrow). 

A detailed description and functionality can be found in the presentation https://offzone.moscow/getfile/?bmFtZT1BLkdyaWdvcnlhbl9ELktvbG9za292X0FQVCBhdHRhY2tzIG9uIFJ1c3NpYW4gY29tcGFuaWVzIGluIEgxIDIwMjItIGhpZ2hsaWdodHMucGRmJklEPTI0MDg=

<h2>Algorithm of the script</h2>
<ol>
<li>Loads the file as a PE image (unfortunately, because of the large size of the binary files, it takes quite a long time =();</li>
<li>Searches for the start of the function responsible for decryption;</li>
  
<img src="/images/start.png" alt="Start of the function"/>
<li>Searches for the end of this function;</li>
<img src="/images/end.png" alt="End of the function"/>
<li>Disassembles the binary data, parses the assembly instructions and their arguments, gets the offsets at which the encrypted load fragments are stored;</li>
<li>Also takes the encryption key and initialization vector for the AES-CBC from the disassembled listing;</li>
<li>Forms an encoded and encrypted payload from fragments;</li>
<li>Decodes, decrypts the data, and then performs the unhexlify procedure.</li>
</ol>

<h2>How to use</h2>
To get the payload, run the script with the --f parameter, passing it the path to the file. The output file will be created in the same directory labeled "_payload_decr.bin"

<p>
<img src="/images/example.gif" alt="Example of using"/>
</p>
