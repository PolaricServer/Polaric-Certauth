Minimal CA REST service. 
For IoT devices like the *Arctic Tracker* or *Polaric Server* instances to be run on mobile LANs.

The device generates its own certificate. Possibly using the DNS extension to add a *.local* (mDNS) name. 
By default the certificate is self-signed, but then clients using a web-browser to access devices, must (manually) 
add an exception to the browser's security policy. In addition, this method does not necessarily work with a smartphone app. 

So, the device can generate a CSR and call the REST-API on a CA-server to sign it. It *should* require authentication. The CA certificate may be installed in the browser or the smartphone app so they can verify certificates from the devices. 

It is still a bit work-in-progress. 

