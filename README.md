## Minimal CA REST service. 

For IoT devices like the *Arctic Tracker* or *Polaric Server* instances to be run on mobile LANs and accessed by a web-application or smartphone app. 

A device like the Arctic Tracker generates its own certificate. Possibly using the DNS extension to add a *.local* (mDNS) name. By default the certificate is self-signed, but then clients using a web-browser to access devices, must (manually) add an exception to the browser's security policy. In addition, this method does not necessarily work with a smartphone app. 

The solution is that the device generate a CSR and send it to a REST-API on a CA-server to have it signed. This process *should* require some authentication to verify that the device requesting the certificate is legitimate. The CA certificate (used for signing) may be installed in the browser or the smartphone app so they can verify certificates from the devices. 

It is still a bit work-in-progress. 

