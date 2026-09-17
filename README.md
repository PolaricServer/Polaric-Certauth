## Minimal CA REST service. 

For IoT devices like the *Arctic Tracker* or *Polaric Server* instances to be run on mobile LANs and accessed by a web-application or smartphone app. 

A device like the Arctic Tracker generates its own certificate. Possibly using the DNS extension to add a *.local* (mDNS) name. By default the certificate is self-signed, but then clients using a web-browser to access devices, must (manually) add an exception to the browser's security policy. In addition, this method does not necessarily work with a smartphone app. 
 
The solution is that the device generate a CSR and send it to a REST-API on a CA-server to have it signed. This process *should* require some authentication to verify that the device requesting the certificate is legitimate. The CA certificate (used for signing) may be installed in the browser or the smartphone app so they can verify certificates from the devices. 
 
It is still a bit work-in-progress. 

## C client

A simple C client is available in `client/`.
It is intended to build and run on Linux.

Build it with:

```sh
cd client
make
```

The client uses libcurl and OpenSSL. On Debian/Ubuntu systems, install the required development packages with:

```sh
sudo apt-get install libcurl4-openssl-dev libssl-dev
```

The resulting `certclient` program reads settings from `certclient.ini`, submits a PEM encoded CSR to the authenticated `/cacert/sign` REST endpoint, and writes the returned PEM encoded certificate to the configured output file.

By default it reads `./certclient.ini` from the current working directory. For example, if you run it from `client/`, it will use the `certclient.ini` file in that directory. You can override that by passing a config file path on the command line:

```sh
./certclient /path/to/certclient.ini
```

The configuration file supports:

- `service_url`, `sign_path`, `login_path`
- `csr_file`, `cert_file`
- `userid`
- exactly one of `password`, `session_key`, or `shared_secret`
- optional `days`, authorization `role`, `ca_file`, and `insecure_tls`
