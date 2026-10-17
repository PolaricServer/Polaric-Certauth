## Minimal CA REST service. 

For IoT devices like the *Arctic Tracker* or *Polaric Server* instances to be run on (possibly mobile) LANs and accessed by web-applications or smartphone apps. 

A device like the Arctic Tracker generates its own certificate. It may also be using the DNS extension to add a *.local* (mDNS) name. By default the certificate is self-signed, but then clients using a web-browser to access devices, must (manually) add an exception to the browser's security policy each time there is a new certificate. In addition, this method does not necessarily work with a smartphone app. 
 
The solution is that the device generates a CSR and sends it to a REST-API on a CA-server to have it signed. We use a REST API which *should* require some authentication to verify that the device requesting the certificate is legitimate. The CA-certificate (used for signing) may be installed in browsers or smartphone apps so they can verify certificates from the devices. 

## Server and CLI for signing

A server is implemented in Java, using the polaric-core framework. A simple command-line interface allows (1) creating a CA certificate, (2) show the PEM representation of the CA-certificate, (3) show the details of the CA-certificate, (4) issue a certificate (sign) based on a CSR. 

The REST API offer two endpoints
* `GET /cacert` - return a PEM representation of the CA-certificate
* `PUT /cacert/sign` - take a CSR as input (PEM-format) and return a signed certificate (PEM-format)

The PUT operation requires a device HMAC-authentication using a shared secret. It currently doesn't support user-logins. 


## C client

A simple C client is available in `client/`.
It is intended to build and run on Linux. The polaric-webapp2 (from v.4.3) can use this if it is installed and correctly configured. 

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

- `service_url`, `sign_path`
- `csr_file`, `cert_file`
- `userid`
- `shared_secret`
- optional `days` 

## Debian packaging

This repository includes Debian packaging metadata for two binary packages:

- `polaric-certauth-server`
- `polaric-certauth-client`

Build them from the repository root with:

```sh
dpkg-buildpackage -us -uc -b
```

The server package installs the Java application and helper shell together
with `/etc/polaric-certauth/server.ini`. It installs two wrapper commands: `polaric-certauth-ca-shell` (command shell). `polaric-certauth-server` which is called by the system to start the server. 

The client package installs a wrapper command named
`polaric-certauth-client` together with `/etc/polaric-certauth/client.ini`.
