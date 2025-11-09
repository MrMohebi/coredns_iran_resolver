# iran_resolver

**iran_resolver** is a custom CoreDNS plugin designed to dynamically detect and manage banned and sanctioned domains in Iran. It can automatically generate host files for these domains and redirect requests to your specified IPs, making it useful for services like [Shecan](https://shecan.ir/).

This plugin helps you identify domains restricted due to local censorship or international sanctions and handle them seamlessly within your DNS infrastructure.


## How It Works

1. **Domain Lookup:**
   When a client queries a domain, iran_resolver first forwards the request to Google DNS (or another configured upstream).

2. **Ban Detection:**

   * If the upstream DNS returns `10.10.34.35` (PayvandHa’s special response), the domain is considered **banned in Iran**.
   * The domain is added to an in-memory **ban buffer**.

3. **Sanction Detection:**

   * The plugin then queries additional Iranian DNS providers.
   * If their response matches a configured pattern (like `develop.403` or `electro`), the domain is marked as **under sanction in Iran**.
   * The domain is added to an in-memory **sanction buffer**.

4. **Buffered Writing to Hosts Files:**

   * For performance reasons, domains are **not written to disk immediately**.
   * They are stored in buffers (`ban-buffer-size` and `sanction-buffer-size`).
   * Once a buffer fills, all domains in it are written to the corresponding host file.
   * This batching reduces disk I/O but may cause a slight delay before newly detected domains appear in the host files.

5. **Caching & Response:**

   * On subsequent queries for the same domain, iran_resolver responds with IPs from your configured upstream servers instead of the original IP.
   * This ensures banned and sanctioned domains are consistently redirected.

6. **Host File Generation:**

   * Generates separate host files for **banned** and **sanctioned** domains.
   * A combined host file can also be generated for DNS resolution purposes.


## Configuration

Example configuration:

```text
iran_resolver {
    dns-to-check 78.157.42.101:53 10.202.10.202:53  # Required: upstream DNS servers to check

    sanction-search develop.403 electro               # Patterns to identify sanctioned domains
    ban-search 10.10.34.35                            # Pattern to identify banned domains

    sanction-hosts-file /etc/hosts_dir/hosts-sanction # Path to store sanctioned hosts
    ban-hosts-file /etc/hosts_dir/hosts-ban           # Path to store banned hosts

    result-hosts-file /etc/hosts_dir/hosts-ir         # Path to combined host file

    sanction-dest-server-ips 10.10.10.10 20.20.20.20 # IPs to use for sanctioned domains
    ban-dest-server-ips 40.40.40.40 30.30.30.30      # IPs to use for banned domains

    sanction-buffer-size 10                             # Number of new sanctioned domains to buffer before writing to disk
    ban-buffer-size 10                                  # Number of new banned domains to buffer before writing to disk
}
```


## Key Features

* **Automatic Detection:** Dynamically identifies domains banned or sanctioned in Iran.
* **Custom Redirects:** Redirects clients to specified IPs for restricted domains.
* **Buffered Writing:** Reduces disk I/O by batching domain writes to host files.
* **Host File Generation:** Produces separate and combined host files for banned and sanctioned domains.
* **Flexible Configuration:** Supports multiple upstream DNS servers, detection patterns, and custom IPs for restricted domains.


## Notes

* The plugin works best with reliable upstream DNS servers.
* Buffered writing means there may be a small delay before newly detected domains appear in the host files.
* Properly configuring the buffer sizes (`sanction-buffer-size` and `ban-buffer-size`) balances performance and responsiveness.
