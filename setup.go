package iran_resolver

import (
	"bufio"
	"github.com/coredns/caddy"
	"github.com/coredns/caddy/caddyfile"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/pkg/errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func init() { plugin.Register("iran_resolver", setup) }

// setup is the function that gets called when the config parser see the token "iran_resolver".
func setup(c *caddy.Controller) error {
	ir, err := parseIR(c)
	if err != nil {
		return plugin.Error("iran_resolver", err)
	}

	// init files
	err = initHostFile(ir.banHostsFile, "hosts file witch contains ban domains:")
	if err != nil {
		return plugin.Error("iran_resolver", err)
	}
	err = initHostFile(ir.sanctionHostsFile, "hosts file witch contains sanction domains:")
	if err != nil {
		return plugin.Error("iran_resolver", err)
	}
	err = initHostFile(ir.resultHostsFile, "")
	if err != nil {
		return plugin.Error("iran_resolver", err)
	}

	err = updateHostsFileWithIps(ir.sanctionHostsFile, ir.sanctionDestServers)
	if err != nil {
		return plugin.Error("iran_resolver", err)
	}
	err = updateHostsFileWithIps(ir.banHostsFile, ir.banDestServers)
	if err != nil {
		return plugin.Error("iran_resolver", err)
	}
	err = mergeHostsFiles(ir.sanctionHostsFile, ir.banHostsFile, ir.resultHostsFile)
	if err != nil {
		return plugin.Error("iran_resolver", err)
	}

	// check required params
	if len(ir.banDestServers) < 1 || len(ir.sanctionDestServers) < 1 || len(ir.dns2check) < 1 {
		return plugin.Error("iran_resolver", errors.New("dns-to-check & sanction-dest-server-ips & ban-dest-server-ips are required!"))
	}

	c.OnStartup(func() error {
		return ir.OnStartup()
	})
	c.OnShutdown(ir.OnShutdown)

	// Add the Plugin to CoreDNS, so Servers can use it in their plugin chain.
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		ir.Next = next
		return ir
	})

	return nil
}

// OnStartup starts a goroutines for all clients.
func (ir *IranResolver) OnStartup() (err error) {
	return nil
}

// OnShutdown stops all configured clients.
func (ir *IranResolver) OnShutdown() error {
	return nil
}

func parseIR(c *caddy.Controller) (*IranResolver, error) {
	var (
		ir  *IranResolver
		err error
		i   int
	)
	for c.Next() {
		if i > 0 {
			return nil, plugin.ErrOnce
		}
		i++
		ir, err = parseStanza(&c.Dispenser)
		if err != nil {
			return nil, err
		}
	}

	return ir, nil
}

func parseStanza(c *caddyfile.Dispenser) (*IranResolver, error) {
	ir := New()

	for c.NextBlock() {
		err := parseValue(strings.ToLower(c.Val()), ir, c)
		if err != nil {
			return nil, err
		}
	}
	return ir, nil
}

func parseValue(v string, ir *IranResolver, c *caddyfile.Dispenser) error {
	switch v {
	case "dns-to-check":
		return parseDns2Check(ir, c)
	case "sanction-search":
		return parseSanctionSearch(ir, c)
	case "ban-search":
		return parseBanSearch(ir, c)
	case "sanction-hosts-file":
		return parseSanctionHostsFile(ir, c)
	case "ban-hosts-file":
		return parseBanHostsFile(ir, c)
	case "result-hosts-file":
		return parseResultHostsFile(ir, c)
	case "sanction-dest-server-ips":
		return parseSanctionDestServers(ir, c)
	case "ban-dest-server-ips":
		return parseBanDestServers(ir, c)
	case "sanction-buffer-size":
		return parseSanctionListBufferSize(ir, c)
	case "ban-buffer-size":
		return parseBanListBufferSize(ir, c)
	default:
		return errors.Errorf("unknown property %v", v)
	}
}

func parseDns2Check(ir *IranResolver, c *caddyfile.Dispenser) error {
	args := c.RemainingArgs()
	if len(args) == 0 {
		return c.ArgErr()
	}

	for _, arg := range args {
		ip, err := net.ResolveUDPAddr("udp", arg)
		if err != nil {
			return c.ArgErr()
		}
		ir.dns2check = append(ir.dns2check, ip)
	}
	return nil
}

func parseSanctionSearch(ir *IranResolver, c *caddyfile.Dispenser) error {
	args := c.RemainingArgs()
	if len(args) == 0 {
		return c.ArgErr()
	}

	for _, arg := range args {
		ir.sanctionSearchParams = append(ir.sanctionSearchParams, arg)
	}
	return nil
}

func parseBanSearch(ir *IranResolver, c *caddyfile.Dispenser) error {
	args := c.RemainingArgs()
	if len(args) == 0 {
		return c.ArgErr()
	}

	for _, arg := range args {
		ir.banSearchParams = append(ir.banSearchParams, arg)
	}
	return nil
}

func parseSanctionHostsFile(ir *IranResolver, c *caddyfile.Dispenser) error {
	if !c.NextArg() {
		return c.ArgErr()
	}
	v := c.Val()
	if len(v) < 2 || !filepath.IsAbs(v) {
		return errors.New("sanction-hosts-file only accepts absolut path!")
	}
	if v == ir.banHostsFile || v == ir.resultHostsFile {
		return errors.New("should not be the same as ban-hosts-file or result-hosts-file!")
	}
	ir.sanctionHostsFile = v
	return nil
}

func parseBanHostsFile(ir *IranResolver, c *caddyfile.Dispenser) error {
	if !c.NextArg() {
		return c.ArgErr()
	}
	v := c.Val()
	if len(v) < 2 || !filepath.IsAbs(v) {
		return errors.New("ban-hosts-file only accepts absolut path!")
	}
	if v == ir.sanctionHostsFile || v == ir.resultHostsFile {
		return errors.New("should not be the same as sanction-hosts-file or result-hosts-file!")
	}
	ir.banHostsFile = v
	return nil
}

func parseResultHostsFile(ir *IranResolver, c *caddyfile.Dispenser) error {
	if !c.NextArg() {
		return c.ArgErr()
	}
	v := c.Val()
	if len(v) < 2 || !filepath.IsAbs(v) {
		return errors.New("result-hosts-file only accepts absolut path!")
	}
	if v == ir.sanctionHostsFile || v == ir.banHostsFile {
		return errors.New("should not be the same as sanction-hosts-file or ban-hosts-file!")
	}
	ir.resultHostsFile = v
	return nil
}

func parseSanctionDestServers(ir *IranResolver, c *caddyfile.Dispenser) error {
	args := c.RemainingArgs()
	if len(args) == 0 {
		return c.ArgErr()
	}

	for _, arg := range args {
		ip := net.ParseIP(arg)
		if ip == nil {
			return errors.New("sanction-dest-server-ips must be a list of valid ip addresses!")
		}
		ir.sanctionDestServers = append(ir.sanctionDestServers, ip)
	}
	return nil
}

func parseBanDestServers(ir *IranResolver, c *caddyfile.Dispenser) error {
	args := c.RemainingArgs()
	if len(args) == 0 {
		return c.ArgErr()
	}

	for _, arg := range args {
		ip := net.ParseIP(arg)
		if ip == nil {
			return errors.New("ban-dest-server-ips must be a list of valid ip addresses!")
		}
		ir.banDestServers = append(ir.banDestServers, ip)
	}
	return nil
}

func parseSanctionListBufferSize(ir *IranResolver, c *caddyfile.Dispenser) error {
	var err error
	ir.sanctionListBufferSize, err = parsePositiveInt(c)
	return err
}

func parseBanListBufferSize(ir *IranResolver, c *caddyfile.Dispenser) error {
	var err error
	ir.banListBufferSize, err = parsePositiveInt(c)
	return err
}

func parsePositiveInt(c *caddyfile.Dispenser) (int, error) {
	if !c.NextArg() {
		return -1, c.ArgErr()
	}
	v := c.Val()
	num, err := strconv.Atoi(v)
	if err != nil {
		return -1, c.ArgErr()
	}
	if num < 0 {
		return -1, c.ArgErr()
	}
	return num, nil
}

func initHostFile(path string, welcomeSentence string) error {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		title := []byte("\n\n# " + welcomeSentence + " \n")
		err = os.WriteFile(path, title, 0644)
		if err != nil {
			return errors.New("couldn't create hosts file")
		}
	}
	return nil
}

func updateHostsFileWithIps(path string, ips []net.IP) error {
	hostsList, err := getHostsFromFile(path)
	if err != nil {
		return err
	}

	hostsList = removeDuplicates(hostsList)

	err = removeNonCommentLines(path)
	if err != nil {
		return err
	}

	newContent := ""

	for _, s := range hostsList {
		for _, ip := range ips {
			newLine := ip.String() + "    " + s
			newContent += newLine + "\n"
		}
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}

	_, err = f.WriteString(newContent)
	if err != nil {
		return err
	}

	err = f.Close()
	if err != nil {
		return err
	}

	return nil
}

func getHostsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var firstElements []string

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue // Ignore lines starting with #
		}

		fields := strings.Fields(line)
		if len(fields) > 0 {
			firstElements = append(firstElements, fields[1])
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return firstElements, nil
}
