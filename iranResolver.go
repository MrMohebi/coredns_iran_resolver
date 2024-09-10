package iran_resolver

import (
	"context"
	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
	"io"
	"net"
	"os"
	"strings"
	"sync"
)

type resolver struct {
	url string
	ip  net.IP
}

// IranResolver is a coredns plugin to generate hosts file for banned and sanctioned urls.
type IranResolver struct {
	dns2check            []net.Addr
	sanctionSearchParams []string
	banSearchParams      []string
	sanctionHostsFile    string
	banHostsFile         string
	resultHostsFile      string

	banMu        sync.Mutex
	sanctionMu   sync.Mutex
	sanctionList []resolver
	banList      []resolver

	banListBufferSize      int
	sanctionListBufferSize int

	sanctionDestServers []net.IP
	banDestServers      []net.IP

	Next plugin.Handler
}

func New() *IranResolver {
	return &IranResolver{
		banListBufferSize:      10,
		sanctionListBufferSize: 10,
		sanctionHostsFile:      "/etc/hosts-sanction",
		banHostsFile:           "/etc/hosts-ban",
		resultHostsFile:        "/etc/hosts-iran-resolver",
	}
}

// Name implements the Handler interface.
func (ir *IranResolver) Name() string { return "iran_resolver" }

// ServeDNS implements the plugin.Handler interface. This method gets called when iran_resolver is used
// in a Server.
func (ir *IranResolver) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {

	req := r.Copy()
	go askFromDnsServers(ir, req)

	// Call next plugin (if any).
	return plugin.NextOrFailure(ir.Name(), ir.Next, ctx, w, r)
}

func askFromDnsServers(ir *IranResolver, req *dns.Msg) {
	for _, server := range ir.dns2check {
		resp, err := dns.Exchange(req, server.String())
		if err != nil {
			println(err)
		}

		if r, err := checkBan(ir, resp); r {
			if err != nil {
				println(err)
			}
			break
		}

		if r, err := checkSanction(ir, resp); r {
			if err != nil {
				println(err)
			}
			break
		}
	}

}
func checkSanction(ir *IranResolver, resp *dns.Msg) (bool, error) {
	var err error
	result := false
	for _, p := range ir.sanctionSearchParams {
		if strings.Contains(resp.String(), p) {
			result = true
			break
		}
	}
	if result {
		url := strings.TrimSuffix(resp.Question[0].Name, ".")
		if !isInList(ir.sanctionList, url) {
			err = addSanctionToList(ir, url)
		}

		return result, err
	}

	return result, nil
}

func checkBan(ir *IranResolver, resp *dns.Msg) (bool, error) {
	var err error
	result := false
	for _, p := range ir.banSearchParams {
		if strings.Contains(resp.String(), p) {
			result = true
			break
		}
	}
	if result {
		url := strings.TrimSuffix(resp.Question[0].Name, ".")
		if !isInList(ir.banList, url) {
			err = addBanToList(ir, url)
		}

		return result, err
	}

	return result, nil
}

func addBanToList(ir *IranResolver, url string) error {
	ir.banMu.Lock()
	defer ir.banMu.Unlock()

	for _, ip := range ir.banDestServers {
		ir.banList = append(
			ir.banList,
			resolver{
				url: url,
				ip:  ip,
			})
	}
	if len(ir.banList) > ir.banListBufferSize {
		f, err := os.OpenFile(ir.banHostsFile, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		for _, h := range ir.banList {
			if _, err = f.WriteString("\n" + h.ip.String() + "    " + h.url); err != nil {
				return err
			}
		}
		err = f.Close()
		if err != nil {
			return err
		}

		ir.banList = nil

		err = mergeHostsFiles(ir.sanctionHostsFile, ir.banHostsFile, ir.resultHostsFile)
		if err != nil {
			return err
		}
	}

	return nil
}

func addSanctionToList(ir *IranResolver, url string) error {
	ir.sanctionMu.Lock()
	defer ir.sanctionMu.Unlock()

	for _, ip := range ir.sanctionDestServers {
		ir.sanctionList = append(
			ir.sanctionList,
			resolver{
				url: url,
				ip:  ip,
			})
	}

	if len(ir.sanctionList) > ir.sanctionListBufferSize {
		f, err := os.OpenFile(ir.sanctionHostsFile, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		for _, h := range ir.sanctionList {
			if _, err = f.WriteString("\n" + h.ip.String() + "    " + h.url); err != nil {
				return err
			}
		}
		err = f.Close()
		if err != nil {
			return err
		}
		ir.sanctionList = nil

		err = mergeHostsFiles(ir.sanctionHostsFile, ir.banHostsFile, ir.resultHostsFile)
		if err != nil {
			return err
		}
	}

	return nil
}

func isInList(list []resolver, url string) bool {
	result := false
	for _, i := range list {
		if i.url == url {
			result = true
			break
		}
	}
	return result
}

func mergeHostsFiles(f1Path string, f2Path string, dest string) error {
	f1, err := os.Open(f1Path)
	if err != nil {
		return err
	}
	defer f1.Close()

	f2, err := os.Open(f2Path)
	if err != nil {
		return err
	}
	defer f2.Close()

	out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, f1)
	if err != nil {
		return err
	}

	_, err = io.Copy(out, f2)
	if err != nil {
		return err
	}
	return nil
}
