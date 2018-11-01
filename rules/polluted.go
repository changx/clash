package rules

import (
	"container/list"
	"crypto/tls"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"strings"
	"sync"
	"time"
)
import C "github.com/Dreamacro/clash/constant"

/*
	lru cache for pollution result, copy from tls pkg :P
 */
type pollutionCache struct {
	sync.Mutex
	m        map[string]*list.Element
	q        *list.List
	capacity int
}

type pollutionCacheEntry struct {
	hostname string
	state    int
}

const HostnamePolluted = 1
const HostnameClean = 2

func (pc *pollutionCache) Get(hostname string) (int, bool) {
	pc.Lock()
	defer pc.Unlock()

	if el, ok := pc.m[hostname]; ok {
		pc.q.MoveToFront(el)
		return el.Value.(*pollutionCacheEntry).state, true
	}
	return 0, false
}

func (pc *pollutionCache) Put(hostname string, state int) {
	pc.Lock()
	defer pc.Unlock()

	if r, ok := pc.m[hostname]; ok {
		pc.q.MoveToFront(r)
		return
	}

	if pc.q.Len() < pc.capacity {
		entry := &pollutionCacheEntry{
			hostname: hostname,
			state:    state,
		}
		pc.m[hostname] = pc.q.PushFront(entry)
		return
	}

	el := pc.q.Back()
	entry := el.Value.(*pollutionCacheEntry)
	delete(pc.m, entry.hostname)
	entry.hostname = hostname
	entry.state = state
	pc.q.MoveToFront(el)
	pc.m[hostname] = el
}

type Polluted struct {
	safeDNS        string
	honeypotDNS    string
	localDNS       string
	adapter        string
	cache          *pollutionCache
	unsafeResolver *dns.Client
	safeResolver   *dns.Client
}

func (pr *Polluted) RuleType() C.RuleType {
	return C.POLLUTED
}

func (pr *Polluted) IsMatch(metadata *C.Metadata) bool {
	pollution := pr.match(metadata.Host, 0)
	if pollution {
		log.Infof("%s polluted", metadata.Host)
	} else {
		log.Infof("%s clean", metadata.Host)
	}
	return pollution
}

func (pr *Polluted) match(hostname string, retry int) bool {
	if retry > 3 {
		// too many tries, force proxy
		return true
	}

	if state, ok := pr.cache.Get(hostname); ok {
		return state == HostnamePolluted
	} else {
		q := new(dns.Msg)
		fqdn := dns.Fqdn(hostname)

		q.SetQuestion(fqdn, dns.TypeA)

		if answer, _, err := pr.unsafeResolver.Exchange(q, pr.honeypotDNS); err != nil {
			return pr.match(hostname, retry+1)
		} else if answer.Answer != nil {
			// GFW 如果抢答，判定为污染
			pr.cache.Put(hostname, HostnamePolluted)
			return true
		} else {
			// GFW 未抢答
			// 用本地 DNS 检查 hostname 解析结果中的 CNAME 记录, 需要递归判定是否 CNAME 被污染
			// 如果结果中的 CNAME 记录被污染，返回的结果仍然是不可用的
			if answer, _, err := pr.unsafeResolver.Exchange(q, pr.localDNS); err != nil {
				return pr.match(hostname, retry+1)
			} else if answer != nil {
				for _, rr := range answer.Answer {
					if rr.Header().Rrtype == dns.TypeCNAME {
						cname := rr.(*dns.CNAME)
						if pr.match(cname.Target, 0) {
							pr.cache.Put(cname.Target, HostnamePolluted)
							pr.cache.Put(hostname, HostnamePolluted)
							return true
						} else {
							pr.cache.Put(cname.Target, HostnameClean)
						}
					}
				}
			} else {
				// no error, no answer ，拒绝解析也是 GFW 一种污染手段，也有可能是偶然的网络错误，强制走代理
				pr.cache.Put(hostname, HostnamePolluted)
				return true
			}

			// 不是 CNAME，或者 CNAME 检查通过
			pr.cache.Put(hostname, HostnameClean)
		}
	}
	return false
}

func (pr *Polluted) Adapter() string {
	return pr.adapter
}

func (pr *Polluted) Payload() string {
	return pr.safeDNS
}

func NewPOLLUTED(dnsHosts string, adapter string) *Polluted {

	dnsList := strings.Split(dnsHosts, ";")

	tlsResolver := new(dns.Client)
	tlsResolver.Net = "tcp4-tls"
	tlsResolver.TLSConfig = &tls.Config{
		InsecureSkipVerify: false,
		ClientSessionCache: tls.NewLRUClientSessionCache(64),
		MinVersion:         tls.VersionTLS11,
		MaxVersion:         tls.VersionTLS12,
	}

	tlsResolver.DialTimeout = 5 * time.Second

	polluted := Polluted{
		adapter:        adapter,
		unsafeResolver: new(dns.Client),
		safeResolver:   tlsResolver,
		cache: &pollutionCache{
			m:        make(map[string]*list.Element),
			q:        list.New(),
			capacity: 1024,
		},
	}

	if len(dnsList) < 2 {
		tlsResolver.TLSConfig.ServerName = "9.9.9.9:853"
		polluted.safeDNS = "9.9.9.9:853"
	} else {
		tlsResolver.TLSConfig.ServerName = dnsList[2]
		polluted.safeDNS = dnsList[2]
	}

	if len(dnsList) < 2 {
		polluted.localDNS = "119.29.29.29:53"
	} else {
		polluted.localDNS = dnsList[1]
	}

	if len(dnsList) < 1 {
		polluted.honeypotDNS = "198.11.138.248:53"
	} else {
		polluted.honeypotDNS = dnsList[0]
	}

	return &polluted
}
