#include <sys/kernel.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/systm.h>
#include <sys/types.h>

#include <net/if.h>
#include <net/pfil.h>
#include <net/vnet.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip_var.h>

static pfil_hook_t icmp_block_hook;
static u_long icmp_dropped_count = 0;

static pfil_return_t icmp_block_check(struct mbuf **m0, struct ifnet *ifp,
                                      int flags, void *ruleset,
                                      struct inpcb *inp) {
  struct mbuf *m = *m0;
  struct ip *ip;
  struct icmp *icp;
  int ip_hlen;

  if (m->m_len < (int)sizeof(struct ip)) {
    m = m_pullup(m, sizeof(struct ip));
    if (m == NULL) {
      *m0 = NULL;
      return (PFIL_DROPPED);
    }
    *m0 = m;
  }

  ip = mtod(m, struct ip *);
  if (ip->ip_p != IPPROTO_ICMP)
    return (PFIL_PASS);

  ip_hlen = ip->ip_hl << 2;
  if (m->m_len < ip_hlen + (int)sizeof(struct icmp)) {
    m = m_pullup(m, ip_hlen + sizeof(struct icmp));
    if (m == NULL) {
      *m0 = NULL;
      return (PFIL_DROPPED);
    }
    *m0 = m;
    ip = mtod(m, struct ip *);
  }

  icp = (struct icmp *)((caddr_t)ip + ip_hlen);
  if (icp->icmp_type != ICMP_ECHO)
    return (PFIL_PASS);

  icmp_dropped_count++;
  printf("block_icmp: dropped ICMP Echo Request #%lu, size %u bytes\n",
         icmp_dropped_count, ntohs(ip->ip_len));

  return (PFIL_DROPPED);
}

static int load(void) {
  struct pfil_hook_args pha;
  struct pfil_link_args pla;
  int error;

  icmp_dropped_count = 0;

  bzero(&pha, sizeof(pha));
  pha.pa_version = PFIL_VERSION;
  pha.pa_flags = PFIL_IN;
  pha.pa_type = PFIL_TYPE_IP4;
  pha.pa_mbuf_chk = icmp_block_check;
  pha.pa_ruleset = NULL;
  pha.pa_modname = "block_icmp";
  pha.pa_rulname = "icmp_echo_block";

  icmp_block_hook = pfil_add_hook(&pha);
  if (icmp_block_hook == NULL) {
    printf("block_icmp: pfil_add_hook failed\n");
    return (ENODEV);
  }

  bzero(&pla, sizeof(pla));
  pla.pa_version = PFIL_VERSION;
  pla.pa_flags = PFIL_IN | PFIL_HEADPTR | PFIL_HOOKPTR;
  pla.pa_head = V_inet_pfil_head;
  pla.pa_hook = icmp_block_hook;

  error = pfil_link(&pla);
  if (error != 0) {
    printf("block_icmp: pfil_link failed, error %d\n", error);
    pfil_remove_hook(icmp_block_hook);
    icmp_block_hook = NULL;
    return (error);
  }

  printf("block_icmp: loaded - blocking inbound ICMP Echo Request packets\n");
  return (0);
}

static int unload(void) {
  if (icmp_block_hook != NULL) {
    pfil_remove_hook(icmp_block_hook);
    icmp_block_hook = NULL;
  }
  printf(
      "block_icmp: unloaded - dropped %lu ICMP Echo Request packet(s) total\n",
      icmp_dropped_count);
  return (0);
}

static int event_handler(module_t mod, int event, void *arg) {
  switch (event) {
  case MOD_LOAD:
    return load();
  case MOD_UNLOAD:
    return unload();
  default:
    return EOPNOTSUPP;
  }
}

static moduledata_t icmp_block_mod = {"block_icmp", event_handler, NULL};

DECLARE_MODULE(block_icmp, icmp_block_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
